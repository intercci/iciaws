//! PASETO v3 / v4 public-mode verification.
//!
//! A [`Verifier`] is built once — from AWS KMS or from the local environment —
//! and then answers [`Verifier::verify_token`] for the lifetime of the
//! instance. **No AWS call happens inside `verify_token`**: the public key is
//! fetched and parsed in the constructor, so the hot path (every inbound
//! request) performs no network I/O and no credential lookup.
//!
//! The entry points are `async` purely so that adding a key-refresh path later
//! (re-reading a rotated key, say) would not be a breaking signature change.
//! Nothing on this path does I/O today.
//!
//! # Which verify entry point is used, and why
//!
//! The claims-aware `pasetors::public::{sign, verify}` pair is v4-only and its
//! footer parameter is `Option<&Footer>` — a parsed JSON footer, not raw bytes.
//! The raw-footer API this crate needs (`Option<&[u8]>`) is only on the
//! version-specific token types, so both versions go through
//! `version{3,4}::PublicToken::verify`, which is where all of the signature
//! maths and the PAE construction live. Hand-rolling any of that would be a
//! second implementation of the specification, and a bug in it fails open.
//!
//! The low-level verify functions deliberately do **not** touch the claims, so
//! the `ValidAt` rules (`iat`, `nbf`, `exp`) are applied explicitly by
//! [`validated_claims`] using `ClaimsValidationRules::default()` — the same
//! defaults `pasetors::public::verify` would have used. That is also why the
//! returned [`Claims`] is owned: `Claims::from_string` parses out of
//! `TrustedToken::payload()`, so no lifetime is tied to the `TrustedToken`.
//!
//! # Version pinning
//!
//! The version comes from configuration, never from the token. A token whose
//! header does not match the pinned version is rejected before any key material
//! is touched, so a caller cannot choose which key verifies their own token.
//! The header only ever selects the *parser*; the key always comes from
//! configuration.

use crate::errors::RouterError;
use crate::kms::{self, KeySource, KmsError, PasetoVersion, V3_PUBLIC_KEY_LEN, V4_PUBLIC_KEY_LEN};
use lambda_http::tracing;
use pasetors::Public;
use pasetors::claims::{Claims, ClaimsValidationRules};
use pasetors::keys::AsymmetricPublicKey;
use pasetors::token::UntrustedToken;
use pasetors::version3::V3;
use pasetors::version4::V4;
use std::env;

/// Error message used when the local public key is absent or blank.
const PUB_KEY_MISSING: &str =
    "no PASETO public key configured (set PASETO_PUB_KEY for the `env` key source)";

/// Auth scheme prefix accepted by [`Verifier::verify_token`], matching the
/// legacy `Keys::verify_token` behaviour.
const BEARER: &str = "Bearer ";

/// The public key for whichever PASETO version the deployment pins.
#[derive(Debug)]
enum PublicMaterial {
    /// PASETO v3 — 49-byte compressed P-384 point.
    V3(AsymmetricPublicKey<V3>),
    /// PASETO v4 — 32-byte raw Ed25519 key.
    V4(AsymmetricPublicKey<V4>),
}

/// A verification-only PASETO handle, pinned to one key and one version.
///
/// Build it with [`Verifier::new`] or [`Verifier::with_source`].
#[derive(Debug)]
pub struct Verifier {
    /// Where the key was loaded from. Kept for inspection; never used to pick a
    /// key at verification time.
    source: KeySource,
    /// The pinned PASETO version, derived from key material.
    version: PasetoVersion,
    /// The resolved KMS key reference. Empty for the `env` source, which has no
    /// AWS key to name.
    kms_key_id: String,
    /// The parsed public key. Verification never needs the secret half — which
    /// is exactly why a KMS-backed verifier is safe: we hold the public key, so
    /// local verification stays possible even when signing happens in AWS.
    public: PublicMaterial,
}

impl Verifier {
    /// Build a verifier from the environment.
    ///
    /// # Environment variables
    ///
    /// * `PASETO_KEY_SOURCE` — `kms`, `env` or `auto` (default). `auto` resolves
    ///   to `kms` on Lambda and `env` off it.
    /// * `KMS_KEY_ID` — the KMS key, required by the `kms` source.
    /// * `PASETO_PUB_KEY` — base64url raw public key, required by the `env`
    ///   source. 32 bytes selects v4, 49 bytes selects v3.
    ///
    /// `.env` is loaded first when `LAMBDA_TASK_ROOT` is absent, so a local run
    /// behaves like the deployed one.
    ///
    /// # Errors
    ///
    /// * [`RouterError::KeyPairError`] — unusable configuration, or a
    ///   `GetPublicKey` / transport failure.
    pub async fn new(key_id: Option<String>) -> Result<Self, RouterError> {
        kms::load_dotenv_if_local();
        let source = KeySource::resolve(None)?;
        Self::build(source, key_id).await
    }

    /// Build a verifier from an explicit key source and optional key id.
    ///
    /// `source` is the raw `PASETO_KEY_SOURCE` string (`kms` / `env` / `auto` /
    /// `None`) rather than a [`KeySource`]: `KeySource` is crate-private, and
    /// naming it in a public signature would leak a non-public type through this
    /// crate's public API. [`Verifier::new`] is the `None` shorthand.
    ///
    /// # Errors
    ///
    /// See [`Verifier::new`].
    pub async fn with_source(
        key_id: Option<String>,
        source: Option<&str>,
    ) -> Result<Self, RouterError> {
        kms::load_dotenv_if_local();
        let source = KeySource::resolve(source)?;
        Self::build(source, key_id).await
    }

    async fn build(source: KeySource, key_id: Option<String>) -> Result<Self, RouterError> {
        match source {
            KeySource::Env => Self::from_env_keys(),
            KeySource::Kms => Self::from_kms(key_id).await,
        }
    }

    /// Build from `PASETO_PUB_KEY`. Purely local: no AWS client is constructed.
    fn from_env_keys() -> Result<Self, RouterError> {
        let configured = env::var(kms::PUB_KEY_ENV)
            .map_err(|_| RouterError::KeyPairError(PUB_KEY_MISSING.to_string()))?;
        let trimmed = configured.trim();
        if trimmed.is_empty() {
            return Err(RouterError::KeyPairError(PUB_KEY_MISSING.to_string()));
        }

        let bytes = kms::b64url_decode(trimmed)?;
        // The key length is what selects the version: there is no KeySpec to ask
        // in the `env` source, and inspecting key material (never the token) is
        // the only honest signal available.
        let version = PasetoVersion::from_key_len(bytes.len()).ok_or_else(|| {
            RouterError::KeyPairError(format!(
                "PASETO_PUB_KEY must be {V3_PUBLIC_KEY_LEN} raw bytes (v3) or \
                 {V4_PUBLIC_KEY_LEN} raw bytes (v4), got {}",
                bytes.len()
            ))
        })?;

        // The inherent `from`, not a `TryFrom`: pasetors provides no
        // `TryFrom<&[u8]>` impl for its key types.
        let public = match version {
            PasetoVersion::V3 => {
                PublicMaterial::V3(AsymmetricPublicKey::<V3>::from(&bytes).map_err(|e| {
                    RouterError::KeyPairError(format!("invalid v3 public key: {e}"))
                })?)
            }
            PasetoVersion::V4 => {
                PublicMaterial::V4(AsymmetricPublicKey::<V4>::from(&bytes).map_err(|e| {
                    RouterError::KeyPairError(format!("invalid v4 public key: {e}"))
                })?)
            }
        };

        tracing::info!(
            version = ?version,
            key_source = describe(KeySource::Env),
            "PASETO verifier configured from PASETO_PUB_KEY"
        );
        Ok(Self {
            source: KeySource::Env,
            version,
            kms_key_id: String::new(),
            public,
        })
    }

    /// Fetch the public key from KMS and pin the version to its `KeySpec`.
    async fn from_kms(key_id: Option<String>) -> Result<Self, RouterError> {
        let key_id = kms::resolve_key_id(key_id)?;
        let client = kms::kms_client().await;
        let output = client
            .get_public_key()
            .key_id(&key_id)
            .send()
            .await
            .map_err(|e| KmsError::GetPublicKey(Box::new(e)))?;

        // KeySpec, not key length, is authoritative here: AWS already told us
        // what kind of key this is, and `PasetoVersion::from_key_spec` maps an
        // unrecognised spec onto `UnsupportedKeySpec` rather than a compile error.
        // Never `unwrap` an SDK `Option` accessor — an absent KeySpec is a
        // malformed response, not a programming error.
        let spec = output.key_spec().ok_or_else(|| {
            RouterError::KeyPairError("KMS GetPublicKey returned no KeySpec".to_string())
        })?;
        let version = PasetoVersion::from_key_spec(spec)?;

        // `.as_ref()` rather than deref coercion: `Blob` has no `Deref`.
        let spki = output.public_key().ok_or(KmsError::MissingPublicKey)?;
        let public = match version {
            PasetoVersion::V3 => PublicMaterial::V3(kms::p384_public_key_from_spki(spki.as_ref())?),
            PasetoVersion::V4 => {
                PublicMaterial::V4(kms::ed25519_public_key_from_spki(spki.as_ref())?)
            }
        };

        tracing::info!(
            version = ?version,
            key_source = describe(KeySource::Kms),
            "PASETO verifier configured from KMS"
        );
        Ok(Self {
            source: KeySource::Kms,
            version,
            kms_key_id: key_id,
            public,
        })
    }

    /// Verify a token and return its validated claims.
    ///
    /// Equivalent to `verify_token_with_footer(token, None)`. A `Bearer ` prefix
    /// is stripped if present, matching the legacy `Keys::verify_token`.
    ///
    /// # Errors
    ///
    /// Every failure — wrong version, malformed token, bad signature, expired or
    /// otherwise invalid claims — is reported as
    /// [`RouterError::Unauthenticated`], because all of them mean "this token is
    /// not acceptable". Token bytes are never included in the message.
    pub async fn verify_token(&self, token: &str) -> Result<Claims, RouterError> {
        self.verify_token_with_footer(token, None).await
    }

    /// Verify a token against an expected footer.
    ///
    /// With `footer: None` the token's footer is validated but not compared to a
    /// known value (pasetors' own semantics). With `Some(..)` the footer is
    /// validated **and** compared, so a token issued under a different footer —
    /// a different key id, say — is rejected.
    ///
    /// # Errors
    ///
    /// See [`Verifier::verify_token`].
    pub async fn verify_token_with_footer(
        &self,
        token: &str,
        footer: Option<&[u8]>,
    ) -> Result<Claims, RouterError> {
        let raw = token.strip_prefix(BEARER).unwrap_or(token);

        // The version is configuration, never the token. Refusing a mismatched
        // header here means a v3 key is never even offered a v4 token. The two
        // rejections are reported separately so a misconfigured deployment (wrong
        // pinned version) is distinguishable from a malformed request.
        match PasetoVersion::from_token(raw) {
            None => {
                return Err(RouterError::Unauthenticated(
                    "unrecognized PASETO header".to_string(),
                ));
            }
            Some(found) if found != self.version => {
                return Err(RouterError::Unauthenticated(format!(
                    "token version {found:?} does not match configured version {:?}",
                    self.version
                )));
            }
            Some(_) => {}
        }

        match &self.public {
            PublicMaterial::V3(key) => {
                let untrusted =
                    UntrustedToken::<Public, V3>::try_from(raw).map_err(unauthenticated)?;
                let trusted =
                    pasetors::version3::PublicToken::verify(key, &untrusted, footer, None)
                        .map_err(unauthenticated)?;
                validated_claims(trusted.payload())
            }
            PublicMaterial::V4(key) => {
                let untrusted =
                    UntrustedToken::<Public, V4>::try_from(raw).map_err(unauthenticated)?;
                let trusted =
                    pasetors::version4::PublicToken::verify(key, &untrusted, footer, None)
                        .map_err(unauthenticated)?;
                validated_claims(trusted.payload())
            }
        }
    }

    /// The pinned PASETO version, so a deployment can assert at start-up which
    /// version it accepts.
    pub fn version(&self) -> PasetoVersion {
        self.version
    }

    /// `true` when this verifier's key came from KMS.
    pub fn is_kms(&self) -> bool {
        matches!(self.source, KeySource::Kms)
    }

    /// The resolved KMS key reference. Empty for the `env` source, which has no
    /// AWS key to name.
    pub fn kms_key_id(&self) -> &str {
        &self.kms_key_id
    }
}

/// Map a verification failure onto `Unauthenticated`.
///
/// Written as a function rather than a `map_err` closure at each call site so
/// the mapping — and the promise that token bytes stay out of the message — has
/// exactly one place to be wrong.
fn unauthenticated(err: pasetors::errors::Error) -> RouterError {
    RouterError::Unauthenticated(format!("token rejected: {err}"))
}

/// Parse the payload and apply the `ValidAt` rules.
///
/// The low-level `verify` functions authenticate the signature but leave the
/// claims alone, so `iat` / `nbf` / `exp` are enforced here with
/// `ClaimsValidationRules::default()` — the same defaults the claims-aware
/// `pasetors::public::verify` applies. Owning the [`Claims`] is what lets this
/// return them without borrowing the `TrustedToken`.
fn validated_claims(payload: &str) -> Result<Claims, RouterError> {
    let claims = Claims::from_string(payload).map_err(unauthenticated)?;
    ClaimsValidationRules::default()
        .validate_claims(&claims)
        .map_err(unauthenticated)?;
    Ok(claims)
}

/// A short, non-sensitive name for the key source, for logs.
const fn describe(source: KeySource) -> &'static str {
    match source {
        KeySource::Kms => "kms",
        KeySource::Env => "env",
    }
}

/// Shared test scaffolding for the `env` key source.
///
/// `pub(crate)` because the environment is process-global: `signer`'s tests and
/// this module's tests mutate the same variables and run on the same thread pool,
/// so they must share one lock. A per-module lock would serialise each module's
/// tests against itself and nothing against the other.
#[cfg(test)]
pub(crate) mod test {
    // Holding the env lock across `.await` is the point: the constructors read
    // process-global variables, so releasing the lock between the `set` and the
    // `new` would let a concurrent test change them underneath. Nothing in this
    // module blocks on real I/O, so the guard is held for microseconds.
    #![allow(clippy::await_holding_lock)]

    use super::*;
    use pasetors::keys::{AsymmetricKeyPair, AsymmetricSecretKey, Generate};
    use pasetors::version3::PublicToken as V3PublicToken;
    use pasetors::version4::PublicToken as V4PublicToken;
    use std::ffi::OsString;
    use std::sync::{Mutex, MutexGuard, OnceLock};
    use std::time::Duration;

    /// Serialises the tests that mutate the process environment, which is global
    /// state shared by every test thread in this binary.
    pub(crate) fn env_lock() -> MutexGuard<'static, ()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// RAII snapshot of the key-related environment variables, restored on drop
    /// so a failing assertion cannot leak mutated state into other tests.
    pub(crate) struct KeyEnvGuard {
        saved: Vec<(&'static str, Option<OsString>)>,
    }

    impl KeyEnvGuard {
        /// Capture the current values, then pin `LAMBDA_TASK_ROOT` so
        /// `load_dotenv_if_local()` skips `dotenv()`. Without it a developer's
        /// `.env` could inject `PASETO_PUB_KEY` / `PASETO_PRV_KEY` underneath a
        /// test that means to assert those variables are *absent*, and `dotenv`
        /// would happily fill them back in.
        ///
        /// Pinning it also flips `KeySource::env_default()` to `Kms`, so tests
        /// that want the `env` source pass `"env"` explicitly to `with_source`
        /// rather than relying on the default. `KeySource::resolve(None)` does not
        /// consult `PASETO_KEY_SOURCE` at all — only an explicit argument — so the
        /// `LAMBDA_TASK_ROOT` probe is the sole switch `new(None)` answers to.
        pub(crate) fn capture() -> Self {
            let names = [
                kms::KMS_KEY_ID_ENV,
                kms::KEY_SOURCE_ENV,
                kms::PUB_KEY_ENV,
                kms::PRV_KEY_ENV,
                "LAMBDA_TASK_ROOT",
            ];
            let saved = names
                .iter()
                .map(|n| (*n, env::var_os(n)))
                .collect::<Vec<(&'static str, Option<OsString>)>>();
            // SAFETY: the caller holds `env_lock()`.
            unsafe { env::set_var("LAMBDA_TASK_ROOT", "test") };
            Self { saved }
        }

        /// Set or clear an environment variable for the duration of the test.
        pub(crate) fn set(name: &str, value: Option<&str>) {
            // SAFETY: see `capture()`; `env_lock()` is held by the caller.
            unsafe {
                match value {
                    Some(v) => env::set_var(name, v),
                    None => env::remove_var(name),
                };
            }
        }
    }

    impl Drop for KeyEnvGuard {
        fn drop(&mut self) {
            for (name, value) in self.saved.drain(..) {
                // SAFETY: `env_lock()` is held for the guard's whole lifetime, so
                // no other test thread is touching the environment.
                unsafe {
                    match value {
                        Some(v) => env::set_var(name, v),
                        None => env::remove_var(name),
                    };
                }
            }
        }
    }

    /// A freshly generated v4 keypair plus a verifier built from its public half.
    async fn verifier_for_v4() -> (AsymmetricKeyPair<V4>, Verifier) {
        let pair = AsymmetricKeyPair::<V4>::generate().expect("v4 keygen");
        KeyEnvGuard::set(
            kms::PUB_KEY_ENV,
            Some(&kms::b64url_encode(pair.public.as_bytes())),
        );
        KeyEnvGuard::set(kms::KEY_SOURCE_ENV, Some("env"));
        let verifier = Verifier::with_source(None, Some("env"))
            .await
            .expect("verifier");
        (pair, verifier)
    }

    /// The v3 equivalent of [`verifier_for_v4`].
    async fn verifier_for_v3() -> (AsymmetricKeyPair<V3>, Verifier) {
        let pair = AsymmetricKeyPair::<V3>::generate().expect("v3 keygen");
        KeyEnvGuard::set(
            kms::PUB_KEY_ENV,
            Some(&kms::b64url_encode(pair.public.as_bytes())),
        );
        KeyEnvGuard::set(kms::KEY_SOURCE_ENV, Some("env"));
        let verifier = Verifier::with_source(None, Some("env"))
            .await
            .expect("verifier");
        (pair, verifier)
    }

    fn v4_token(secret: &AsymmetricSecretKey<V4>) -> String {
        let claims = Claims::new_expires_in(&Duration::from_secs(3600)).expect("claims");
        V4PublicToken::sign(
            secret,
            Claims::to_string(&claims).unwrap().as_bytes(),
            None,
            None,
        )
        .expect("v4 sign")
    }

    fn v3_token(secret: &AsymmetricSecretKey<V3>) -> String {
        let claims = Claims::new_expires_in(&Duration::from_secs(3600)).expect("claims");
        V3PublicToken::sign(
            secret,
            Claims::to_string(&claims).unwrap().as_bytes(),
            None,
            None,
        )
        .expect("v3 sign")
    }

    /// Assert a 401. Takes the error by reference so callers can still assert on
    /// the message afterwards.
    fn assert_401(err: &RouterError) {
        assert!(
            matches!(err, RouterError::Unauthenticated(_)),
            "expected a 401 Unauthenticated, got {err:?}"
        );
    }

    #[tokio::test]
    async fn v4_env_round_trip_returns_the_signed_claims() {
        let _guard = (env_lock(), KeyEnvGuard::capture());
        let (pair, verifier) = verifier_for_v4().await;
        let token = v4_token(&pair.secret);

        assert!(token.starts_with(kms::V4_HEADER));
        let claims = verifier.verify_token(&token).await.expect("verify");
        assert!(claims.contains_claim("iat"));
        assert!(claims.contains_claim("exp"));
    }

    #[tokio::test]
    async fn v3_env_round_trip_returns_the_signed_claims() {
        let _guard = (env_lock(), KeyEnvGuard::capture());
        let (pair, verifier) = verifier_for_v3().await;
        let token = v3_token(&pair.secret);

        assert!(token.starts_with(kms::V3_HEADER));
        let claims = verifier.verify_token(&token).await.expect("verify");
        assert!(claims.contains_claim("exp"));
    }

    #[tokio::test]
    async fn bearer_prefixed_token_is_accepted() {
        let _guard = (env_lock(), KeyEnvGuard::capture());
        let (pair, verifier) = verifier_for_v4().await;
        let token = v4_token(&pair.secret);

        verifier
            .verify_token(&format!("Bearer {token}"))
            .await
            .expect("legacy `Bearer ` stripping must keep working");
    }

    #[tokio::test]
    async fn token_signed_by_another_key_is_rejected() {
        let _guard = (env_lock(), KeyEnvGuard::capture());
        let (pair, _) = verifier_for_v4().await;
        let intruder = AsymmetricKeyPair::<V4>::generate().expect("intruder keygen");
        let token = v4_token(&intruder.secret);

        // Reconfigure on the legitimate key, so the *only* possible cause of
        // failure is the wrong signature.
        KeyEnvGuard::set(
            kms::PUB_KEY_ENV,
            Some(&kms::b64url_encode(pair.public.as_bytes())),
        );
        let verifier = Verifier::with_source(None, Some("env"))
            .await
            .expect("verifier");

        assert_401(
            &verifier
                .verify_token(&token)
                .await
                .expect_err("must reject"),
        );
    }

    #[tokio::test]
    async fn garbage_empty_and_headerless_tokens_are_401() {
        let _guard = (env_lock(), KeyEnvGuard::capture());
        let (_, verifier) = verifier_for_v4().await;

        for bad in ["", "not-a-token", "v2.public.abc", "v4.local.abc"] {
            assert_401(&verifier.verify_token(bad).await.expect_err("must reject"));
        }
    }

    #[tokio::test]
    async fn v3_configured_verifier_refuses_a_v4_token() {
        let _guard = (env_lock(), KeyEnvGuard::capture());
        let (v3_pair, _) = verifier_for_v3().await;
        let v4_pair = AsymmetricKeyPair::<V4>::generate().expect("v4 keygen");
        let v4_token = v4_token(&v4_pair.secret);

        KeyEnvGuard::set(
            kms::PUB_KEY_ENV,
            Some(&kms::b64url_encode(v3_pair.public.as_bytes())),
        );
        let verifier = Verifier::with_source(None, Some("env"))
            .await
            .expect("verifier");
        assert_eq!(verifier.version(), PasetoVersion::V3);

        let err = verifier
            .verify_token(&v4_token)
            .await
            .expect_err("a v4 token must not be parsed by a v3 verifier");
        assert_401(&err);
        assert!(
            err.to_string().contains("does not match"),
            "a version mismatch must name itself, not look like a bad signature: {err}"
        );
    }

    #[tokio::test]
    async fn v4_configured_verifier_refuses_a_v3_token() {
        let _guard = (env_lock(), KeyEnvGuard::capture());
        let (v4_pair, _) = verifier_for_v4().await;
        let v3_pair = AsymmetricKeyPair::<V3>::generate().expect("v3 keygen");
        let v3_token = v3_token(&v3_pair.secret);

        KeyEnvGuard::set(
            kms::PUB_KEY_ENV,
            Some(&kms::b64url_encode(v4_pair.public.as_bytes())),
        );
        let verifier = Verifier::with_source(None, Some("env"))
            .await
            .expect("verifier");
        assert_eq!(verifier.version(), PasetoVersion::V4);

        assert_401(
            &verifier
                .verify_token(&v3_token)
                .await
                .expect_err("must reject"),
        );
    }

    #[tokio::test]
    async fn truncated_body_is_401() {
        let _guard = (env_lock(), KeyEnvGuard::capture());
        let (pair, verifier) = verifier_for_v4().await;
        let token = v4_token(&pair.secret);

        // Keep the header, chop half the body: the version check still passes, so
        // the rejection has to come from the signature maths.
        let truncated = format!(
            "{}{}",
            kms::V4_HEADER,
            &token[kms::V4_HEADER.len()..token.len() / 2]
        );
        assert_401(
            &verifier
                .verify_token(&truncated)
                .await
                .expect_err("must reject"),
        );
    }

    #[tokio::test]
    async fn expired_token_is_rejected() {
        let _guard = (env_lock(), KeyEnvGuard::capture());
        let (pair, verifier) = verifier_for_v4().await;

        // `exp` explicitly in the past. `add_additional("exp", ..)` would be
        // refused because `exp` is a registered claim, so the setter is used.
        let mut claims = Claims::new_expires_in(&Duration::from_secs(3600)).expect("claims");
        claims.expiration("2000-01-01T00:00:00Z").expect("exp");
        let token = V4PublicToken::sign(
            &pair.secret,
            Claims::to_string(&claims).unwrap().as_bytes(),
            None,
            None,
        )
        .expect("sign");

        assert_401(
            &verifier
                .verify_token(&token)
                .await
                .expect_err("must reject"),
        );
    }

    #[tokio::test]
    async fn missing_public_key_is_a_500() {
        let _lock = env_lock();
        let _guard = KeyEnvGuard::capture();
        KeyEnvGuard::set(kms::PUB_KEY_ENV, None);

        let err = Verifier::with_source(None, Some("env"))
            .await
            .expect_err("a verifier with no key must not be constructible");
        assert!(
            matches!(err, RouterError::KeyPairError(_)),
            "expected KeyPairError, got {err:?}"
        );
        assert!(err.to_string().contains("PASETO_PUB_KEY"), "{err}");
    }

    #[tokio::test]
    async fn blank_public_key_is_a_500() {
        let _lock = env_lock();
        let _guard = KeyEnvGuard::capture();
        KeyEnvGuard::set(kms::PUB_KEY_ENV, Some("  "));

        assert!(matches!(
            Verifier::with_source(None, Some("env"))
                .await
                .expect_err("must reject"),
            RouterError::KeyPairError(_)
        ));
    }

    #[tokio::test]
    async fn wrong_length_public_key_is_a_500() {
        let _lock = env_lock();
        let _guard = KeyEnvGuard::capture();
        KeyEnvGuard::set(kms::PUB_KEY_ENV, Some(&kms::b64url_encode(&[7u8; 7])));

        let err = Verifier::with_source(None, Some("env"))
            .await
            .expect_err("a 7-byte key must be rejected, not unwrapped");
        assert!(matches!(err, RouterError::KeyPairError(_)), "{err:?}");
        assert!(err.to_string().contains("49"), "must name the sizes: {err}");
        assert!(err.to_string().contains("32"), "must name the sizes: {err}");
    }

    #[tokio::test]
    async fn env_source_reports_itself_as_not_kms() {
        let _guard = (env_lock(), KeyEnvGuard::capture());
        let (_, verifier) = verifier_for_v4().await;

        assert!(!verifier.is_kms());
        assert_eq!(verifier.kms_key_id(), "");
        assert_eq!(verifier.version(), PasetoVersion::V4);
    }

    #[tokio::test]
    async fn unknown_key_source_never_falls_back() {
        let _lock = env_lock();
        let _guard = KeyEnvGuard::capture();
        KeyEnvGuard::set(kms::PUB_KEY_ENV, Some("irrelevant"));

        // A silent fallback would verify against local keys because of a typo in
        // the source name; it must be a loud 500 instead.
        let err = Verifier::with_source(None, Some("vault"))
            .await
            .expect_err("must reject");
        assert!(matches!(err, RouterError::KeyPairError(_)), "{err:?}");
        assert!(
            err.to_string().contains("vault"),
            "the message must quote the offending value: {err}"
        );
    }

    #[tokio::test]
    async fn explicit_env_source_beats_the_lambda_default() {
        let _guard = (env_lock(), KeyEnvGuard::capture());
        let pair = AsymmetricKeyPair::<V4>::generate().expect("keygen");
        KeyEnvGuard::set(
            kms::PUB_KEY_ENV,
            Some(&kms::b64url_encode(pair.public.as_bytes())),
        );

        // `KeyEnvGuard` pins `LAMBDA_TASK_ROOT`, so the implicit default here is
        // `Kms`. The explicit `"env"` argument must win, and must win without
        // touching AWS — proof that `with_source` resolves the argument rather
        // than passing it through.
        let verifier = Verifier::with_source(None, Some("env"))
            .await
            .expect("verifier");
        assert!(!verifier.is_kms());
        assert_eq!(verifier.kms_key_id(), "");
    }

    /// `new(None)` — unlike `with_source` — resolves the source from
    /// `LAMBDA_TASK_ROOT` alone. On Lambda that means `Kms`, and with no
    /// `KMS_KEY_ID` present it must fail rather than quietly falling back to env.
    #[tokio::test]
    async fn new_on_lambda_defaults_to_kms_and_never_falls_back() {
        let _lock = env_lock();
        let _guard = KeyEnvGuard::capture();
        KeyEnvGuard::set(kms::KMS_KEY_ID_ENV, None);
        KeyEnvGuard::set(kms::PUB_KEY_ENV, Some("irrelevant"));

        // `LAMBDA_TASK_ROOT` is pinned by the guard, so `env_default()` is `Kms`.
        // A perfectly good `PASETO_PUB_KEY` is present and must still be ignored:
        // silently verifying with local keys when AWS was the configured source
        // is exactly the downgrade this must not perform.
        let err = Verifier::new(None).await.expect_err("must reject");
        assert!(matches!(err, RouterError::KeyPairError(_)), "{err:?}");
        assert!(
            err.to_string().contains("KMS_KEY_ID"),
            "the message must name the variable to set: {err}"
        );
    }
}
