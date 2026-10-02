//! PASETO v3 / v4 public-mode signing.
//!
//! A [`Signer`] is built once — from AWS KMS or from the local environment — and
//! then mints tokens for the lifetime of the instance. Two sources, one API:
//!
//! * **`env`** — the raw secret key lives in the process, so pasetors owns the
//!   whole operation: `version{3,4}::PublicToken::sign` builds the PAE, signs and
//!   assembles the token. Nothing is hand-framed and nothing does I/O.
//! * **`kms`** — the secret key never leaves AWS, so pasetors *cannot* sign. The
//!   pre-authentication encoding is therefore built here and handed to KMS as a
//!   `MessageType::Raw` message; KMS hashes and signs.
//!
//! # The PAE ordering is load-bearing
//!
//! PASETO signs a pre-authentication encoding of the token's parts, and the two
//! public-mode versions order them differently. **PASETO v3 puts the 49-byte
//! compressed public key first, before the header**:
//! `PAE([public_key, header, message, footer, implicit_assertion])`. That is why
//! [`Signer`] retains the public key even though it never signs locally —
//! reversing the order silently breaks every verification, with no error at the
//! call site.
//!
//! # KMS message type and signature encoding
//!
//! Both algorithms use `MessageType::Raw`: KMS receives the raw PAE bytes and
//! hashes internally.
//!
//! * `ECC_NIST_EDWARDS25519` + `ED25519_SHA_512` → a pure 64-byte RFC 8032
//!   signature, exactly what v4 wants. `ED25519_PH_SHA_512` is deliberately never
//!   used: it takes a digest and hashes again, which double-hashes.
//! * `ECC_NIST_P384` + `ECDSA_SHA_384` → **DER**-encoded `SEQUENCE{r, s}` that
//!   `kms::ecdsa_der_to_raw96` converts into the fixed 96 raw bytes v3 requires.
//!
//! KMS ECDSA is non-deterministic (no RFC 6979); PASETO v3 explicitly permits
//! CSPRNG nonces, so that is compliant.
//!
//! # Key rotation
//!
//! Rotating the KMS key **invalidates every previously issued v3 token
//! immediately**: v3 binds the public key into the PAE, so a token signed by the
//! old key can never verify under the new one and there is no overlap window. For
//! v4 a rotation is equally fatal but for the ordinary reason — a different key
//! means a different signature. Issue v4 if you need a graceful turnover.
//!
//! # Hot path
//!
//! With the `env` source, signing performs no I/O at all. With the `kms` source
//! every signature is one `Sign` call, which is the entire point of keeping the
//! key in KMS.

use crate::errors::TokenError;
use crate::kms::{
    self, KeySource, KmsError, PasetoVersion, V3_PUBLIC_KEY_LEN, V3_PUBLIC_SIG_LEN,
    V3_SECRET_KEY_LEN, V4_PUBLIC_KEY_LEN, V4_PUBLIC_SIG_LEN, V4_SECRET_KEY_LEN,
};
use aws_sdk_kms::types::MessageType;
// Re-exported by the generated SDK client rather than depended on directly: the
// crate's own `Cargo.toml` is off-limits, and this is the exact type `Sign::message` wants.
use aws_sdk_kms::primitives::Blob;
use tracing;
use pasetors::claims::Claims;
use pasetors::keys::AsymmetricSecretKey;
use pasetors::version3::V3;
use pasetors::version4::V4;
use serde_json::json;
use std::collections::HashMap;
use std::env;
use std::time::Duration;

/// Lifetime of an access token: 1 hour.
const ACCESS_TOKEN_SECONDS: u64 = 3600;
/// Lifetime of a refresh token: 2 days.
const REFRESH_TOKEN_SECONDS: u64 = 2 * 24 * 3600;

/// Message used when the local signing key is absent or blank.
const NO_SIGNING_KEY: &str = "no signing key loaded: set PASETO_PRV_KEY to enable token signing";

/// Message used when the KMS `Sign` response carries no signature.
const NO_SIGNATURE: &str = "KMS Sign returned no signature bytes";

/// The local secret key for whichever PASETO version the deployment pins.
///
/// Never used by the `kms` source, which signs remotely. It is an `Option`
/// rather than a dummy value so that a KMS-backed signer physically cannot sign
/// locally: there is no key material to sign with, so a source mismatch surfaces
/// as a 500 instead of a token nobody can verify.
#[derive(Debug)]
enum SecretMaterial {
    /// PASETO v3 — 48-byte P-384 scalar.
    V3(AsymmetricSecretKey<V3>),
    /// PASETO v4 — 64-byte Ed25519 seed || public key.
    V4(AsymmetricSecretKey<V4>),
}

/// A PASETO signing handle, pinned to one key and one version.
///
/// Build it with [`Signer::new`] or [`Signer::with_source`].
#[derive(Debug)]
pub struct Signer {
    /// Where the signing key came from. Resolved once in the constructor and
    /// never re-decided per call, so a KMS outage can never silently downgrade
    /// this instance to signing with local env keys.
    source: KeySource,
    /// The pinned PASETO version, derived from key material.
    version: PasetoVersion,
    /// The resolved KMS key reference. Empty for the `env` source.
    kms_key_id: String,
    /// Raw public-key bytes in the form the PAE needs: 49 compressed bytes for v3.
    ///
    /// Empty for v4, whose PAE carries no key, and for the `env` source, where
    /// pasetors builds the PAE itself and nothing is hand-framed. v3 is the reason
    /// this field exists at all: the key is *inside* the signed pre-authentication
    /// encoding even though it is never used to sign.
    kms_public_key: Vec<u8>,
    /// The local secret key. `None` for the `kms` source.
    env_secret: Option<SecretMaterial>,
}

impl Signer {
    /// Build a signer from the environment.
    ///
    /// # Environment variables
    ///
    /// * `PASETO_KEY_SOURCE` — `kms`, `env` or `auto` (default). `auto` resolves
    ///   to `kms` on Lambda and `env` off it.
    /// * `KMS_KEY_ID` — the KMS key, required by the `kms` source.
    /// * `PASETO_PRV_KEY` — base64url raw secret key, required by the `env`
    ///   source. 64 bytes selects v4, 48 bytes selects v3.
    ///
    /// `.env` is loaded first when `LAMBDA_TASK_ROOT` is absent, so a local run
    /// behaves like the deployed one.
    ///
    /// # Errors
    ///
    /// * [`TokenError::KeyPairError`] — unusable configuration, or a
    ///   `GetPublicKey` / transport failure.
    pub async fn new(key_id: Option<String>) -> Result<Self, TokenError> {
        kms::load_dotenv_if_local();
        let source = KeySource::resolve(None)?;
        Self::build(source, key_id).await
    }

    /// Build a signer from an explicit key source and optional key id.
    ///
    /// `source` is the raw `PASETO_KEY_SOURCE` string (`kms` / `env` / `auto` /
    /// `None`) rather than a [`KeySource`]: `KeySource` is crate-private, and
    /// naming it in a public signature would leak a non-public type through this
    /// crate's public API. [`Signer::new`] is the `None` shorthand.
    ///
    /// # Errors
    ///
    /// See [`Signer::new`].
    pub async fn with_source(
        key_id: Option<String>,
        source: Option<&str>,
    ) -> Result<Self, TokenError> {
        kms::load_dotenv_if_local();
        let source = KeySource::resolve(source)?;
        Self::build(source, key_id).await
    }

    async fn build(source: KeySource, key_id: Option<String>) -> Result<Self, TokenError> {
        match source {
            KeySource::Env => Self::from_env_keys(),
            KeySource::Kms => Self::from_kms(key_id).await,
        }
    }

    /// Build from `PASETO_PRV_KEY`. Purely local: no AWS client is constructed.
    fn from_env_keys() -> Result<Self, TokenError> {
        let configured = env::var(kms::PRV_KEY_ENV)
            .map_err(|_| TokenError::KeyPairError(NO_SIGNING_KEY.to_string()))?;
        let trimmed = configured.trim();
        if trimmed.is_empty() {
            return Err(TokenError::KeyPairError(NO_SIGNING_KEY.to_string()));
        }

        let bytes = kms::b64url_decode(trimmed)?;
        // Dispatch on the *secret* length, not the public one: this instance never
        // sees a public key, and the two lengths cannot collide (64 vs 48).
        let version = match bytes.len() {
            V4_SECRET_KEY_LEN => PasetoVersion::V4,
            V3_SECRET_KEY_LEN => PasetoVersion::V3,
            other => {
                return Err(TokenError::KeyPairError(format!(
                    "PASETO_PRV_KEY must be {V4_SECRET_KEY_LEN} raw bytes (v4) or \
                     {V3_SECRET_KEY_LEN} raw bytes (v3), got {other}"
                )));
            }
        };

        // The inherent `from`, not a `TryFrom`: pasetors provides no
        // `TryFrom<&[u8]>` impl for its key types.
        let env_secret = match version {
            PasetoVersion::V4 => {
                SecretMaterial::V4(AsymmetricSecretKey::<V4>::from(&bytes).map_err(|e| {
                    TokenError::KeyPairError(format!("invalid v4 secret key: {e}"))
                })?)
            }
            PasetoVersion::V3 => {
                SecretMaterial::V3(AsymmetricSecretKey::<V3>::from(&bytes).map_err(|e| {
                    TokenError::KeyPairError(format!("invalid v3 secret key: {e}"))
                })?)
            }
        };

        tracing::info!(
            version = ?version,
            "PASETO signer configured from PASETO_PRV_KEY"
        );
        Ok(Self {
            source: KeySource::Env,
            version,
            kms_key_id: String::new(),
            // v4's PAE carries no key and the `env` path never frames anything by
            // hand, so there is nothing to retain.
            kms_public_key: Vec::new(),
            env_secret: Some(env_secret),
        })
    }

    /// Resolve the KMS key, fetch its public key, and pin the version to its
    /// `KeySpec`.
    ///
    /// The public key is fetched even though this instance only signs, because
    /// v3's PAE puts it first and the signer therefore has to hold it.
    async fn from_kms(key_id: Option<String>) -> Result<Self, TokenError> {
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
        // Never `unwrap` an SDK `Option` accessor.
        let spec = output.key_spec().ok_or_else(|| {
            TokenError::KeyPairError("KMS GetPublicKey returned no KeySpec".to_string())
        })?;
        let version = PasetoVersion::from_key_spec(spec)?;

        // `.as_ref()` rather than deref coercion: `Blob` has no `Deref`.
        let spki = output.public_key().ok_or(KmsError::MissingPublicKey)?;
        let kms_public_key = match version {
            PasetoVersion::V3 => {
                let key = kms::p384_public_key_from_spki(spki.as_ref())?;
                key.as_bytes().to_vec()
            }
            PasetoVersion::V4 => {
                let key = kms::ed25519_public_key_from_spki(spki.as_ref())?;
                key.as_bytes().to_vec()
            }
        };

        // These bytes go straight into the v3 PAE, so a length that disagrees
        // with the pinned version would mint tokens no implementation could
        // verify. Fail loudly here instead.
        let expected = match version {
            PasetoVersion::V3 => V3_PUBLIC_KEY_LEN,
            PasetoVersion::V4 => V4_PUBLIC_KEY_LEN,
        };
        if kms_public_key.len() != expected {
            return Err(TokenError::KeyPairError(format!(
                "KMS public key length mismatch for {version:?}: got {}, want {expected}",
                kms_public_key.len()
            )));
        }

        tracing::info!(version = ?version, "PASETO signer configured from KMS");
        Ok(Self {
            source: KeySource::Kms,
            version,
            kms_key_id: key_id,
            kms_public_key,
            env_secret: None,
        })
    }

    /// Sign a claims document and return the compact token string.
    ///
    /// With the `env` source, pasetors owns the whole operation. With the `kms`
    /// source the PAE is built here ([`Signer::kms_message`]) and signed remotely.
    ///
    /// # Errors
    ///
    /// [`TokenError::KeyPairError`] (500) on any failure — a signing failure is
    /// a server or key problem, never a caller-auth problem, so it must never be
    /// reported as 401.
    pub async fn sign_claims(
        &self,
        claims: &Claims,
        footer: Option<&[u8]>,
    ) -> Result<String, TokenError> {
        match self.source {
            KeySource::Env => self.sign_local(claims, footer),
            KeySource::Kms => self.sign_via_kms(claims, footer).await,
        }
    }

    /// Local signing: we hold the secret, so pasetors does everything — PAE,
    /// signature maths and token assembly included. Nothing here re-implements any
    /// part of the specification.
    fn sign_local(&self, claims: &Claims, footer: Option<&[u8]>) -> Result<String, TokenError> {
        let payload = kms::claims_to_payload(claims)?;
        let secret = self.env_secret.as_ref().ok_or_else(|| {
            TokenError::KeyPairError(
                "local signing requested but this signer holds no local secret key".to_string(),
            )
        })?;
        match secret {
            SecretMaterial::V3(key) => {
                pasetors::version3::PublicToken::sign(key, &payload, footer, None).map_err(|e| {
                    TokenError::KeyPairError(format!("PASETO v3 signing failed: {e}"))
                })
            }
            SecretMaterial::V4(key) => {
                pasetors::version4::PublicToken::sign(key, &payload, footer, None).map_err(|e| {
                    TokenError::KeyPairError(format!("PASETO v4 signing failed: {e}"))
                })
            }
        }
    }

    /// Remote signing: build the PAE locally, let KMS hash and sign it.
    async fn sign_via_kms(
        &self,
        claims: &Claims,
        footer: Option<&[u8]>,
    ) -> Result<String, TokenError> {
        let payload = kms::claims_to_payload(claims)?;
        let message = self.kms_message(&payload, footer.unwrap_or(&[]))?;
        let signature = self.kms_sign(&message).await?;
        Ok(kms::assemble_token(
            self.version.header(),
            &payload,
            &signature,
            footer,
        ))
    }

    /// Build the exact byte string handed to KMS for signing.
    ///
    /// Split out from [`Signer::sign_via_kms`] because this framing is the part
    /// that is easy to get subtly wrong and the part that cannot be exercised
    /// through the network — which makes it the part that most needs a test.
    fn kms_message(&self, payload: &[u8], footer: &[u8]) -> Result<Vec<u8>, TokenError> {
        match self.version {
            // v4: four pieces, no key material.
            PasetoVersion::V4 => {
                kms::pae(&[kms::V4_HEADER.as_bytes(), payload, footer, &[]]).map_err(Into::into)
            }
            // v3: five pieces, and the 49-byte compressed public key comes FIRST,
            // ahead of the header. PASETO v3 mandates `PAE([pk, h, m, f, i])`; the
            // key is inside the signed data by design, which is what makes a v3
            // signature unforgeable under a different key. Reversing these two
            // pieces silently breaks every v3 verification.
            PasetoVersion::V3 => {
                if self.kms_public_key.len() != V3_PUBLIC_KEY_LEN {
                    return Err(TokenError::KeyPairError(format!(
                        "PASETO v3 PAE needs the {V3_PUBLIC_KEY_LEN}-byte compressed public key \
                         first, but {} bytes are loaded",
                        self.kms_public_key.len()
                    )));
                }
                kms::pae(&[
                    &self.kms_public_key,
                    kms::V3_HEADER.as_bytes(),
                    payload,
                    footer,
                    &[],
                ])
                .map_err(Into::into)
            }
        }
    }

    /// Sign one already-framed message and return the raw signature bytes in the
    /// exact form PASETO embeds.
    async fn kms_sign(&self, message: &[u8]) -> Result<Vec<u8>, TokenError> {
        let client = kms::kms_client().await;
        let output = client
            .sign()
            .key_id(&self.kms_key_id)
            .message(Blob::new(message.to_vec()))
            // Raw, not DIGEST. PASETO v3 signs `SHA-384(PAE(...))` and v4 signs the
            // PAE itself, so KMS is handed the PAE and hashes it internally. A
            // DIGEST request would either double-hash (v4) or ask KMS to verify
            // something we did not compute (v3).
            .message_type(MessageType::Raw)
            .signing_algorithm(self.version.signing_algorithm())
            .send()
            .await
            .map_err(|e| KmsError::Sign(Box::new(e)))?;

        // Never `unwrap` an SDK `Option` accessor.
        let signature = output
            .signature()
            .ok_or_else(|| TokenError::KeyPairError(NO_SIGNATURE.to_string()))?;
        let raw = signature.as_ref();

        match self.version {
            // v4: the bytes KMS returns *are* the 64-byte RFC 8032 signature, so
            // they are used directly. `ED25519_PH_SHA_512` is never requested — it
            // consumes a digest and hashes again, which would double-hash.
            PasetoVersion::V4 => {
                if raw.len() != V4_PUBLIC_SIG_LEN {
                    return Err(TokenError::KeyPairError(format!(
                        "Ed25519 signature must be {V4_PUBLIC_SIG_LEN} bytes, got {}",
                        raw.len()
                    )));
                }
                Ok(raw.to_vec())
            }
            // v3: KMS returns DER `SEQUENCE{r, s}`; PASETO wants fixed-width
            // `r(48) || s(48)`. This is also why there is no `sha2` dependency: KMS
            // already did the SHA-384 for us.
            PasetoVersion::V3 => {
                let fixed = kms::ecdsa_der_to_raw96(raw)?;
                debug_assert_eq!(fixed.len(), V3_PUBLIC_SIG_LEN);
                Ok(fixed.to_vec())
            }
        }
    }

    /// Mint an access token: 1-hour lifetime, no `typ` claim.
    pub async fn gen_access_token(
        &self,
        sub: &str,
        aud: &str,
        extra: Option<HashMap<String, String>>,
    ) -> Result<String, TokenError> {
        self.gen_token(sub, aud, ACCESS_TOKEN_SECONDS, extra).await
    }

    /// Mint a refresh token: 2-day lifetime plus `typ = "refresh"`.
    pub async fn gen_refresh_token(
        &self,
        sub: &str,
        aud: &str,
        extra: Option<HashMap<String, String>>,
    ) -> Result<String, TokenError> {
        let mut extras = extra.unwrap_or_default();
        // The discriminator is set here, at the one place that knows which kind of
        // token is being minted, so a caller cannot forget it and a downstream
        // verifier can tell the two apart without inspecting the lifetime.
        extras.insert("typ".to_string(), "refresh".to_string());
        self.gen_token(sub, aud, REFRESH_TOKEN_SECONDS, Some(extras))
            .await
    }

    async fn gen_token(
        &self,
        sub: &str,
        aud: &str,
        secs: u64,
        extra: Option<HashMap<String, String>>,
    ) -> Result<String, TokenError> {
        let claims = build_claims(sub, aud, secs, extra)?;
        self.sign_claims(&claims, None).await
    }

    /// The pinned PASETO version, so a deployment can assert at start-up which
    /// version it issues.
    pub fn version(&self) -> PasetoVersion {
        self.version
    }

    /// `true` when this signer holds no local secret and signs via KMS.
    pub fn is_kms(&self) -> bool {
        matches!(self.source, KeySource::Kms)
    }

    /// The resolved KMS key reference. Empty for the `env` source, which has no
    /// AWS key to name.
    pub fn kms_key_id(&self) -> &str {
        &self.kms_key_id
    }
}

/// Build the claim set for a token.
///
/// Mirrors the legacy `Keys::gen_token` shape exactly, so a token issued through
/// the new signer is indistinguishable from one issued through the old path.
fn build_claims(
    sub: &str,
    aud: &str,
    secs: u64,
    extra: Option<HashMap<String, String>>,
) -> Result<Claims, TokenError> {
    let duration = Duration::from_secs(secs);
    let mut claims = Claims::new_expires_in(&duration)?;
    claims.subject(sub)?;
    claims.audience(aud)?;
    if let Some(extras) = extra {
        for (key, value) in &extras {
            // Only the key is logged: claim values routinely carry user data.
            tracing::debug!("token extra claim added: {key}");
            claims.add_additional(key, json!(value))?;
        }
    }
    Ok(claims)
}

#[cfg(test)]
mod test {
    // Holding the env lock across `.await` is the point: the constructors read
    // process-global variables, so releasing the lock between the `set` and the
    // `new` would let a concurrent test change them underneath. Nothing in this
    // module blocks on real I/O, so the guard is held for microseconds.
    #![allow(clippy::await_holding_lock)]

    use super::*;
    // The environment is process-global, so `signer` and `verifier` must share
    // one lock and one RAII snapshot helper rather than each locking itself.
    use crate::verifier::Verifier;
    use crate::verifier::test::{KeyEnvGuard, env_lock};
    use pasetors::keys::{AsymmetricKeyPair, Generate};
    use pasetors::version3::V3;
    use pasetors::version4::V4;
    use serde_json::json;

    /// Configure the `env` source from a freshly generated v4 keypair and return
    /// a signer plus a verifier built from the matching public half.
    async fn env_v4() -> (Signer, Verifier) {
        let pair = AsymmetricKeyPair::<V4>::generate().expect("v4 keygen");
        KeyEnvGuard::set(
            kms::PUB_KEY_ENV,
            Some(&kms::b64url_encode(pair.public.as_bytes())),
        );
        KeyEnvGuard::set(
            kms::PRV_KEY_ENV,
            Some(&kms::b64url_encode(pair.secret.as_bytes())),
        );
        let signer = Signer::with_source(None, Some("env"))
            .await
            .expect("signer");
        let verifier = Verifier::with_source(None, Some("env"))
            .await
            .expect("verifier");
        (signer, verifier)
    }

    /// The v3 equivalent of [`env_v4`].
    async fn env_v3() -> (Signer, Verifier) {
        let pair = AsymmetricKeyPair::<V3>::generate().expect("v3 keygen");
        KeyEnvGuard::set(
            kms::PUB_KEY_ENV,
            Some(&kms::b64url_encode(pair.public.as_bytes())),
        );
        KeyEnvGuard::set(
            kms::PRV_KEY_ENV,
            Some(&kms::b64url_encode(pair.secret.as_bytes())),
        );
        let signer = Signer::with_source(None, Some("env"))
            .await
            .expect("signer");
        let verifier = Verifier::with_source(None, Some("env"))
            .await
            .expect("verifier");
        (signer, verifier)
    }

    fn extras(pairs: &[(&str, &str)]) -> Option<HashMap<String, String>> {
        Some(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        )
    }

    /// `exp - iat` in whole seconds, read back off the verified claims.
    ///
    /// `Claims` exposes `iat` / `exp` as RFC 3339 strings and nothing else, so
    /// this parses both with a deliberately small reader (the subset pasetors
    /// emits: `YYYY-MM-DDTHH:MM:SSZ`) and does civil-date arithmetic.
    fn lifetime_seconds(claims: &Claims) -> i64 {
        fn epoch(text: &str) -> i64 {
            let num = |from: usize, to: usize| -> i64 {
                text[from..to]
                    .parse::<i64>()
                    .unwrap_or_else(|_| panic!("bad datetime {text}"))
            };
            assert_eq!(text.len(), 20, "unexpected RFC 3339 shape: {text}");
            let (y, mo, d) = (num(0, 4), num(5, 7), num(8, 10));
            let (h, mi, s) = (num(11, 13), num(14, 16), num(17, 19));

            // Howard Hinnant's days-from-civil: exact for the proleptic Gregorian
            // calendar, and no dependency needed.
            let y = if mo <= 2 { y - 1 } else { y };
            let era = if y >= 0 { y } else { y - 399 } / 400;
            let yoe = y - era * 400;
            let mp = (mo + 9) % 12;
            let doy = (153 * mp + 2) / 5 + d - 1;
            let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
            (era * 146_097 + doe - 719_468) * 86_400 + h * 3_600 + mi * 60 + s
        }

        let iat = claims
            .get_claim("iat")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("no iat claim"));
        let exp = claims
            .get_claim("exp")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("no exp claim"));
        epoch(exp) - epoch(iat)
    }

    #[tokio::test]
    async fn v4_access_token_round_trips_with_extras() {
        let _guard = (env_lock(), KeyEnvGuard::capture());
        let (signer, verifier) = env_v4().await;

        let token = signer
            .gen_access_token("user-1", "aud-1", extras(&[("role", "admin")]))
            .await
            .expect("access token");

        assert!(token.starts_with(kms::V4_HEADER), "header was {token:?}");
        let claims = verifier.verify_token(&token).await.expect("verify");
        assert_eq!(
            claims.get_claim("sub").and_then(|v| v.as_str()),
            Some("user-1")
        );
        assert_eq!(
            claims.get_claim("aud").and_then(|v| v.as_str()),
            Some("aud-1")
        );
        assert_eq!(
            claims.get_claim("role"),
            Some(&json!("admin")),
            "an extra claim must survive the round trip"
        );
    }

    #[tokio::test]
    async fn v3_access_token_round_trips() {
        let _guard = (env_lock(), KeyEnvGuard::capture());
        let (signer, verifier) = env_v3().await;

        let token = signer
            .gen_access_token("user-3", "aud-3", None)
            .await
            .expect("access token");

        assert!(token.starts_with(kms::V3_HEADER), "header was {token:?}");
        let claims = verifier.verify_token(&token).await.expect("verify");
        assert_eq!(
            claims.get_claim("sub").and_then(|v| v.as_str()),
            Some("user-3")
        );
        assert_eq!(
            claims.get_claim("aud").and_then(|v| v.as_str()),
            Some("aud-3")
        );
    }

    #[tokio::test]
    async fn access_token_lives_one_hour() {
        let _guard = (env_lock(), KeyEnvGuard::capture());
        let (signer, verifier) = env_v4().await;

        let token = signer
            .gen_access_token("u", "a", None)
            .await
            .expect("token");
        let claims = verifier.verify_token(&token).await.expect("verify");

        assert_eq!(
            lifetime_seconds(&claims),
            ACCESS_TOKEN_SECONDS as i64,
            "exp - iat must equal the declared access-token lifetime"
        );
    }

    #[tokio::test]
    async fn refresh_token_lives_two_days() {
        let _guard = (env_lock(), KeyEnvGuard::capture());
        let (signer, verifier) = env_v4().await;

        let token = signer
            .gen_refresh_token("u", "a", None)
            .await
            .expect("token");
        let claims = verifier.verify_token(&token).await.expect("verify");

        assert_eq!(lifetime_seconds(&claims), REFRESH_TOKEN_SECONDS as i64);
    }

    #[tokio::test]
    async fn refresh_token_carries_typ_and_access_token_does_not() {
        let _guard = (env_lock(), KeyEnvGuard::capture());
        let (signer, verifier) = env_v4().await;

        let refresh = signer
            .gen_refresh_token("u", "a", None)
            .await
            .expect("token");
        let access = signer
            .gen_access_token("u", "a", None)
            .await
            .expect("token");

        let refresh_claims = verifier.verify_token(&refresh).await.expect("verify");
        assert_eq!(refresh_claims.get_claim("typ"), Some(&json!("refresh")));

        let access_claims = verifier.verify_token(&access).await.expect("verify");
        assert_eq!(
            access_claims.get_claim("typ"),
            None,
            "an access token must not claim to be a refresh token"
        );
    }

    #[tokio::test]
    async fn refresh_token_preserves_caller_extras() {
        let _guard = (env_lock(), KeyEnvGuard::capture());
        let (signer, verifier) = env_v4().await;

        let token = signer
            .gen_refresh_token("u", "a", extras(&[("scope", "read")]))
            .await
            .expect("token");
        let claims = verifier.verify_token(&token).await.expect("verify");
        assert_eq!(claims.get_claim("scope"), Some(&json!("read")));
    }

    #[tokio::test]
    async fn v3_pae_puts_the_public_key_first() {
        // Documents *why* the ordering inside `kms_message` is load-bearing: the
        // key-first five-piece PAE differs from both a header-first ordering and a
        // v4-style four-piece PAE, so any reordering mints tokens that nothing can
        // verify — silently.
        let key = vec![0x02u8; V3_PUBLIC_KEY_LEN];
        let header = kms::V3_HEADER.as_bytes();
        let payload = b"payload";
        let footer: &[u8] = b"footer";

        let key_first = kms::pae(&[&key, header, payload, footer, &[]]).expect("pae");
        let four_piece = kms::pae(&[header, payload, footer, &[]]).expect("pae");
        assert_ne!(
            key_first, four_piece,
            "v3's five-piece PAE must not equal a four-piece v4-style PAE"
        );

        let key_second = kms::pae(&[header, &key, payload, footer, &[]]).expect("pae");
        assert_ne!(
            key_first, key_second,
            "the key's position in the piece list is significant, not decorative"
        );
    }

    /// Build a `Signer` directly, so the framing paths that need a populated
    /// `kms_public_key` can be exercised without AWS.
    ///
    /// The `kms` source cannot be built offline — it needs a real `GetPublicKey`
    /// response — so a struct literal is the only way to reach those arms. The
    /// constructed value is still consistent: the key length matches the version,
    /// which is exactly the invariant `Signer::from_kms` enforces.
    fn offline_kms_signer(version: PasetoVersion, public_len: usize) -> Signer {
        Signer {
            source: KeySource::Kms,
            version,
            kms_key_id: "offline-test-key".to_string(),
            kms_public_key: vec![0x02u8; public_len],
            env_secret: None,
        }
    }

    #[tokio::test]
    async fn v4_kms_message_has_no_key_piece() {
        // The counterpart to the v3 ordering test: v4's PAE is four pieces, the
        // header first, with no key material at all.
        let signer = offline_kms_signer(PasetoVersion::V4, V4_PUBLIC_KEY_LEN);
        let message = signer.kms_message(b"payload", b"footer").expect("message");
        assert_eq!(
            message,
            kms::pae(&[kms::V4_HEADER.as_bytes(), b"payload", b"footer", &[]]).expect("pae")
        );
    }

    #[tokio::test]
    async fn v3_kms_message_puts_a_loaded_key_first() {
        // `kms_message` is unit-testable without AWS precisely because it touches
        // only local state, which is what makes the hand-rolled framing safe to
        // ship on the one path that cannot be integration-tested offline.
        let signer = offline_kms_signer(PasetoVersion::V3, V3_PUBLIC_KEY_LEN);
        let message = signer.kms_message(b"payload", b"footer").expect("message");
        assert_eq!(
            message,
            kms::pae(&[
                &signer.kms_public_key,
                kms::V3_HEADER.as_bytes(),
                b"payload",
                b"footer",
                &[]
            ])
            .expect("pae")
        );
    }

    #[tokio::test]
    async fn v3_kms_message_refuses_a_signer_without_its_public_key() {
        // A key-less v3 signer must refuse to frame rather than silently emit a
        // PAE that verifies nowhere.
        let signer = offline_kms_signer(PasetoVersion::V3, 0);
        let err = signer
            .kms_message(b"payload", b"")
            .expect_err("must refuse");
        assert!(matches!(err, TokenError::KeyPairError(_)), "{err:?}");
        assert!(err.to_string().contains("49"), "must name the size: {err}");
    }

    #[tokio::test]
    async fn v4_kms_message_ignores_the_unused_public_key() {
        // v4 does not bind a key into the PAE, so the bytes the constructor fetched
        // must not leak into the signed framing.
        let signer = offline_kms_signer(PasetoVersion::V4, 64);
        let message = signer.kms_message(b"payload", b"footer").expect("message");
        assert_eq!(
            message,
            kms::pae(&[kms::V4_HEADER.as_bytes(), b"payload", b"footer", &[]]).expect("pae")
        );
    }

    #[tokio::test]
    async fn footer_is_honoured() {
        let _guard = (env_lock(), KeyEnvGuard::capture());
        let (signer, verifier) = env_v4().await;

        let claims = build_claims("u", "a", ACCESS_TOKEN_SECONDS, None).expect("claims");
        let token = signer
            .sign_claims(&claims, Some(b"key-id-1"))
            .await
            .expect("sign");

        verifier
            .verify_token_with_footer(&token, Some(b"key-id-1"))
            .await
            .expect("a matching footer must verify");

        let err = verifier
            .verify_token_with_footer(&token, Some(b"key-id-2"))
            .await
            .expect_err("a different footer must be rejected");
        assert!(
            matches!(err, TokenError::Unauthenticated(_)),
            "expected 401, got {err:?}"
        );
    }

    #[tokio::test]
    async fn missing_private_key_is_a_500() {
        let _lock = env_lock();
        let _guard = KeyEnvGuard::capture();
        KeyEnvGuard::set(kms::PRV_KEY_ENV, None);

        let err = Signer::with_source(None, Some("env"))
            .await
            .expect_err("a signer with no secret must not be constructible");
        assert!(
            matches!(err, TokenError::KeyPairError(_)),
            "expected KeyPairError, got {err:?}"
        );
        assert!(
            err.to_string().contains("PASETO_PRV_KEY"),
            "the message must name the variable to set: {err}"
        );
    }

    #[tokio::test]
    async fn blank_private_key_is_a_500() {
        let _lock = env_lock();
        let _guard = KeyEnvGuard::capture();
        KeyEnvGuard::set(kms::PRV_KEY_ENV, Some("   "));

        assert!(matches!(
            Signer::with_source(None, Some("env"))
                .await
                .expect_err("must reject"),
            TokenError::KeyPairError(_)
        ));
    }

    #[tokio::test]
    async fn wrong_length_secret_errors_without_panicking() {
        let _lock = env_lock();
        let _guard = KeyEnvGuard::capture();
        KeyEnvGuard::set(kms::PRV_KEY_ENV, Some(&kms::b64url_encode(&[7u8; 7])));

        let err = Signer::with_source(None, Some("env"))
            .await
            .expect_err("a 7-byte secret must be rejected, not unwrapped");
        assert!(
            matches!(err, TokenError::KeyPairError(_)),
            "expected KeyPairError, got {err:?}"
        );
        assert!(err.to_string().contains("64"), "must name the sizes: {err}");
        assert!(err.to_string().contains("48"), "must name the sizes: {err}");
    }

    #[tokio::test]
    async fn unknown_key_source_never_falls_back() {
        let _lock = env_lock();
        let _guard = KeyEnvGuard::capture();
        KeyEnvGuard::set(kms::PRV_KEY_ENV, Some(&kms::b64url_encode(&[7u8; 64])));

        // A silent fallback would start signing with local env keys because of a
        // typo in one variable. It must be a loud 500 instead.
        let err = Signer::with_source(None, Some("vault"))
            .await
            .expect_err("must reject");
        assert!(matches!(err, TokenError::KeyPairError(_)), "{err:?}");
        assert!(
            err.to_string().contains("vault"),
            "the message must quote the offending value: {err}"
        );
    }

    /// `new(None)` resolves the source from `LAMBDA_TASK_ROOT`, which the guard
    /// pins, so the implicit source is `Kms`. A perfectly valid local secret is
    /// present and must still be ignored rather than silently used to sign.
    #[tokio::test]
    async fn new_on_lambda_defaults_to_kms_and_never_falls_back() {
        let _lock = env_lock();
        let _guard = KeyEnvGuard::capture();
        KeyEnvGuard::set(kms::KMS_KEY_ID_ENV, None);
        let pair = AsymmetricKeyPair::<V4>::generate().expect("keygen");
        KeyEnvGuard::set(
            kms::PRV_KEY_ENV,
            Some(&kms::b64url_encode(pair.secret.as_bytes())),
        );

        let err = Signer::new(None).await.expect_err("must reject");
        assert!(matches!(err, TokenError::KeyPairError(_)), "{err:?}");
        assert!(
            err.to_string().contains("KMS_KEY_ID"),
            "the message must name the variable to set: {err}"
        );
    }

    #[tokio::test]
    async fn env_signer_reports_itself_as_not_kms() {
        let _guard = (env_lock(), KeyEnvGuard::capture());
        let (signer, _) = env_v4().await;
        assert!(!signer.is_kms());
        assert_eq!(signer.kms_key_id(), "");
        assert_eq!(signer.version(), PasetoVersion::V4);
    }

    #[tokio::test]
    async fn v3_env_signer_pins_the_v3_version() {
        let _guard = (env_lock(), KeyEnvGuard::capture());
        let (signer, _) = env_v3().await;
        assert_eq!(signer.version(), PasetoVersion::V3);
        assert!(!signer.is_kms());
    }

    #[tokio::test]
    async fn explicit_env_source_is_accepted_by_with_source() {
        let _lock = env_lock();
        let _guard = KeyEnvGuard::capture();
        let pair = AsymmetricKeyPair::<V4>::generate().expect("keygen");
        KeyEnvGuard::set(
            kms::PRV_KEY_ENV,
            Some(&kms::b64url_encode(pair.secret.as_bytes())),
        );

        // `KeyEnvGuard` pins `LAMBDA_TASK_ROOT`, so the implicit default is
        // `Kms`. The explicit `"env"` argument must win, and must win without
        // touching AWS — proof that `with_source` resolves the argument rather
        // than passing it through.
        let signer = Signer::with_source(None, Some("env"))
            .await
            .expect("signer");
        assert!(!signer.is_kms());
        assert_eq!(signer.kms_key_id(), "");
    }

    #[tokio::test]
    async fn a_kms_signer_holds_no_local_secret() {
        // `env_secret` is `None` on the kms source, so a source mix-up fails as a
        // 500 rather than minting a token no key can verify.
        let signer = offline_kms_signer(PasetoVersion::V4, V4_PUBLIC_KEY_LEN);
        assert!(signer.env_secret.is_none());
        assert!(signer.is_kms());
        assert_eq!(signer.kms_key_id(), "offline-test-key");
    }
}
