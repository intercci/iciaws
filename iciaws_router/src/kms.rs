//! Shared primitives for KMS-backed PASETO v3 / v4 signing and verification.
//!
//! The private half of an asymmetric PASETO key never leaves AWS KMS. This
//! module therefore owns everything both the signer and the verifier need and
//! that is *pure*: the PASETO pre-authentication encoding, base64url framing,
//! SPKI decoding, and DERâ†’raw signature conversion. The actual `Sign` /
//! `GetPublicKey` calls live in `signer.rs` / `verifier.rs`; nothing here
//! performs a network request except building a client.
//!
//! # The two PAE orderings
//!
//! PASETO signs a *pre-authentication encoding* of the token's parts, and the
//! two public-mode versions order those parts differently. Getting this wrong
//! does not raise an error at the call site â€” it silently breaks every
//! verification, so the asymmetry is spelled out here.
//!
//! * **v4.public** â€” four pieces, no key material:
//!   `PAE([header, message, footer, implicit_assertion])`
//!   (`pasetors::version4::PublicToken::sign`, `pae::pae(&[Self::HEADER.as_bytes(), message, f, i])`)
//!
//! * **v3.public** â€” five pieces, and **the 49-byte compressed public key comes
//!   FIRST, before the header**:
//!   `PAE([public_key_49_bytes, header, message, footer, implicit_assertion])`
//!   (`pasetors::version3::PublicToken::sign` line 174 and `verify` line 215).
//!
//! The v3 key is inside the PAE by design: it binds a v3 signature to the
//! specific public key that must verify it. The practical consequence of doing
//! PASETO v3 with a KMS key is that **rotating the KMS key invalidates every
//! previously issued v3 token immediately**, with no overlap window. Plan
//! rotations accordingly, or issue v4 tokens when you need graceful turnover.
//!
//! # Message type and hashing
//!
//! Both KMS algorithms are used with `MessageType::Raw`, i.e. KMS is handed the
//! raw PAE bytes and hashes internally:
//!
//! * `ECC_NIST_EDWARDS25519` + `ED25519_SHA_512` â†’ pure RFC 8032 Ed25519
//!   signature (64 bytes). The `ED25519_PH_SHA_512` variant is deliberately
//!   *not* used: it expects a digest and hashes again, which double-hashes.
//! * `ECC_NIST_P384` + `ECDSA_SHA_384` â†’ DER-encoded `SEQUENCE{r, s}`, which is
//!   exactly what PASETO v3 wants since v3 signs `SHA-384(PAE(...))` with
//!   ECDSA P-384. This is also why `sha2` is *not* a dependency here.
//!
//! KMS ECDSA is non-deterministic (no RFC 6979). PASETO v3 explicitly permits
//! CSPRNG nonces, so that is compliant.

use crate::errors::RouterError;
use aws_sdk_kms::types::{KeySpec, SigningAlgorithmSpec};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use dotenv::dotenv;
use lambda_http::tracing;
use pasetors::claims::Claims;
use pasetors::keys::AsymmetricPublicKey;
use pasetors::version3::UncompressedPublicKey;
use pasetors::version3::V3;
use pasetors::version4::V4;
use std::env;
use thiserror::Error;

/// Environment variable naming the KMS key (key id, ARN, `alias/name`, â€¦).
pub(crate) const KMS_KEY_ID_ENV: &str = "KMS_KEY_ID";

/// Environment variable choosing between the KMS key source and the local
/// environment key source (`kms` / `env` / `auto`).
pub(crate) const KEY_SOURCE_ENV: &str = "PASETO_KEY_SOURCE";

/// Environment variable holding the base64url raw public key used by the
/// `Env` key source.
pub(crate) const PUB_KEY_ENV: &str = "PASETO_PUB_KEY";

/// Environment variable holding the base64url raw secret key used by the
/// `Env` key source (signer only).
pub(crate) const PRV_KEY_ENV: &str = "PASETO_PRV_KEY";

// `pasetors` keeps all of these private: `V3::PUBLIC_KEY` / `V3::PUBLIC_SIG` /
// `V3::SECRET_KEY` and friends live behind a `pub(crate) mod private`, so they
// cannot be referenced from here. The values are copied verbatim from
// `impl Version for V3` / `impl Version for V4` in `pasetors-0.8.1`.
/// `v3.public.` â€” PASETO v3 public-mode header, trailing dot included.
pub(crate) const V3_HEADER: &str = "v3.public.";
/// `v4.public.` â€” PASETO v4 public-mode header, trailing dot included.
pub(crate) const V4_HEADER: &str = "v4.public.";

/// PASETO v3 secret (private) key length in bytes.
pub(crate) const V3_SECRET_KEY_LEN: usize = 48;
/// PASETO v3 compressed public key length in bytes (`0x02|0x03 || x`).
pub(crate) const V3_PUBLIC_KEY_LEN: usize = 49;
/// PASETO v3 signature length in bytes (`r(48) || s(48)`).
pub(crate) const V3_PUBLIC_SIG_LEN: usize = 96;
/// PASETO v4 secret key length in bytes (Ed25519 seed || public key).
pub(crate) const V4_SECRET_KEY_LEN: usize = 64;
/// PASETO v4 raw Ed25519 public key length in bytes.
pub(crate) const V4_PUBLIC_KEY_LEN: usize = 32;
/// PASETO v4 Ed25519 signature length in bytes.
pub(crate) const V4_PUBLIC_SIG_LEN: usize = 64;

/// RFC 8410 SubjectPublicKeyInfo prefix for an Ed25519 key:
/// `SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING (0 unused) }` =
/// `302a300506032b6570032100`. A full Ed25519 SPKI is this 12-byte header
/// followed by the 32 raw public-key bytes, 44 bytes in total.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Total length of an Ed25519 SPKI: 12-byte prefix + 32-byte raw key.
const ED25519_SPKI_LEN: usize = ED25519_SPKI_PREFIX.len() + V4_PUBLIC_KEY_LEN;

/// Length of an uncompressed SEC1 P-384 point: `0x04 || x(48) || y(48)`.
const P384_SEC1_LEN: usize = 1 + 48 + 48;

/// Marker byte of an uncompressed SEC1 elliptic-curve point (SEC 1 Â§2.3.3).
const SEC1_UNCOMPRESSED_TAG: u8 = 0x04;

/// Length of a P-384 SPKI: `SEQUENCE` header + `AlgorithmIdentifier` (19
/// bytes) + `BIT STRING` header (3 bytes) + 97-byte uncompressed point.
const P384_SPKI_LEN: usize = 120;

/// Errors raised while configuring, framing or verifying a KMS-backed PASETO.
#[derive(Debug, Error)]
pub(crate) enum KmsError {
    /// No KMS key id was supplied and `KMS_KEY_ID` is absent or blank.
    #[error("no KMS key id configured (set {KMS_KEY_ID_ENV})")]
    MissingKeyId,

    /// `PASETO_KEY_SOURCE` was set to something other than kms/env/auto.
    #[error("invalid {KEY_SOURCE_ENV} value: {0} (expected `kms`, `env` or `auto`)")]
    InvalidKeySource(String),

    /// The KMS key exists but its `KeySpec` is not a PASETO key we can drive.
    #[error("unsupported KMS KeySpec: {0}")]
    UnsupportedKeySpec(String),

    /// `GetPublicKey` succeeded but returned no `PublicKey` blob.
    #[error("KMS GetPublicKey returned no public key bytes")]
    MissingPublicKey,

    /// The `GetPublicKey` SPKI blob has the wrong length.
    #[error("unexpected SPKI length: got {got}, want {want}")]
    SpkiLength { got: usize, want: usize },

    /// The `GetPublicKey` SPKI blob does not start with the expected DER prefix.
    #[error("unexpected SPKI prefix for {kind}")]
    SpkiPrefix { kind: &'static str },

    /// A KMS ECDSA DER signature could not be converted to the fixed-width
    /// `r || s` form PASETO v3 requires.
    #[error("ECDSA DER to raw conversion failed: {0}")]
    DerToRaw(String),

    /// A PAE length did not fit in a `u64`.
    #[error("PAE length overflow: {0} does not fit in u64")]
    PaeOverflow(String),

    /// A claims document could not be serialised to JSON.
    #[error("claims serialization failed: {0}")]
    ClaimsSerialization(pasetors::errors::Error),

    /// A `Sign` call failed.
    #[error("KMS Sign failed: {0}")]
    Sign(#[source] Box<KmsSignError>),

    /// A `GetPublicKey` call failed.
    #[error("KMS GetPublicKey failed: {0}")]
    GetPublicKey(#[source] Box<KmsGetPublicKeyError>),

    /// pasetors rejected key material or a token.
    #[error("pasetors error: {0}")]
    Pasetors(#[from] pasetors::errors::Error),

    /// base64url decoding failed.
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
}

/// The concrete `SdkError` returned by `KMS Sign`, named through the
/// `aws_sdk_kms::error` re-export so `aws-smithy-runtime-api` does not have to
/// be a direct dependency. Boxed inside [`KmsError`] because `SdkError` is far
/// bigger than the rest of the enum, and every `Result<_, KmsError>` would
/// otherwise carry hundreds of bytes of dead weight.
type KmsSignError = aws_sdk_kms::error::SdkError<aws_sdk_kms::operation::sign::SignError>;

/// The concrete `SdkError` returned by `KMS GetPublicKey`, named the same way.
type KmsGetPublicKeyError =
    aws_sdk_kms::error::SdkError<aws_sdk_kms::operation::get_public_key::GetPublicKeyError>;

impl From<KmsError> for RouterError {
    /// Mapping policy, deliberately explicit because `RouterError` variants
    /// carry HTTP status codes:
    ///
    /// * **401 `Unauthenticated`** â€” the caller's token or claims could not be
    ///   validated: bad claims JSON, bad signature bytes, bad DER encoding,
    ///   malformed base64, or malformed pasetors key material. These mean "your
    ///   token is not acceptable", not "the server is broken".
    /// * **500 `KeyPairError`** â€” the deployment itself is misconfigured or AWS
    ///   is unreachable: no key id, unusable `KeySpec`, a missing/incompatible
    ///   public key in the KMS response, a bad PAE length, or a `Sign` /
    ///   `GetPublicKey` transport/service failure. These are operator problems
    ///   and must not be reported to the client as an auth failure.
    fn from(err: KmsError) -> Self {
        match err {
            KmsError::ClaimsSerialization(e) => RouterError::Unauthenticated(e.to_string()),
            KmsError::DerToRaw(e) => RouterError::Unauthenticated(e),
            KmsError::Pasetors(e) => RouterError::Unauthenticated(e.to_string()),
            KmsError::Base64(e) => RouterError::Unauthenticated(e.to_string()),
            other => RouterError::KeyPairError(other.to_string()),
        }
    }
}

/// The PASETO version a KMS key drives, derived from its key material.
///
/// Widened to `pub` because `Signer::version` / `Verifier::version` expose it in
/// this crate's public API; the rest of this module stays `pub(crate)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasetoVersion {
    /// PASETO v3.public â€” ECDSA over P-384 with SHA-384.
    V3,
    /// PASETO v4.public â€” Ed25519.
    V4,
}

impl PasetoVersion {
    /// Pick the version from a KMS `KeySpec`.
    ///
    /// Matching is done on `KeySpec::as_str()` rather than on the enum
    /// variants because `KeySpec` is `#[non_exhaustive]`: AWS can add key specs
    /// in any SDK release, and matching on variants would make this function a
    /// non-exhaustive `match` hostage to their release cadence. Matching the
    /// wire string means an unknown spec falls into the same
    /// [`KmsError::UnsupportedKeySpec`] arm instead of a compile error.
    pub(crate) fn from_key_spec(spec: &KeySpec) -> Result<Self, KmsError> {
        match spec.as_str() {
            "ECC_NIST_EDWARDS25519" => Ok(Self::V4),
            "ECC_NIST_P384" => Ok(Self::V3),
            other => Err(KmsError::UnsupportedKeySpec(other.to_string())),
        }
    }

    /// Pick the version from a raw public key length.
    ///
    /// Used by the `Env` key source, where there is no `KeySpec` to consult:
    /// 32 raw bytes is Ed25519 (v4) and 49 compressed bytes is P-384 (v3).
    /// Note this inspects key *material*, never a token.
    pub(crate) fn from_key_len(len: usize) -> Option<Self> {
        match len {
            V4_PUBLIC_KEY_LEN => Some(Self::V4),
            V3_PUBLIC_KEY_LEN => Some(Self::V3),
            _ => None,
        }
    }

    /// Pick the parser to run for a token, purely from its header.
    ///
    /// # This MUST NOT be used to choose a key.
    ///
    /// The key always comes from configuration (`KMS_KEY_ID` or the `Env`
    /// source) and never from the token. This function only answers "which
    /// parser do I hand this token to", so that a `v3` token is parsed as v3
    /// instead of being reported as an unrecognised token. Selecting a key from
    /// a token would let a caller pick the key that verifies their own token.
    pub(crate) fn from_token(token: &str) -> Option<Self> {
        if token.starts_with(V3_HEADER) {
            Some(Self::V3)
        } else if token.starts_with(V4_HEADER) {
            Some(Self::V4)
        } else {
            None
        }
    }

    /// The `vN.public.` header, trailing dot included.
    pub fn header(&self) -> &'static str {
        match self {
            Self::V3 => V3_HEADER,
            Self::V4 => V4_HEADER,
        }
    }

    /// The KMS `SigningAlgorithmSpec` that goes with this version.
    pub(crate) fn signing_algorithm(&self) -> SigningAlgorithmSpec {
        match self {
            Self::V3 => SigningAlgorithmSpec::EcdsaSha384,
            Self::V4 => SigningAlgorithmSpec::Ed25519Sha512,
        }
    }
}

/// Where the signing key material comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeySource {
    /// An asymmetric KMS key, referenced by `KMS_KEY_ID`.
    Kms,
    /// Raw key bytes supplied through `PASETO_PUB_KEY` / `PASETO_PRV_KEY`.
    Env,
}

impl KeySource {
    /// Resolve the configured source.
    ///
    /// `None` falls back to [`KeySource::env_default`]. `"auto"` is exactly
    /// equivalent to `None`. Comparison is case-insensitive and trims
    /// surrounding whitespace so a value pasted out of a console still works.
    ///
    /// An unrecognised value is an error, never a silent fallback: quietly
    /// signing with local env keys because of a typo in `PASETO_KEY_SOURCE`
    /// would issue tokens nobody can verify with the KMS key.
    pub(crate) fn resolve(explicit: Option<&str>) -> Result<Self, KmsError> {
        let source = match explicit.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            None | Some("auto") => Self::env_default(),
            Some("kms") => Self::Kms,
            Some("env") => Self::Env,
            Some(other) => return Err(KmsError::InvalidKeySource(other.to_string())),
        };
        tracing::info!("PASETO key source: {}", source.label());
        Ok(source)
    }

    /// A short human-readable name for logs. Key material is never logged.
    fn label(&self) -> &'static str {
        match self {
            Self::Kms => "kms",
            Self::Env => "env",
        }
    }

    /// The deployment-appropriate default.
    ///
    /// `LAMBDA_TASK_ROOT` is set by the Lambda runtime and absent on a developer
    /// machine, which makes it a reliable "am I deployed?" probe â€” the same one
    /// the rest of the workspace uses to decide whether to load `.env`. On
    /// Lambda the default is `Kms` because production should sign with a key
    /// that never exists on disk; locally it is `Env` so a developer needs no
    /// AWS credentials and no `.env`-free fallback path can reach AWS.
    pub(crate) fn env_default() -> Self {
        if env::var("LAMBDA_TASK_ROOT").is_err() {
            Self::Env
        } else {
            Self::Kms
        }
    }
}

/// Load `.env` when running locally. No-op on Lambda.
///
/// The established house pattern (`iciaws_s3/src/lib.rs:40-44`): the Lambda
/// runtime sets `LAMBDA_TASK_ROOT`, and there is no `.env` to read there.
pub(crate) fn load_dotenv_if_local() {
    if env::var("LAMBDA_TASK_ROOT").is_err() {
        dotenv().ok();
    }
}

/// Build a KMS client. Performs no network I/O itself.
pub(crate) async fn kms_client() -> aws_sdk_kms::Client {
    load_dotenv_if_local();
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    aws_sdk_kms::Client::new(&config)
}

/// Resolve the KMS key id from an explicit value or `KMS_KEY_ID`.
///
/// Precedence: a non-blank explicit argument, then a non-blank `KMS_KEY_ID`,
/// then [`KmsError::MissingKeyId`]. A blank or whitespace-only value at either
/// level is treated as absent rather than sent to AWS as an empty key id.
///
/// The value is deliberately **not** parsed or normalised. KMS accepts key ARNs,
/// `alias/name`, alias ARNs and bare key UUIDs, validates them itself, and
/// returns a far better error message than a local parser could. Trimming is
/// the only transformation applied, because a trailing newline from a
/// `LambdaFunction::from_env().key_id()` call is the one realistic source of
/// whitespace noise.
pub(crate) fn resolve_key_id(key_id: Option<String>) -> Result<String, KmsError> {
    if let Some(explicit) = key_id {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    if let Ok(from_env) = env::var(KMS_KEY_ID_ENV) {
        let trimmed = from_env.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    Err(KmsError::MissingKeyId)
}

/// Encode `n` as 8 little-endian bytes with the MSB cleared.
///
/// The MSB clear is not a rounding detail: PAE lengths are unsigned 64-bit and
/// the high bit is reserved so the encoding stays interoperable with the
/// reference implementations. `pasetors::pae::le64` is private, so this is a
/// byte-for-byte reimplementation.
pub(crate) fn le64(n: u64) -> [u8; 8] {
    let mut out = [0u8; 8];
    let mut n_tmp = n;

    out[0] = (n_tmp & 255) as u8;
    n_tmp >>= 8;
    out[1] = (n_tmp & 255) as u8;
    n_tmp >>= 8;
    out[2] = (n_tmp & 255) as u8;
    n_tmp >>= 8;
    out[3] = (n_tmp & 255) as u8;
    n_tmp >>= 8;
    out[4] = (n_tmp & 255) as u8;
    n_tmp >>= 8;
    out[5] = (n_tmp & 255) as u8;
    n_tmp >>= 8;
    out[6] = (n_tmp & 255) as u8;
    n_tmp >>= 8;
    n_tmp &= 127; // clear the MSB for interoperability
    out[7] = (n_tmp & 255) as u8;

    out
}

/// PASETO pre-authentication encoding.
///
/// `le64(pieces.len())` followed by, for each piece, `le64(piece.len())` and
/// the piece itself. Byte-for-byte reimplementation of
/// `pasetors::pae::pae`, which is private.
///
/// See the module docs for the two orderings (v3 prefixes the public key).
pub(crate) fn pae(pieces: &[&[u8]]) -> Result<Vec<u8>, KmsError> {
    let count =
        u64::try_from(pieces.len()).map_err(|_| KmsError::PaeOverflow(pieces.len().to_string()))?;
    let mut out: Vec<u8> = Vec::with_capacity(64);
    out.extend_from_slice(&le64(count));
    for elem in pieces.iter() {
        let len =
            u64::try_from(elem.len()).map_err(|_| KmsError::PaeOverflow(elem.len().to_string()))?;
        out.extend_from_slice(&le64(len));
        out.extend_from_slice(elem);
    }
    Ok(out)
}

/// base64url, no padding â€” the only base64 variant PASETO uses.
///
/// PASETO's encoding is `ct-codecs::Base64UrlSafeNoPadding`. `BASE64_STANDARD`
/// and `URL_SAFE` (which pads) must never be used on a token body or on the
/// PAE: a single stray `+`, `/` or `=` makes every signature check fail.
pub(crate) fn b64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode a base64url unpadded PASETO segment.
pub(crate) fn b64url_decode(s: &str) -> Result<Vec<u8>, KmsError> {
    Ok(URL_SAFE_NO_PAD.decode(s)?)
}

/// Build a PASETO v4 public key from the Ed25519 SPKI blob KMS returns.
///
/// `GetPublicKey` returns DER SubjectPublicKeyInfo; PASETO wants the 32 raw
/// bytes. The SPKI is fixed-shape for Ed25519 (RFC 8410 Â§9), so the length and
/// the 12-byte DER prefix are both validated here before slicing. Validating
/// the prefix is what turns "some DER blob of the right size" into "an Ed25519
/// key": a P-384 SPKI has a different `AlgorithmIdentifier` and would produce a
/// plausible-looking but wrong 32-byte key if it were only length-checked.
///
/// The construction itself is the **inherent**
/// `AsymmetricPublicKey::<V4>::from(&[u8])`, not a `TryFrom`: pasetors provides
/// no `TryFrom<&[u8]>` impl for its key types, and pasetors' own check is only
/// "is it 32 bytes".
pub(crate) fn ed25519_public_key_from_spki(
    spki: &[u8],
) -> Result<AsymmetricPublicKey<V4>, KmsError> {
    if spki.len() != ED25519_SPKI_LEN {
        return Err(KmsError::SpkiLength {
            got: spki.len(),
            want: ED25519_SPKI_LEN,
        });
    }
    if spki[..ED25519_SPKI_PREFIX.len()] != ED25519_SPKI_PREFIX {
        return Err(KmsError::SpkiPrefix { kind: "Ed25519" });
    }
    Ok(AsymmetricPublicKey::<V4>::from(
        &spki[ED25519_SPKI_PREFIX.len()..],
    )?)
}

/// Build a PASETO v3 public key from the P-384 SPKI blob KMS returns.
///
/// The SPKI is `SEQUENCE(23) { SEQUENCE(19){OID, OID}, BIT STRING(119){ 0x00,
/// 0x04 || x(48) || y(48) } }`, i.e. 120 bytes whose last 97 are an
/// uncompressed SEC1 point. PASETO v3 wants the 49-byte *compressed* form, so
/// the 97 bytes go through [`UncompressedPublicKey`], which also re-validates
/// that the point actually lies on the curve.
///
/// The length and the `0x04` tag are checked here and **not** delegated, because
/// `impl TryFrom<&[u8]> for UncompressedPublicKey`
/// (`pasetors-0.8.1/src/version3.rs:112`) guards with
/// `if value.len() != 97 && value[0] != 4` â€” a logical `&&` where the intent was
/// `||`. That bug lets a 97-byte compressed point, or a wrong-length uncompressed
/// one whose first byte happens to be `0x04`, past the guard. The downstream
/// `TryFrom<&UncompressedPublicKey>` impl (line 138) is correct and is relied on
/// for the on-curve check.
pub(crate) fn p384_public_key_from_spki(spki: &[u8]) -> Result<AsymmetricPublicKey<V3>, KmsError> {
    if spki.len() != P384_SPKI_LEN {
        return Err(KmsError::SpkiLength {
            got: spki.len(),
            want: P384_SPKI_LEN,
        });
    }
    let sec1 = &spki[spki.len() - P384_SEC1_LEN..];
    if sec1.len() != P384_SEC1_LEN || sec1[0] != SEC1_UNCOMPRESSED_TAG {
        return Err(KmsError::SpkiPrefix { kind: "P-384" });
    }
    let uncompressed = UncompressedPublicKey::try_from(sec1)?;
    Ok(AsymmetricPublicKey::<V3>::try_from(&uncompressed)?)
}

/// Convert a KMS DER-encoded ECDSA signature into the fixed 96 bytes PASETO v3
/// requires (`r(48, big-endian) || s(48, big-endian)`).
///
/// AWS KMS returns ECDSA signatures as an ASN.1 DER `SEQUENCE { INTEGER r,
/// INTEGER s }`; PASETO v3 tokens carry them fixed-width. Note the leading zero
/// DER strips from a short `r`/`s` is restored here by `p384`'s fixed-width
/// encoding, which is what makes the round trip lossless.
///
/// `p384::ecdsa::Signature::from_der` is the DER entry point;
/// `Signature::try_from(&[u8])` is **not** â€” it demands exactly 96 fixed-width
/// bytes and rejects DER input.
pub(crate) fn ecdsa_der_to_raw96(der: &[u8]) -> Result<[u8; V3_PUBLIC_SIG_LEN], KmsError> {
    let sig =
        p384::ecdsa::Signature::from_der(der).map_err(|e| KmsError::DerToRaw(e.to_string()))?;
    let bytes = sig.to_bytes();
    if bytes.len() != V3_PUBLIC_SIG_LEN {
        return Err(KmsError::DerToRaw(format!(
            "expected {V3_PUBLIC_SIG_LEN} raw signature bytes, got {}",
            bytes.len()
        )));
    }
    let mut raw = [0u8; V3_PUBLIC_SIG_LEN];
    raw.copy_from_slice(bytes.as_ref());
    Ok(raw)
}

/// Serialise claims into the PASETO payload bytes.
///
/// `Claims::to_string` is an inherent method returning `Result<String, Error>`
/// that shadows `ToString::to_string`; the inherent one is what produces the
/// canonical JSON PASETO signs, so it is called explicitly rather than relying
/// on the trait.
pub(crate) fn claims_to_payload(claims: &Claims) -> Result<Vec<u8>, KmsError> {
    let json = Claims::to_string(claims).map_err(KmsError::ClaimsSerialization)?;
    Ok(json.into_bytes())
}

/// Assemble the final token string from a signed `message || signature` and an
/// optional footer.
///
/// Mirrors `pasetors::version3::PublicToken::sign` lines 182-191: the body is
/// `message || signature` â€” not the PAE â€” base64url encoded with no padding, and
/// a non-empty footer is appended as a second `.`-separated base64url segment.
pub(crate) fn assemble_token(
    header: &str,
    message: &[u8],
    signature: &[u8],
    footer: Option<&[u8]>,
) -> String {
    let body = b64url_encode(&[message, signature].concat());
    match footer {
        Some(f) if !f.is_empty() => format!("{header}{body}.{}", b64url_encode(f)),
        _ => format!("{header}{body}"),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use p384::ecdsa::Signature as P384Signature;
    use p384::ecdsa::SigningKey;
    use p384::ecdsa::signature::Signer;
    use pasetors::keys::AsymmetricKeyPair;
    use pasetors::keys::Generate;
    use std::ffi::OsString;
    use std::sync::{Mutex, MutexGuard, OnceLock};
    use std::time::Duration;

    /// Serialises the tests that mutate the process environment, which is global
    /// state shared by every test thread in this binary.
    fn env_lock() -> MutexGuard<'static, ()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// RAII snapshot of the KMS/key-source environment variables, restored on
    /// drop so a failing assertion cannot leak mutated state into other tests.
    struct KmsEnvGuard {
        saved: Vec<(&'static str, Option<OsString>)>,
    }

    impl KmsEnvGuard {
        /// Capture the current values of the environment variables this module
        /// reads.
        ///
        /// Also sets `LAMBDA_TASK_ROOT`, which makes `load_dotenv_if_local()` and
        /// `KeySource::env_default()` behave deterministically and makes these
        /// tests independent of any `.env` file on the developer's machine.
        fn capture() -> Self {
            let names = [
                KMS_KEY_ID_ENV,
                KEY_SOURCE_ENV,
                PUB_KEY_ENV,
                PRV_KEY_ENV,
                "LAMBDA_TASK_ROOT",
            ];
            let saved = names
                .iter()
                .map(|n| (*n, env::var_os(n)))
                .collect::<Vec<(&'static str, Option<OsString>)>>();
            // SAFETY: the caller holds `env_lock()`, so no other test thread is
            // reading or writing the environment while this guard is alive.
            unsafe { env::set_var("LAMBDA_TASK_ROOT", "test") };
            Self { saved }
        }

        /// Set or clear an environment variable for the duration of the test.
        fn set(name: &str, value: Option<&str>) {
            // SAFETY: see `capture()`; `env_lock()` is held by the caller.
            unsafe {
                match value {
                    Some(v) => env::set_var(name, v),
                    None => env::remove_var(name),
                };
            }
        }
    }

    impl Drop for KmsEnvGuard {
        fn drop(&mut self) {
            for (name, value) in self.saved.drain(..) {
                // SAFETY: `env_lock()` is still held for the whole lifetime of the
                // guard, so no other test thread touches the environment here.
                unsafe {
                    match value {
                        Some(v) => env::set_var(name, v),
                        None => env::remove_var(name),
                    };
                }
            }
        }
    }

    // ---- le64 ---------------------------------------------------------

    #[test]
    fn test_le64_known_vectors() {
        assert_eq!(le64(0), [0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(le64(1), [1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(le64(255), [255, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(le64(256), [0, 1, 0, 0, 0, 0, 0, 0]);
    }

    /// The most-significant bit of the *top* byte is cleared, which is the one
    /// place PAE's `le64` differs from a naive `u64::to_le_bytes()`.
    #[test]
    fn test_le64_clears_msb() {
        assert_eq!(le64(u64::MAX), [255, 255, 255, 255, 255, 255, 255, 0x7f]);
        // Bit 63 is the one that gets masked off, and nothing else is.
        assert_eq!(le64(1u64 << 63), [0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(le64(1u64 << 63 | 0x5a), [0x5a, 0, 0, 0, 0, 0, 0, 0]);
        // Bit 56 still lands in the top byte untouched, so only bit 63 goes.
        assert_eq!(le64(1u64 << 56), [0, 0, 0, 0, 0, 0, 0, 1]);
    }

    // ---- pae ----------------------------------------------------------

    #[test]
    fn test_pae_empty_and_empty_piece() {
        assert_eq!(pae(&[]).unwrap(), le64(0).to_vec());

        let one = pae(&[b""]).unwrap();
        let mut expected = le64(1).to_vec();
        expected.extend_from_slice(&le64(0));
        assert_eq!(one, expected);
    }

    /// Checked by hand against the reference vectors in the PASETO test suite
    /// (`pasetors-0.8.1/src/pae.rs` `mod unit_tests`):
    /// `PAE(["Paragon", "Initiative"])`.
    #[test]
    fn test_pae_two_pieces_against_spec_layout() {
        let encoded = pae(&[b"Paragon", b"Initiative"]).unwrap();
        let mut expected = le64(2).to_vec();
        expected.extend_from_slice(&le64(7));
        expected.extend_from_slice(b"Paragon");
        expected.extend_from_slice(&le64(10));
        expected.extend_from_slice(b"Initiative");
        assert_eq!(encoded, expected);
        assert_eq!(encoded.len(), 8 + (8 + 7) + (8 + 10));
    }

    /// Lengths are prepended to every piece, never to the concatenation, so a
    /// boundary shift cannot produce the same PAE.
    #[test]
    fn test_pae_is_unambiguous() {
        let split = pae(&[b"ab", b"c"]).unwrap();
        let joined = pae(&[b"a", b"bc"]).unwrap();
        assert_ne!(split, joined);
    }

    // ---- base64url ----------------------------------------------------

    #[test]
    fn test_b64url_roundtrip_and_alphabet() {
        let payload: Vec<u8> = (0u8..=255).collect();
        let encoded = b64url_encode(&payload);
        assert!(!encoded.contains('='), "padding is forbidden in PASETO");
        assert!(!encoded.contains('+'), "standard base64 alphabet leaked in");
        assert!(!encoded.contains('/'), "standard base64 alphabet leaked in");
        assert_eq!(b64url_decode(&encoded).unwrap(), payload);
    }

    /// Bytes 0xFB 0xFF 0xBF encode to `+` and `/` under standard base64, so
    /// this pins the URL-safe alphabet rather than only the absence of `=`.
    #[test]
    fn test_b64url_uses_url_safe_alphabet() {
        let encoded = b64url_encode(&[0xfb, 0xff, 0xbf, 0x00]);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert_eq!(
            b64url_decode(&encoded).unwrap(),
            vec![0xfb, 0xff, 0xbf, 0x00]
        );
    }

    #[test]
    fn test_b64url_decode_rejects_standard_alphabet() {
        assert!(b64url_decode("++//").is_err());
        assert!(b64url_decode("not base64!!").is_err());
    }

    // ---- resolve_key_id -----------------------------------------------

    #[test]
    fn test_resolve_key_id_precedence() {
        let _guard = env_lock();
        let _env = KmsEnvGuard::capture();

        KmsEnvGuard::set(KMS_KEY_ID_ENV, Some("env-key"));
        assert_eq!(
            resolve_key_id(Some("explicit-key".to_string())).unwrap(),
            "explicit-key"
        );
        // explicit wins and is trimmed
        assert_eq!(
            resolve_key_id(Some("  explicit-key  ".to_string())).unwrap(),
            "explicit-key"
        );
        // blank/whitespace-only explicit falls through to the environment
        assert_eq!(resolve_key_id(Some("   ".to_string())).unwrap(), "env-key");
        assert_eq!(resolve_key_id(Some(String::new())).unwrap(), "env-key");
        // and only then does the environment win
        assert_eq!(resolve_key_id(None).unwrap(), "env-key");
    }

    #[test]
    fn test_resolve_key_id_missing() {
        let _guard = env_lock();
        let _env = KmsEnvGuard::capture();

        KmsEnvGuard::set(KMS_KEY_ID_ENV, None);
        assert!(matches!(resolve_key_id(None), Err(KmsError::MissingKeyId)));

        // A blank environment value is as good as absent
        KmsEnvGuard::set(KMS_KEY_ID_ENV, Some("  "));
        assert!(matches!(resolve_key_id(None), Err(KmsError::MissingKeyId)));
    }

    /// Every KMS-acceptable key reference form must pass through untouched:
    /// `resolve_key_id` validates nothing but emptiness.
    #[test]
    fn test_resolve_key_id_passes_key_forms_through() {
        let _guard = env_lock();
        let _env = KmsEnvGuard::capture();

        KmsEnvGuard::set(KMS_KEY_ID_ENV, None);
        let forms = [
            "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab",
            "alias/iciaws-paseto",
            "arn:aws:kms:us-east-1:123456789012:alias/iciaws-paseto",
            "1234abcd-12ab-34cd-56ef-1234567890ab",
        ];
        for form in forms {
            assert_eq!(resolve_key_id(Some(form.to_string())).unwrap(), form);
        }
    }

    // ---- KeySource ----------------------------------------------------

    #[test]
    fn test_key_source_resolve() {
        let _guard = env_lock();
        let _env = KmsEnvGuard::capture();

        // LAMBDA_TASK_ROOT is set by the guard, so env_default() is Kms.
        assert_eq!(KeySource::env_default(), KeySource::Kms);
        assert_eq!(KeySource::resolve(None).unwrap(), KeySource::Kms);
        assert_eq!(KeySource::resolve(Some("auto")).unwrap(), KeySource::Kms);
        assert_eq!(KeySource::resolve(Some("KMS")).unwrap(), KeySource::Kms);
        assert_eq!(KeySource::resolve(Some("kms")).unwrap(), KeySource::Kms);
        assert_eq!(KeySource::resolve(Some("  EnV ")).unwrap(), KeySource::Env);
        assert!(matches!(
            KeySource::resolve(Some("bogus")),
            Err(KmsError::InvalidKeySource(_))
        ));
        // Never a silent cross-source fallback.
        assert!(KeySource::resolve(Some("")).is_err());
    }

    #[test]
    fn test_key_source_env_default_off_lambda() {
        let _guard = env_lock();
        let _env = KmsEnvGuard::capture();

        // SAFETY: `env_lock()` is held, so no other thread touches the environment.
        unsafe { env::remove_var("LAMBDA_TASK_ROOT") };
        assert_eq!(KeySource::env_default(), KeySource::Env);
        assert_eq!(KeySource::resolve(None).unwrap(), KeySource::Env);
    }

    #[test]
    fn test_env_constant_names() {
        assert_eq!(KMS_KEY_ID_ENV, "KMS_KEY_ID");
        assert_eq!(KEY_SOURCE_ENV, "PASETO_KEY_SOURCE");
        assert_eq!(PUB_KEY_ENV, "PASETO_PUB_KEY");
        assert_eq!(PRV_KEY_ENV, "PASETO_PRV_KEY");
    }

    #[test]
    fn test_paseto_constants() {
        assert_eq!(V3_HEADER, "v3.public.");
        assert_eq!(V4_HEADER, "v4.public.");
        assert_eq!(V3_SECRET_KEY_LEN, 48);
        assert_eq!(V3_PUBLIC_KEY_LEN, 49);
        assert_eq!(V3_PUBLIC_SIG_LEN, 96);
        assert_eq!(V4_SECRET_KEY_LEN, 64);
        assert_eq!(V4_PUBLIC_KEY_LEN, 32);
        assert_eq!(V4_PUBLIC_SIG_LEN, 64);
    }

    // ---- PasetoVersion ------------------------------------------------

    #[test]
    fn test_paseto_version_from_key_spec() {
        assert_eq!(
            PasetoVersion::from_key_spec(&KeySpec::EccNistEdwards25519).unwrap(),
            PasetoVersion::V4
        );
        assert_eq!(
            PasetoVersion::from_key_spec(&KeySpec::EccNistP384).unwrap(),
            PasetoVersion::V3
        );
        // RSA is a real KeySpec but not a PASETO key we can drive.
        assert!(matches!(
            PasetoVersion::from_key_spec(&KeySpec::Rsa2048),
            Err(KmsError::UnsupportedKeySpec(s)) if s == "RSA_2048"
        ));
    }

    #[test]
    fn test_paseto_version_from_key_len() {
        assert_eq!(PasetoVersion::from_key_len(32), Some(PasetoVersion::V4));
        assert_eq!(PasetoVersion::from_key_len(49), Some(PasetoVersion::V3));
        assert_eq!(PasetoVersion::from_key_len(7), None);
        assert_eq!(PasetoVersion::from_key_len(48), None);
    }

    #[test]
    fn test_paseto_version_from_token() {
        assert_eq!(
            PasetoVersion::from_token("v4.public.whatever"),
            Some(PasetoVersion::V4)
        );
        assert_eq!(
            PasetoVersion::from_token("v3.public.whatever"),
            Some(PasetoVersion::V3)
        );
        assert_eq!(PasetoVersion::from_token("v2.public.x"), None);
        assert_eq!(PasetoVersion::from_token("garbage"), None);
        assert_eq!(PasetoVersion::from_token(""), None);
    }

    #[test]
    fn test_paseto_version_header_and_algorithm() {
        assert_eq!(PasetoVersion::V3.header(), "v3.public.");
        assert_eq!(PasetoVersion::V4.header(), "v4.public.");
        assert_eq!(
            PasetoVersion::V3.signing_algorithm(),
            SigningAlgorithmSpec::EcdsaSha384
        );
        assert_eq!(
            PasetoVersion::V4.signing_algorithm(),
            SigningAlgorithmSpec::Ed25519Sha512
        );
    }

    // ---- SPKI parsers --------------------------------------------------

    /// A synthetic but structurally valid Ed25519 SPKI: the RFC 8410 prefix
    /// followed by 32 known bytes. No KMS call and no ASN.1 encoder needed.
    fn synthetic_ed25519_spki(raw: &[u8; V4_PUBLIC_KEY_LEN]) -> Vec<u8> {
        let mut spki = ED25519_SPKI_PREFIX.to_vec();
        spki.extend_from_slice(raw);
        spki
    }

    #[test]
    fn test_ed25519_public_key_from_spki_roundtrip() {
        let raw: [u8; V4_PUBLIC_KEY_LEN] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];
        let spki = synthetic_ed25519_spki(&raw);
        assert_eq!(spki.len(), 44);

        let key = ed25519_public_key_from_spki(&spki).unwrap();
        assert_eq!(key.as_bytes(), raw.as_slice());
    }

    #[test]
    fn test_ed25519_public_key_from_spki_rejects_bad_input() {
        let raw = [7u8; V4_PUBLIC_KEY_LEN];
        let good = synthetic_ed25519_spki(&raw);

        // wrong length
        assert!(matches!(
            ed25519_public_key_from_spki(&good[..43]),
            Err(KmsError::SpkiLength { got: 43, want: 44 })
        ));
        assert!(ed25519_public_key_from_spki(&[]).is_err());

        // right length, corrupted DER prefix
        let mut corrupt = good.clone();
        corrupt[8] = 0x71; // the OID's last byte
        assert!(matches!(
            ed25519_public_key_from_spki(&corrupt),
            Err(KmsError::SpkiPrefix { kind: "Ed25519" })
        ));

        // right length, corrupted tag
        let mut corrupt = good.clone();
        corrupt[0] = 0x31;
        assert!(ed25519_public_key_from_spki(&corrupt).is_err());
    }

    /// A real P-384 key pair, generated offline by pasetors' CSPRNG path.
    ///
    /// Only the error paths of `p384_public_key_from_spki` are exercised: the
    /// happy path needs a 120-byte P-384 SPKI, which would mean pulling an
    /// ASN.1/SPKI encoder (`p384`'s `pkcs8` feature) into the dependency graph
    /// purely to build test input. The compressed 49-byte form is checked
    /// against the length and tag invariants that the function enforces.
    #[test]
    fn test_p384_public_key_shape_and_error_paths() {
        let pair = AsymmetricKeyPair::<V3>::generate().unwrap();
        let compressed = pair.public.as_bytes();
        assert_eq!(compressed.len(), V3_PUBLIC_KEY_LEN);
        assert!(
            compressed[0] == 0x02 || compressed[0] == 0x03,
            "PASETO v3 uses a compressed SEC1 point"
        );

        // wrong length (including a valid-looking 49-byte compressed key)
        assert!(matches!(
            p384_public_key_from_spki(compressed),
            Err(KmsError::SpkiLength { got: 49, want: 120 })
        ));
        assert!(p384_public_key_from_spki(&[]).is_err());

        // right length, but the trailing 97 bytes are not an uncompressed point
        let mut bad = vec![0u8; P384_SPKI_LEN];
        bad[P384_SPKI_LEN - 1] = 0x04; // tag is wrong, and so are x and y
        assert!(matches!(
            p384_public_key_from_spki(&bad),
            Err(KmsError::SpkiPrefix { kind: "P-384" })
        ));

        // right length and right tag, but not a point on the curve: this is the
        // case the buggy `&&` guard in pasetors would let through, which is why
        // the guard is duplicated here.
        let mut not_on_curve = vec![0u8; P384_SPKI_LEN];
        not_on_curve[P384_SPKI_LEN - P384_SEC1_LEN] = SEC1_UNCOMPRESSED_TAG;
        assert!(p384_public_key_from_spki(&not_on_curve).is_err());
    }

    // ---- ECDSA DER -> raw ---------------------------------------------

    /// A fixed 48-byte P-384 scalar; `SigningKey::try_from(&[u8])` takes a raw
    /// scalar so no key generation feature is required.
    fn test_signing_key() -> SigningKey {
        let mut scalar = [0u8; 48];
        scalar[47] = 0x2a;
        scalar[0] = 0x01;
        SigningKey::try_from(&scalar[..]).expect("valid P-384 scalar")
    }

    #[test]
    fn test_ecdsa_der_to_raw96_roundtrip() {
        let key = test_signing_key();
        // `SigningKey` implements `Signer` for several signature types, so the
        // call is annotated to pick the plain ECDSA one.
        let signed: P384Signature = Signer::sign(&key, b"pre-auth bytes");
        let der = signed.to_der();
        let raw = ecdsa_der_to_raw96(der.as_ref()).unwrap();

        assert_eq!(raw.len(), V3_PUBLIC_SIG_LEN);
        // The fixed-width form must parse back as a P-384 signature.
        let reparsed = P384Signature::try_from(&raw[..]).unwrap();
        let reparsed_bytes = reparsed.to_bytes();
        let reparsed_bytes: &[u8] = reparsed_bytes.as_ref();
        assert_eq!(reparsed_bytes, raw.as_ref());
        // And it must agree with the DER signature it came from.
        assert_eq!(reparsed, signed);
    }

    #[test]
    fn test_ecdsa_der_to_raw96_rejects_garbage() {
        assert!(ecdsa_der_to_raw96(&[]).is_err());
        assert!(ecdsa_der_to_raw96(&[0x30, 0x00]).is_err());
        assert!(ecdsa_der_to_raw96(b"definitely not DER").is_err());
        // A 96-byte fixed-width signature is *not* valid DER input: from_der
        // must reject it rather than silently misreading it.
        assert!(ecdsa_der_to_raw96(&[0x11; V3_PUBLIC_SIG_LEN]).is_err());
    }

    // ---- claims / assembly ---------------------------------------------

    #[test]
    fn test_claims_to_payload_is_json() {
        let mut claims = Claims::new_expires_in(&Duration::from_secs(3600)).unwrap();
        claims.subject("user123").unwrap();
        claims.audience("appid").unwrap();

        let payload = claims_to_payload(&claims).unwrap();
        let as_json: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(as_json["sub"], "user123");
        assert_eq!(as_json["aud"], "appid");
        assert!(as_json["exp"].is_string());
    }

    #[test]
    fn test_assemble_token_without_footer() {
        let message = b"payload";
        let signature = [0xaau8; 8];
        let token = assemble_token(V4_HEADER, message, &signature, None);

        assert!(token.starts_with(V4_HEADER));
        let body = token.trim_start_matches(V4_HEADER);
        assert!(
            !body.contains('.'),
            "no footer means exactly one body segment"
        );
        let mut expected = message.to_vec();
        expected.extend_from_slice(&signature);
        assert_eq!(b64url_decode(body).unwrap(), expected);
    }

    #[test]
    fn test_assemble_token_with_footer() {
        let message = b"payload";
        let signature = [0xbbu8; 8];
        let footer = b"kid-123";
        let token = assemble_token(V3_HEADER, message, &signature, Some(footer));

        assert!(token.starts_with(V3_HEADER));
        let rest = token.trim_start_matches(V3_HEADER);
        let segments: Vec<&str> = rest.split('.').collect();
        assert_eq!(segments.len(), 2, "a footer adds exactly one `.` separator");

        let mut expected = message.to_vec();
        expected.extend_from_slice(&signature);
        assert_eq!(b64url_decode(segments[0]).unwrap(), expected);
        assert_eq!(b64url_decode(segments[1]).unwrap(), footer.to_vec());
    }

    /// An empty footer must be treated as absent: PASETO encodes "no footer" as
    /// the absence of the trailing segment, never as an empty segment.
    #[test]
    fn test_assemble_token_empty_footer_is_no_footer() {
        let token = assemble_token(V4_HEADER, b"payload", &[0x01], Some(b""));
        // The header itself ends in '.', so the separator count is checked on
        // the part after it.
        let body = token.trim_start_matches(V4_HEADER);
        assert!(
            !body.contains('.'),
            "an empty footer must not add a segment"
        );
        assert_eq!(token, assemble_token(V4_HEADER, b"payload", &[0x01], None));
    }

    // ---- error mapping -------------------------------------------------

    #[test]
    fn test_kms_error_maps_to_401_for_crypto_failures() {
        let crypto = [
            KmsError::ClaimsSerialization(pasetors::errors::Error::ClaimInvalidJson),
            KmsError::DerToRaw("bad der".to_string()),
            KmsError::Pasetors(pasetors::errors::Error::Key),
        ];
        for err in crypto {
            let mapped: RouterError = err.into();
            assert!(
                matches!(mapped, RouterError::Unauthenticated(_)),
                "crypto failure must map to 401"
            );
        }
    }

    #[test]
    fn test_kms_error_maps_to_500_for_config_and_transport_failures() {
        let config = [
            KmsError::MissingKeyId,
            KmsError::InvalidKeySource("bogus".to_string()),
            KmsError::UnsupportedKeySpec("RSA_2048".to_string()),
            KmsError::MissingPublicKey,
            KmsError::SpkiLength { got: 1, want: 2 },
            KmsError::SpkiPrefix { kind: "Ed25519" },
            KmsError::PaeOverflow("x".to_string()),
        ];
        for err in config {
            let mapped: RouterError = err.into();
            assert!(
                matches!(mapped, RouterError::KeyPairError(_)),
                "configuration failure must map to 500"
            );
        }
    }

    // ---- differential framing: this crate vs pasetors --------------------

    /// The pieces a pasetors token actually signs, recovered from the token
    /// itself with this crate's own base64url decoder.
    struct SplitToken {
        message: Vec<u8>,
        signature: Vec<u8>,
        footer: Option<Vec<u8>>,
    }

    /// Split a pasetors-produced `token` into `(message, signature, footer)`.
    /// `sig_len` is the only width knowledge used, so a wrong signature length
    /// among this module's constants surfaces as a failure here.
    fn split_token(header: &str, token: &str, sig_len: usize) -> SplitToken {
        assert!(
            token.starts_with(header),
            "pasetors produced a token without the {header:?} header: {token:?}"
        );
        let mut segments = token[header.len()..].split('.');
        let body = segments.next().expect("body segment");
        let footer = segments.next();
        assert!(
            segments.next().is_none(),
            "a PASETO token carries at most one footer segment"
        );

        let decoded = b64url_decode(body).expect("body is unpadded base64url");
        assert!(
            decoded.len() > sig_len,
            "a PASETO body is message || signature"
        );
        let (message, signature) = decoded.split_at(decoded.len() - sig_len);

        SplitToken {
            message: message.to_vec(),
            signature: signature.to_vec(),
            footer: footer.map(|f| b64url_decode(f).expect("footer is unpadded base64url")),
        }
    }

    /// A realistic but fixed claim set, so the payload is JSON that PASETO
    /// accepts while staying deterministic across runs.
    fn differential_payload() -> Vec<u8> {
        let mut claims = Claims::new_expires_in(&Duration::from_secs(3600)).unwrap();
        claims.subject("differential").unwrap();
        claims.audience("iciaws_router").unwrap();
        claims_to_payload(&claims).unwrap()
    }

    /// Rebuild a P-384 verifying key from pasetors' 49-byte compressed point
    /// through *our* `p384` build, so the ECDSA checks below run on this crate's
    /// dependency tree rather than on pasetors' older `p384` 0.13.
    fn p384_verifying_key(compressed: &[u8]) -> p384::ecdsa::VerifyingKey {
        use p384::ecdsa::VerifyingKey;
        VerifyingKey::from_sec1_bytes(compressed).expect("valid compressed P-384 point")
    }

    /// v4, no footer: `assemble_token` must rebuild pasetors' token
    /// byte-for-byte, and pasetors' own verifier must accept the result.
    #[test]
    fn differential_v4_no_footer_matches_pasetors() {
        use pasetors::token::Public as PurposePublic;
        use pasetors::version4::PublicToken as V4PublicToken;

        let pair = AsymmetricKeyPair::<V4>::generate().unwrap();
        let payload = differential_payload();
        let token =
            V4PublicToken::sign(&pair.secret, &payload, None, None).expect("pasetors v4 sign");

        let split = split_token(V4_HEADER, &token, V4_PUBLIC_SIG_LEN);
        assert_eq!(split.message, payload);
        assert_eq!(split.signature.len(), V4_PUBLIC_SIG_LEN);
        assert_eq!(split.footer, None);

        let ours = assemble_token(V4_HEADER, &split.message, &split.signature, None);
        assert_eq!(ours, token, "v4 assembly must be byte-identical");

        // Closing the loop: the token we assembled is one pasetors accepts.
        let untrusted =
            pasetors::token::UntrustedToken::<PurposePublic, V4>::try_from(ours.as_str()).unwrap();
        V4PublicToken::verify(&pair.public, &untrusted, None, None)
            .expect("pasetors accepts our token");
    }

    /// v4, with footer: the footer must land in its own trailing segment and
    /// survive our assembly unchanged, byte-for-byte.
    #[test]
    fn differential_v4_with_footer_matches_pasetors() {
        use pasetors::token::Public as PurposePublic;
        use pasetors::version4::PublicToken as V4PublicToken;

        let pair = AsymmetricKeyPair::<V4>::generate().unwrap();
        let payload = differential_payload();
        let footer = b"kid-abc123";
        let token = V4PublicToken::sign(&pair.secret, &payload, Some(footer), None).unwrap();

        let split = split_token(V4_HEADER, &token, V4_PUBLIC_SIG_LEN);
        assert_eq!(split.message, payload);
        assert_eq!(split.footer.as_deref(), Some(&footer[..]));

        let ours = assemble_token(V4_HEADER, &split.message, &split.signature, Some(footer));
        assert_eq!(ours, token, "v4 footer framing must be byte-identical");

        let untrusted =
            pasetors::token::UntrustedToken::<PurposePublic, V4>::try_from(ours.as_str()).unwrap();
        V4PublicToken::verify(&pair.public, &untrusted, Some(footer), None).unwrap();
    }

    /// v3, no footer: pasetors' signature must verify, under ECDSA-P384/SHA-384,
    /// against the PAE *this* crate builds â€” which pins the v3 piece order
    /// `[pk, header, m, f, i]` and the `le64` encoding in one assertion.
    #[test]
    fn differential_v3_no_footer_matches_pasetors() {
        use p384::ecdsa::signature::Verifier;
        use pasetors::token::Public as PurposePublic;
        use pasetors::version3::PublicToken as V3PublicToken;

        let pair = AsymmetricKeyPair::<V3>::generate().unwrap();
        let payload = differential_payload();
        let token =
            V3PublicToken::sign(&pair.secret, &payload, None, None).expect("pasetors v3 sign");

        let split = split_token(V3_HEADER, &token, V3_PUBLIC_SIG_LEN);
        assert_eq!(split.message, payload);
        assert_eq!(split.signature.len(), V3_PUBLIC_SIG_LEN);
        assert_eq!(split.footer, None);

        let our_pae = pae(&[
            pair.public.as_bytes(),
            V3_HEADER.as_bytes(),
            split.message.as_slice(),
            &[],
            &[],
        ])
        .unwrap();
        assert_eq!(&our_pae[..8], &le64(5), "v3 signs five PAE pieces");
        let verifying = p384_verifying_key(pair.public.as_bytes());
        let signature = P384Signature::try_from(&split.signature[..]).unwrap();
        verifying
            .verify(&our_pae, &signature)
            .expect("pasetors' signature must cover our PAE byte-for-byte");

        // Control: the same check must fail on a single flipped bit, so the
        // assertion above cannot pass vacuously.
        let mut mutated = our_pae.clone();
        let last = mutated.len() - 1;
        mutated[last] ^= 0x01;
        assert!(
            verifying.verify(&mutated, &signature).is_err(),
            "a single flipped bit must break ECDSA verification"
        );

        let ours = assemble_token(V3_HEADER, &split.message, &split.signature, None);
        assert_eq!(ours, token, "v3 assembly must be byte-identical");

        let untrusted =
            pasetors::token::UntrustedToken::<PurposePublic, V3>::try_from(ours.as_str()).unwrap();
        V3PublicToken::verify(&pair.public, &untrusted, None, None).unwrap();
    }

    /// v3, with footer: the footer is a signed PAE piece, not just a trailing
    /// segment, so the same ECDSA proof pins `[pk, header, m, f, ""]`.
    #[test]
    fn differential_v3_with_footer_matches_pasetors() {
        use p384::ecdsa::signature::Verifier;
        use pasetors::token::Public as PurposePublic;
        use pasetors::version3::PublicToken as V3PublicToken;

        let pair = AsymmetricKeyPair::<V3>::generate().unwrap();
        let payload = differential_payload();
        let footer = b"kid-abc123";
        let token = V3PublicToken::sign(&pair.secret, &payload, Some(footer), None).unwrap();

        let split = split_token(V3_HEADER, &token, V3_PUBLIC_SIG_LEN);
        assert_eq!(split.message, payload);
        assert_eq!(split.footer.as_deref(), Some(&footer[..]));

        let our_pae = pae(&[
            pair.public.as_bytes(),
            V3_HEADER.as_bytes(),
            split.message.as_slice(),
            footer,
            &[],
        ])
        .unwrap();
        let verifying = p384_verifying_key(pair.public.as_bytes());
        let signature = P384Signature::try_from(&split.signature[..]).unwrap();
        verifying
            .verify(&our_pae, &signature)
            .expect("pasetors' v3 signature must cover our PAE byte-for-byte");

        // Dropping the footer from the PAE must break verification: the footer
        // is inside the signed pre-image, not merely appended to the token.
        let without_footer = pae(&[
            pair.public.as_bytes(),
            V3_HEADER.as_bytes(),
            split.message.as_slice(),
            &[],
            &[],
        ])
        .unwrap();
        assert!(verifying.verify(&without_footer, &signature).is_err());

        let ours = assemble_token(V3_HEADER, &split.message, &split.signature, Some(footer));
        assert_eq!(ours, token, "v3 footer framing must be byte-identical");

        let untrusted =
            pasetors::token::UntrustedToken::<PurposePublic, V3>::try_from(ours.as_str()).unwrap();
        V3PublicToken::verify(&pair.public, &untrusted, Some(footer), None).unwrap();
    }

    /// Negative control: v3's PAE must be order-sensitive. Putting the header
    /// before the public key (the v4 layout) must produce different bytes and
    /// invalidate the real signature, otherwise the v3 differential test could
    /// not detect a reversal.
    #[test]
    fn differential_v3_pae_is_order_sensitive() {
        use p384::ecdsa::signature::Verifier;

        let pair = AsymmetricKeyPair::<V3>::generate().unwrap();
        let payload = differential_payload();

        let key_first = pae(&[
            pair.public.as_bytes(),
            V3_HEADER.as_bytes(),
            payload.as_slice(),
            &[],
            &[],
        ])
        .unwrap();
        let header_first = pae(&[
            V3_HEADER.as_bytes(),
            pair.public.as_bytes(),
            payload.as_slice(),
            &[],
            &[],
        ])
        .unwrap();
        assert_ne!(
            key_first, header_first,
            "PAE must be order-sensitive or a v3/v4 reversal would go unnoticed"
        );

        // The reversal must break the signature, which is what makes the
        // ordering a correctness property rather than a cosmetic one.
        let verifying = p384_verifying_key(pair.public.as_bytes());
        let token =
            pasetors::version3::PublicToken::sign(&pair.secret, &payload, None, None).unwrap();
        let split = split_token(V3_HEADER, &token, V3_PUBLIC_SIG_LEN);
        let signature = P384Signature::try_from(&split.signature[..]).unwrap();
        assert!(verifying.verify(&header_first, &signature).is_err());
    }

    /// v4's PAE is `[header, m, f, i]` â€” four pieces, no public key. Ed25519
    /// signing is not reachable from this crate's dependency graph, so the
    /// signature cannot be replayed against our bytes the way it can for v3;
    /// instead every *nearby wrong* piece list is shown to differ, and the
    /// count field is pinned.
    #[test]
    fn differential_v4_pae_piece_list_is_exact() {
        let pair = AsymmetricKeyPair::<V4>::generate().unwrap();
        let payload = differential_payload();
        let footer: &[u8] = b"kid-abc123";
        let header = V4_HEADER.as_bytes();

        let correct = pae(&[header, payload.as_slice(), footer, &[]]).unwrap();
        assert_eq!(&correct[..8], &le64(4), "v4 signs four PAE pieces");

        let key_first = pae(&[
            pair.public.as_bytes(),
            header,
            payload.as_slice(),
            footer,
            &[],
        ])
        .unwrap();
        let three_piece = pae(&[header, payload.as_slice(), footer]).unwrap();
        let footer_dropped = pae(&[header, payload.as_slice(), &[], &[]]).unwrap();
        let implicit_assert_present = pae(&[header, payload.as_slice(), footer, b"x"]).unwrap();
        let three_piece_v3_count = pae(&[header, payload.as_slice(), footer, &[], &[]]).unwrap();

        for (label, wrong) in [
            ("v4 key-first (v3 layout)", key_first),
            ("3-piece form", three_piece),
            ("footer dropped", footer_dropped),
            ("implicit assertion invented", implicit_assert_present),
            ("5-piece form", three_piece_v3_count),
        ] {
            assert_ne!(correct, wrong, "{label} must not produce our PAE");
        }
    }

    /// The happy path `test_p384_public_key_shape_and_error_paths` could not
    /// reach: a genuine 120-byte P-384 SPKI, produced by `p384`'s own PKCS#8
    /// encoder (already in the tree via its default `pem` feature), must
    /// round-trip through `p384_public_key_from_spki` to exactly the key
    /// pasetors generated.
    #[test]
    fn test_p384_public_key_from_spki_roundtrip_real_spki() {
        use p384::ecdsa::VerifyingKey;
        use p384::pkcs8::EncodePublicKey;

        let pair = AsymmetricKeyPair::<V3>::generate().unwrap();
        let verifying = VerifyingKey::from_sec1_bytes(pair.public.as_bytes()).unwrap();
        let spki = verifying.to_public_key_der().unwrap().as_bytes().to_vec();

        assert_eq!(
            spki.len(),
            P384_SPKI_LEN,
            "a P-384 SPKI is always 120 bytes"
        );
        // SEQUENCE(118) { SEQUENCE(16){id-ecPublicKey, secp384r1},
        //                 BIT STRING(98){ 0x00, 0x04 || x(48) || y(48) } }
        assert_eq!(spki[0], 0x30);
        assert_eq!(spki[1], 0x76);
        assert_eq!(spki[2], 0x30);
        assert_eq!(&spki[20..23], &[0x03, 0x62, 0x00]);
        assert_eq!(
            spki[P384_SPKI_LEN - P384_SEC1_LEN],
            SEC1_UNCOMPRESSED_TAG,
            "the uncompressed point tag sits at the start of the last 97 bytes"
        );

        let key = p384_public_key_from_spki(&spki).expect("a real P-384 SPKI must parse");
        assert_eq!(
            key.as_bytes(),
            pair.public.as_bytes(),
            "the SPKI round-trip must recover pasetors' compressed key"
        );
    }
}
