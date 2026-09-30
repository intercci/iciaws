use crate::errors::RouterError;
use base64::prelude::*;
use dotenv::dotenv;
use lambda_http::tracing;
use pasetors::claims::{Claims, ClaimsValidationRules};
use pasetors::errors::Error as PasetosError;
use pasetors::keys::{AsymmetricKeyPair, AsymmetricPublicKey, AsymmetricSecretKey, Generate};
use pasetors::token::UntrustedToken;
use pasetors::{Public, public, version4::V4};
use serde_json::json;
use std::collections::HashMap;
use std::env;
use std::time::Duration;

const ACCESS_TOKEN_SECONDS: u64 = 1 * 3600; // 1-hour lifetime for an access token
const REFRESH_TOKEN_SECONDS: u64 = 2 * 24 * 3600; // 2 days, 48 hours lifetime for a refresh token

/// Message used when a required key environment variable is absent.
const KEY_NOT_FOUND: &str = "Key Not Found";

/// Message used when signing is attempted on a verifier-only instance.
const NO_SIGNING_KEY: &str =
    "no signing key loaded (verifier-only Keys): set PRV_KEY to enable token signing";

/// PASETO v4 public-mode key material.
///
/// The secret half is optional so a deployment that only *verifies* tokens (an
/// API / resource Lambda) can be provisioned with the public key alone. A
/// verifier-only instance can call [`Keys::verify_token`], but every signing
/// entry point ([`Keys::gen_token`], [`Keys::gen_access_token`],
/// [`Keys::gen_refresh_token`]) fails closed with [`RouterError::KeyPairError`]
/// rather than panicking or emitting an empty token.
#[derive(Debug, Clone)]
pub struct Keys {
    /// Public key; always present and the only key needed to verify a token.
    pub public: AsymmetricPublicKey<V4>,
    /// Secret key; `None` in verifier-only mode, where signing is unavailable.
    pub secret: Option<AsymmetricSecretKey<V4>>,
}

impl Keys {
    /// Create a new Keys instance with keys from environment variables.
    ///
    /// `PUB_KEY` is required. `PRV_KEY` is optional: when it is absent (or blank)
    /// the returned instance is verifier-only and can verify tokens but cannot
    /// sign them. When `PRV_KEY` is present but malformed, loading fails loudly
    /// with [`RouterError::KeyPairError`] rather than silently degrading to
    /// verifier-only.
    ///
    /// # Environment variables:
    ///
    /// * LAMBDA_TASK_ROOT - if exists, it's deployed on remote
    /// * PUB_KEY - the public key string (required)
    /// * PRV_KEY - the private key string (optional; enables token signing)
    ///
    /// # Returns a Keys instance or error
    pub fn from_env() -> Result<Self, RouterError> {
        if env::var("LAMBDA_TASK_ROOT").is_err() {
            dotenv().ok();
        }
        let pb = env::var("PUB_KEY")
            .map_err(|_| RouterError::KeyPairError(format!("{KEY_NOT_FOUND}: PUB_KEY")))?;
        let pv = env::var("PRV_KEY").ok().filter(|s| !s.trim().is_empty());
        let keys = Self::from_strings(pb, pv)?;
        if keys.is_verifier() {
            tracing::info!("Keys loaded in verifier-only mode (PRV_KEY absent): token signing is disabled");
        } else {
            tracing::info!("Keys loaded in signer mode (PUB_KEY and PRV_KEY present)");
        }
        Ok(keys)
    }

    /// Create a new Keys instance from base64-encoded key strings.
    ///
    /// Signature note: the private key is an `Option<String>` so that a
    /// verifier-only instance is expressible. Pass `None` (or use
    /// [`Keys::from_public_string`]) when only `PUB_KEY` is available.
    ///
    /// Parsing is fallible and never panics: a key of the wrong length, or a
    /// secret key that does not match the public key, yields
    /// [`RouterError::KeyPairError`].
    ///
    /// # Arguments:
    ///
    /// * pubkey - public key string
    /// * privkey - private key string, or `None` for a verifier-only instance
    ///
    pub fn from_strings(pubkey: String, privkey: Option<String>) -> Result<Self, RouterError> {
        let bbs = BASE64_STANDARD.decode(&pubkey).map_err(RouterError::from)?;
        let public = AsymmetricPublicKey::<V4>::from(bbs.as_ref())
            .map_err(|e| RouterError::KeyPairError(format!("invalid public key: {e:?}")))?;
        let secret = match privkey {
            Some(pv) => {
                let vbs = BASE64_STANDARD.decode(&pv).map_err(RouterError::from)?;
                let secret = AsymmetricSecretKey::<V4>::from(vbs.as_ref())
                    .map_err(|e| RouterError::KeyPairError(format!("invalid private key: {e:?}")))?;
                // pasetors only checks that the secret key is internally consistent
                // (right length, tail matches its own seed); it does not check that
                // the secret belongs to `public`. Reject a mismatched pair here so
                // a misconfigured deployment fails loudly at load instead of
                // silently minting tokens that its own public key cannot verify.
                let derived = AsymmetricPublicKey::<V4>::try_from(&secret)
                    .map_err(|e| RouterError::KeyPairError(format!("invalid private key: {e:?}")))?;
                if derived != public {
                    return Err(RouterError::KeyPairError(
                        "PUB_KEY and PRV_KEY do not belong to the same key pair".to_string(),
                    ));
                }
                Some(secret)
            }
            None => None,
        };
        Ok(Self { public, secret })
    }

    /// Create a verifier-only Keys instance from a base64 public key string.
    ///
    /// Shorthand for `from_strings(pubkey, None)`: the result can verify tokens
    /// but every signing call returns [`RouterError::KeyPairError`].
    pub fn from_public_string(pubkey: String) -> Result<Self, RouterError> {
        Self::from_strings(pubkey, None)
    }

    /// Create a new Keys instance with a pair of generated random keys.
    ///
    /// Panics only if the OS CSPRNG is unavailable, which is not a recoverable
    /// condition for a Lambda.
    pub fn random_keys() -> Self {
        let pair = AsymmetricKeyPair::<V4>::generate()
            .expect("PASETO v4 key generation requires a working OS CSPRNG");
        Self {
            public: pair.public,
            secret: Some(pair.secret),
        }
    }

    /// `true` when the secret key is loaded, i.e. this instance can sign tokens.
    pub fn has_signing_key(&self) -> bool {
        self.secret.is_some()
    }

    /// `true` when only the public key is loaded, i.e. signing is unavailable.
    pub fn is_verifier(&self) -> bool {
        self.secret.is_none()
    }

    /// Return the base64-encoded string of the current public key.
    ///
    pub fn public_key_string(&self) -> String {
        BASE64_STANDARD.encode(self.public.as_bytes())
    }

    /// Return the base64-encoded string of the current private key.
    ///
    /// Returns `None` in verifier-only mode. An `Option` is used rather than an
    /// empty string or a panic so a caller can never mistake "no key" for a key.
    ///
    pub fn private_key_string(&self) -> Option<String> {
        self.secret.as_ref().map(|s| BASE64_STANDARD.encode(s.as_bytes()))
    }

    /// Create a PASETO token with sub, aud, secs and possibly extra claims.
    ///
    /// # Arguments:
    ///
    /// * sub - The sub field in jwt, usually the user id
    /// * aud - The aud field in jwt, usually the client id or appid
    /// * secs - number of seconds the token lives
    /// * extra - additional fields as jwt claims
    ///
    /// # Returns a token string or error
    ///
    /// # Errors:
    ///
    /// - [`RouterError::KeyPairError`] if this is a verifier-only instance
    ///   (no `PRV_KEY`); checked before any claim is built so the failure is
    ///   fail-closed rather than a panic or a blank token.
    ///
    pub fn gen_token(
        &self,
        sub: &str,
        aud: &str,
        secs: u64,
        extra: Option<HashMap<String, String>>,
    ) -> Result<String, RouterError> {
        let secret = match self.secret.as_ref() {
            Some(s) => s,
            None => {
                tracing::debug!("gen_token refused: {NO_SIGNING_KEY}");
                return Err(RouterError::KeyPairError(NO_SIGNING_KEY.to_string()));
            }
        };
        let duration = Duration::new(secs, 0);
        let mut claims = Claims::new_expires_in(&duration)?;
        claims.subject(sub)?;
        claims.audience(aud)?;
        if let Some(extras) = extra {
            for (key, value) in extras.iter() {
                let v = json!(value);
                tracing::debug!("gen_token add extra key={key}, value={v:?}");
                claims.add_additional(key, v)?;
            }
        }
        let t = public::sign(secret, &claims, None, None)?;
        Ok(t)
    }

    /// Create an access_token with default lifecyle (1 hour)
    pub fn gen_access_token(&self, sub: &str, aud: &str, extra: Option<HashMap<String, String>>) -> Result<String, RouterError> {
        self.gen_token(sub, aud, ACCESS_TOKEN_SECONDS, extra)
    }

    /// Create a refresh_token with default lifecyle (2 days)
    pub fn gen_refresh_token(&self, sub: &str, aud: &str, extra: Option<HashMap<String, String>>) -> Result<String, RouterError> {
        let mut ex = extra.unwrap_or_default();
        ex.insert("typ".to_string(), "refresh".to_string());
        self.gen_token(sub, aud, REFRESH_TOKEN_SECONDS, Some(ex))
    }

    /// Verify a PASETO token and return the Claims.
    ///
    /// Works in both signer and verifier-only mode: only the public key is used.
    /// A `Bearer ` prefix is stripped if present.
    ///
    /// # Arguments:
    ///
    /// * token - &str of a paseto token
    ///
    /// # Errors:
    ///
    /// - Invalid or expired token
    /// - [`RouterError::PasetosError`] if the token carries no validated claims
    ///
    pub fn verify_token(&self, token: &str) -> Result<Claims, RouterError> {
        let tokens = token.strip_prefix("Bearer ").unwrap_or(token);
        let untrusted_token = UntrustedToken::<Public, V4>::try_from(tokens)?;
        let validation_rules = ClaimsValidationRules::new();
        let r = public::verify(
            &self.public,
            &untrusted_token,
            &validation_rules,
            None,
            None,
        )
        .map_err(RouterError::from)?;
        r.payload_claims()
            .cloned()
            .ok_or(RouterError::PasetosError(PasetosError::EmptyPayload))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::collections::HashMap;
    use std::ffi::OsString;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    /// Serializes the tests that mutate the process environment, which is global
    /// state shared by every test thread in this binary.
    fn env_lock() -> MutexGuard<'static, ()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// RAII snapshot of the key-related environment variables, restored on drop
    /// so a failing assertion cannot leak mutated state into other tests.
    struct KeyEnvGuard {
        saved: Vec<(&'static str, Option<OsString>)>,
    }

    impl KeyEnvGuard {
        /// Capture the current values of the key environment variables.
        ///
        /// Also sets `LAMBDA_TASK_ROOT`, which makes `from_env()` skip `dotenv()`
        /// and therefore makes these tests independent of any `.env` file.
        fn capture() -> Self {
            let names = ["PUB_KEY", "PRV_KEY", "LAMBDA_TASK_ROOT"];
            let saved = names
                .iter()
                .map(|n| (*n, env::var_os(n)))
                .collect::<Vec<(&'static str, Option<OsString>)>>();
            // SAFETY: the caller holds `env_lock()`, so no other test thread is
            // reading or writing the environment while this guard is alive.
            unsafe { env::set_var("LAMBDA_TASK_ROOT", "test") };
            Self { saved }
        }

        /// Set `PUB_KEY` and remove `PRV_KEY` to emulate a verify-only deployment.
        fn set_public_only(pub_key: &str) {
            // SAFETY: see `capture()`; `env_lock()` is held by the caller.
            unsafe {
                env::set_var("PUB_KEY", pub_key);
                env::remove_var("PRV_KEY");
            }
        }

        /// Set both key variables to emulate a signing deployment.
        fn set_pair(pub_key: &str, prv_key: &str) {
            // SAFETY: see `capture()`; `env_lock()` is held by the caller.
            unsafe {
                env::set_var("PUB_KEY", pub_key);
                env::set_var("PRV_KEY", prv_key);
            }
        }
    }

    impl Drop for KeyEnvGuard {
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

    /// Test that Keys::random_keys() creates valid keys that can sign and verify tokens
    #[test]
    fn test_random_keys() {
        let keys = Keys::random_keys();
        
        // Should be able to generate a token
        let token = keys.gen_token("user123", "appid", 3600, None);
        assert!(token.is_ok());
        
        // Should be able to verify the token
        let claims = keys.verify_token(&token.unwrap());
        assert!(claims.is_ok());

        // random_keys() populates both halves, so it is a signer, not a verifier
        assert!(keys.has_signing_key());
        assert!(!keys.is_verifier());
    }

    /// Test that Keys::from_strings() correctly parses base64-encoded keys
    #[test]
    fn test_from_strings() {
        // Generate a key pair first to get valid base64 strings
        let keys = Keys::random_keys();
        let pub_key = keys.public_key_string();
        let priv_key = keys.private_key_string().expect("random_keys has a private key");
        
        // Create new Keys from the base64 strings
        let keys_from_strings = Keys::from_strings(pub_key.clone(), Some(priv_key.clone())).unwrap();
        
        // Verify the keys produce the same public key string
        assert_eq!(keys_from_strings.public_key_string(), pub_key);
        assert_eq!(keys_from_strings.private_key_string(), Some(priv_key));
        assert!(keys_from_strings.has_signing_key());
        
        // Should be able to sign and verify with the restored keys
        let token = keys_from_strings.gen_token("testuser", "testapp", 3600, None);
        assert!(token.is_ok());
        
        let claims = keys_from_strings.verify_token(&token.unwrap());
        assert!(claims.is_ok());
    }

    /// Test public_key_string() returns valid base64
    #[test]
    fn test_public_key_string() {
        let keys = Keys::random_keys();
        let pub_key = keys.public_key_string();
        
        // Should be non-empty
        assert!(!pub_key.is_empty());
        
        // Should be valid base64
        let decoded = BASE64_STANDARD.decode(&pub_key);
        assert!(decoded.is_ok());
        assert!(!decoded.unwrap().is_empty());
    }

    /// Test private_key_string() returns valid base64
    #[test]
    fn test_private_key_string() {
        let keys = Keys::random_keys();
        let priv_key = keys.private_key_string().expect("random_keys has a private key");
        
        // Should be non-empty
        assert!(!priv_key.is_empty());
        
        // Should be valid base64
        let decoded = BASE64_STANDARD.decode(&priv_key);
        assert!(decoded.is_ok());
        assert!(!decoded.unwrap().is_empty());
    }

    /// Test gen_token with no extra claims
    #[test]
    fn test_gen_token_basic() {
        let keys = Keys::random_keys();
        
        let token = keys.gen_token("user123", "appid", 3600, None);
        assert!(token.is_ok());
        
        let token_str = token.unwrap();
        // PASETO tokens start with "v4.public."
        assert!(token_str.starts_with("v4.public."));
    }

    /// Test gen_token with extra claims
    #[test]
    fn test_gen_token_with_extra_claims() {
        let keys = Keys::random_keys();
        
        let mut extra = HashMap::new();
        extra.insert("role".to_string(), "admin".to_string());
        extra.insert("tenant".to_string(), "tenant1".to_string());
        
        let token = keys.gen_token("user123", "appid", 3600, Some(extra));
        assert!(token.is_ok());
        
        // Verify the token - just check it succeeds
        let claims = keys.verify_token(&token.unwrap());
        assert!(claims.is_ok());
        let claims_details = claims.unwrap();
        assert_eq!(claims_details.get_claim("role").unwrap().as_str(), Some("admin"));
        assert_eq!(claims_details.get_claim("tenant").unwrap().as_str(), Some("tenant1"));
    }

    /// Test gen_access_token creates a valid token
    #[test]
    fn test_gen_access_token() {
        let keys = Keys::random_keys();
        
        let token = keys.gen_access_token("user123", "appid", None);
        assert!(token.is_ok());
        
        let token_str = token.unwrap();
        
        // Verify it works - this confirms the token has valid sub and aud claims
        let claims = keys.verify_token(&token_str);
        assert!(claims.is_ok());
    }

    /// Test gen_access_token with extra claims
    #[test]
    fn test_gen_access_token_with_extra() {
        let keys = Keys::random_keys();
        
        let mut extra = HashMap::new();
        extra.insert("scope".to_string(), "read write".to_string());
        
        let token = keys.gen_access_token("user123", "appid", Some(extra));
        assert!(token.is_ok());
        
        let claims = keys.verify_token(&token.unwrap());
        assert!(claims.is_ok());
    }

    /// Test gen_refresh_token creates a token with typ="refresh" claim
    #[test]
    fn test_gen_refresh_token() {
        let keys = Keys::random_keys();
        
        let token = keys.gen_refresh_token("user123", "appid", None);
        assert!(token.is_ok());
        
        let token_str = token.unwrap();
        
        // Verify it works - typ claim is included by gen_refresh_token
        let claims = keys.verify_token(&token_str);
        assert!(claims.is_ok());
    }

    /// Test gen_refresh_token with extra claims
    #[test]
    fn test_gen_refresh_token_with_extra() {
        let keys = Keys::random_keys();
        
        let mut extra = HashMap::new();
        extra.insert("device_id".to_string(), "device123".to_string());
        
        let token = keys.gen_refresh_token("user123", "appid", Some(extra));
        assert!(token.is_ok());
        
        // Should verify successfully with both typ and device_id claims
        let claims = keys.verify_token(&token.unwrap());
        assert!(claims.is_ok());
    }

    /// Test verify_token with a valid token
    #[test]
    fn test_verify_token_valid() {
        let keys = Keys::random_keys();
        
        // Generate a token
        let token = keys.gen_token("user123", "appid", 3600, None).unwrap();
        
        // Verify should succeed
        let claims = keys.verify_token(&token);
        assert!(claims.is_ok());
    }

    /// Test verify_token with Bearer prefix
    #[test]
    fn test_verify_token_with_bearer_prefix() {
        let keys = Keys::random_keys();
        
        let token = keys.gen_token("user123", "appid", 3600, None).unwrap();
        let bearer_token = format!("Bearer {}", token);
        
        // Verify with Bearer prefix should succeed
        let claims = keys.verify_token(&bearer_token);
        assert!(claims.is_ok());
    }

    /// Test verify_token with an invalid token (tampered)
    #[test]
    fn test_verify_token_invalid() {
        let keys = Keys::random_keys();
        
        let token = keys.gen_token("user123", "appid", 3600, None).unwrap();
        // Tamper with the token
        let tampered = format!("{}tampered", token);
        
        // Verify should fail
        let claims = keys.verify_token(&tampered);
        assert!(claims.is_err());
    }

    /// Test verify_token with a token from a different key pair
    #[test]
    fn test_verify_token_wrong_key() {
        let keys1 = Keys::random_keys();
        let keys2 = Keys::random_keys();
        
        // Generate token with keys1
        let token = keys1.gen_token("user123", "appid", 3600, None).unwrap();
        
        // Verify with keys2 should fail
        let claims = keys2.verify_token(&token);
        assert!(claims.is_err());
    }

    /// Test token with very short expiration (but still valid at creation time)
    #[test]
    fn test_gen_token_short_expiration() {
        let keys = Keys::random_keys();
        
        // 1 second expiration - should work for generation
        let token = keys.gen_token("user123", "appid", 1, None);
        assert!(token.is_ok());
        
        // Verification should succeed immediately
        let claims = keys.verify_token(&token.unwrap());
        assert!(claims.is_ok());
    }

    /// Test that two different key pairs can sign different tokens
    #[test]
    fn test_different_key_pairs_independent() {
        let keys1 = Keys::random_keys();
        let keys2 = Keys::random_keys();
        
        let token1 = keys1.gen_token("user1", "app1", 3600, None).unwrap();
        let token2 = keys2.gen_token("user2", "app2", 3600, None).unwrap();
        
        // Each key can verify its own token
        assert!(keys1.verify_token(&token1).is_ok());
        assert!(keys2.verify_token(&token2).is_ok());
        
        // Cross verification should fail
        assert!(keys1.verify_token(&token2).is_err());
        assert!(keys2.verify_token(&token1).is_err());
    }

    /// Test Keys cloning functionality
    #[test]
    fn test_keys_clone() {
        let keys = Keys::random_keys();
        let keys_clone = keys.clone();
        
        // Both should work independently
        let token1 = keys.gen_token("user1", "app1", 3600, None).unwrap();
        let token2 = keys_clone.gen_token("user2", "app2", 3600, None).unwrap();
        
        assert!(keys.verify_token(&token1).is_ok());
        assert!(keys_clone.verify_token(&token2).is_ok());
    }

    /// A verifier-only Keys (public key alone) must verify tokens produced by a
    /// full signer Keys sharing the same public key.
    #[test]
    fn test_verify_only_verifies_token_from_full_keys() {
        let signer = Keys::random_keys();
        let token = signer.gen_token("user123", "appid", 3600, None).unwrap();

        // Drop the secret half: this is what from_env() yields with only PUB_KEY
        let verifier = Keys::from_public_string(signer.public_key_string()).unwrap();
        assert!(verifier.is_verifier());
        assert!(!verifier.has_signing_key());
        assert_eq!(verifier.private_key_string(), None);

        // Verification needs only the public key, so it must succeed
        let claims = verifier.verify_token(&token).expect("verifier can verify signer token");
        assert_eq!(claims.get_claim("sub").unwrap().to_owned(), "user123");
        assert_eq!(claims.get_claim("aud").unwrap().to_owned(), "appid");

        // Bearer-prefixed form works too
        let bearer = format!("Bearer {token}");
        assert!(verifier.verify_token(&bearer).is_ok());

        // A different key pair must still be rejected
        let other = Keys::from_public_string(Keys::random_keys().public_key_string()).unwrap();
        assert!(other.verify_token(&token).is_err());
    }

    /// A verifier-only Keys must fail closed on every signing entry point:
    /// an error, never a panic and never a silent empty token.
    #[test]
    fn test_verify_only_gen_token_fails_closed() {
        let verifier = Keys::from_public_string(Keys::random_keys().public_key_string()).unwrap();

        for (name, result) in [
            ("gen_token", verifier.gen_token("user123", "appid", 3600, None)),
            ("gen_access_token", verifier.gen_access_token("user123", "appid", None)),
            ("gen_refresh_token", verifier.gen_refresh_token("user123", "appid", None)),
        ] {
            match result {
                Err(RouterError::KeyPairError(_)) => {}
                Err(other) => panic!("{name} returned the wrong error: {other}"),
                Ok(token) => panic!("{name} signed a token in verifier-only mode: {token:?}"),
            }
        }

        // private_key_string() must not panic either
        assert!(verifier.private_key_string().is_none());
    }

    /// from_env() must boot with PUB_KEY alone: no PRV_KEY, no error, no panic.
    #[test]
    fn test_from_env_without_prv_key_succeeds() {
        let _guard = env_lock();
        let _env = KeyEnvGuard::capture();

        let signer = Keys::random_keys();
        let pub_key = signer.public_key_string();
        KeyEnvGuard::set_public_only(&pub_key);

        let keys = Keys::from_env().expect("from_env must succeed with only PUB_KEY");
        assert!(keys.is_verifier());
        assert!(!keys.has_signing_key());
        assert_eq!(keys.public_key_string(), pub_key);
        assert_eq!(keys.private_key_string(), None);

        // It can still verify a token signed by the matching full key pair
        let token = signer.gen_token("user123", "appid", 3600, None).unwrap();
        assert!(keys.verify_token(&token).is_ok());

        // ... but it cannot sign
        assert!(matches!(
            keys.gen_token("user123", "appid", 3600, None),
            Err(RouterError::KeyPairError(_))
        ));
    }

    /// A blank PRV_KEY is treated as absent, so an empty secret in the
    /// environment does not turn a verify-only deployment into a broken signer.
    #[test]
    fn test_from_env_with_blank_prv_key_is_verifier_only() {
        let _guard = env_lock();
        let _env = KeyEnvGuard::capture();

        let signer = Keys::random_keys();
        // SAFETY: `env_lock()` is held, so no other thread touches the environment.
        unsafe {
            env::set_var("PUB_KEY", signer.public_key_string());
            env::set_var("PRV_KEY", "   ");
        }

        let keys = Keys::from_env().expect("a blank PRV_KEY must not break boot");
        assert!(keys.is_verifier());
    }

    /// with both PUB_KEY and PRV_KEY set, from_env() loads a signer that can
    /// still verify -- i.e. backward compatibility is preserved.
    #[test]
    fn test_from_env_with_prv_key_is_signer() {
        let _guard = env_lock();
        let _env = KeyEnvGuard::capture();

        let signer = Keys::random_keys();
        KeyEnvGuard::set_pair(&signer.public_key_string(), &signer.private_key_string().unwrap());

        let keys = Keys::from_env().expect("from_env must succeed with both keys");
        assert!(keys.has_signing_key());
        assert!(!keys.is_verifier());
        assert_eq!(keys.public_key_string(), signer.public_key_string());

        let token = keys.gen_token("user123", "appid", 3600, None).unwrap();
        assert!(keys.verify_token(&token).is_ok());
        // A token minted by the original pair verifies with the reloaded keys
        assert!(keys.verify_token(&signer.gen_token("user1", "app1", 3600, None).unwrap()).is_ok());
    }

    /// from_env() must still fail (not panic) when PUB_KEY is missing.
    #[test]
    fn test_from_env_without_pub_key_errors() {
        let _guard = env_lock();
        let _env = KeyEnvGuard::capture();

        // SAFETY: `env_lock()` is held, so no other thread touches the environment.
        unsafe {
            env::remove_var("PUB_KEY");
            env::remove_var("PRV_KEY");
        }

        assert!(matches!(Keys::from_env(), Err(RouterError::KeyPairError(_))));
    }

    /// Malformed key material must be reported as an error, never a panic:
    /// a wrong-length or mismatched key would otherwise abort a Lambda.
    #[test]
    fn test_from_strings_rejects_invalid_keys() {
        let keys = Keys::random_keys();
        let pub_key = keys.public_key_string();
        let prv_key = keys.private_key_string().unwrap();

        // Public key of the wrong length
        let short = BASE64_STANDARD.encode([0u8; 8]);
        assert!(matches!(
            Keys::from_strings(short.clone(), None),
            Err(RouterError::KeyPairError(_))
        ));

        // Secret key of the wrong length
        assert!(matches!(
            Keys::from_strings(pub_key.clone(), Some(short.clone())),
            Err(RouterError::KeyPairError(_))
        ));

        // Secret key that does not belong to the public key
        let foreign = Keys::random_keys().private_key_string().unwrap();
        assert_ne!(foreign, prv_key);
        assert!(matches!(
            Keys::from_strings(pub_key, Some(foreign)),
            Err(RouterError::KeyPairError(_))
        ));

        // Not valid base64 at all
        assert!(matches!(
            Keys::from_strings("not base64!!".to_string(), None),
            Err(RouterError::Base64DecodeError(_))
        ));
    }
}
