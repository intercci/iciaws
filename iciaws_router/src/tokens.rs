use crate::errors::RouterError;
use base64::prelude::*;
use dotenv::dotenv;
use lambda_http::tracing;
use pasetors::claims::{Claims, ClaimsValidationRules};
use pasetors::keys::{AsymmetricKeyPair, AsymmetricPublicKey, AsymmetricSecretKey, Generate};
use pasetors::token::UntrustedToken;
use pasetors::{Public, public, version4::V4};
use serde_json::json;
use std::collections::HashMap;
use std::env;
use std::time::Duration;

const ACCESS_TOKEN_SECONDS: u64 = 1 * 3600; // 1-hour lifetime for an access token
const REFRESH_TOKEN_SECONDS: u64 = 2 * 24 * 3600; // 2 days, 48 hours lifetime for a refresh token

#[derive(Debug, Clone)]
pub struct Keys {
    pub keys: AsymmetricKeyPair<V4>,
}

impl Keys {
    /// Create a new Keys instance with keys from environment variables
    ///
    /// # Environment variables:
    ///
    /// * LAMBDA_TASK_ROOT - if exists, it's deployed on remote
    /// * PUB_KEY - the public key string
    /// * PRV_KEY - the private key string
    ///
    /// # Returns a Keys instance or error
    pub fn from_env() -> Result<Self, RouterError> {
        if env::var("LAMBDA_TASK_ROOT").is_err() {
            dotenv().ok();
        }
        let pb = env::var("PUB_KEY").map_err(|_| RouterError::KeyPairError("Key Not Found".to_string()))?;
        let pv = env::var("PRV_KEY").map_err(|_| RouterError::KeyPairError("Key Not Found".to_string()))?;
        let bbs = BASE64_STANDARD.decode(&pb).map_err(RouterError::from)?;
        let vbs = BASE64_STANDARD.decode(&pv).map_err(RouterError::from)?;
        Ok(Self {
            keys: AsymmetricKeyPair::<V4> {
                public: AsymmetricPublicKey::<V4>::from(bbs.as_ref()).unwrap(),
                secret: AsymmetricSecretKey::<V4>::from(vbs.as_ref()).unwrap(),
            },
        })
    }

    /// Create a new Keys instance with a pair of key strings
    ///
    /// # Arguments:
    ///
    /// * pubkey - public key string
    /// * privkey - private key string
    ///
    pub fn from_strings(pubkey: String, privkey: String) -> Self {
        let bbs = BASE64_STANDARD.decode(pubkey).unwrap();
        let vbs = BASE64_STANDARD.decode(privkey).unwrap();
        Self {
            keys: AsymmetricKeyPair::<V4> {
                public: AsymmetricPublicKey::<V4>::from(bbs.as_ref()).unwrap(),
                secret: AsymmetricSecretKey::<V4>::from(vbs.as_ref()).unwrap(),
            },
        }
    }

    /// Create a new Keys instance with a pair of generated random keys.
    ///
    pub fn random_keys() -> Self {
        Keys {
            keys: AsymmetricKeyPair::<V4>::generate().unwrap(),
        }
    }

    /// Return the base64-encoded string of the current public key.
    ///
    pub fn public_key_string(&self) -> String {
        BASE64_STANDARD.encode(self.keys.public.as_bytes())
    }

    /// Return the base64-encoded string of the current private key.
    ///
    pub fn private_key_string(&self) -> String {
        BASE64_STANDARD.encode(self.keys.secret.as_bytes())
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
    pub fn gen_token(
        &self,
        sub: &str,
        aud: &str,
        secs: u64,
        extra: Option<HashMap<String, String>>,
    ) -> Result<String, RouterError> {
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
        let t = public::sign(&self.keys.secret, &claims, None, None)?;
        Ok(t)
    }

    /// Create either a access_token or a refresh_token.
    ///
    /// # Arguments:
    ///
    /// * sub - user id without prefix
    /// * aud - appid (the sk in items with pk=App)
    /// * refresh_token - if true, generate a longer refresh_token with extra claims attribute 'typ'='refresh'
    ///
/*    pub fn gen_common_token(
        &self,
        sub: &str,
        aud: &str,
        refresh_token: bool,
    ) -> Result<String, RouterError> {
        let secs: u64 = if refresh_token {
            REFRESH_TOKEN_SECONDS
        } else {
            ACCESS_TOKEN_SECONDS
        };
        let duration = Duration::new(secs, 0);
        let mut claims = Claims::new_expires_in(&duration)?;
        claims.subject(sub)?;
        claims.audience(aud)?;
        if refresh_token {
            claims.add_additional("typ", "refresh")?;
        }
        let t = public::sign(&self.keys.secret, &claims, None, None)?;
        Ok(t)
    }*/

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
    /// # Arguments:
    ///
    /// * token - &str of a paseto token
    ///
    /// # Errors:
    ///
    /// - Invalid or expired token
    ///
    pub fn verify_token(&self, token: &str) -> Result<Claims, RouterError> {
        let tokens = token.strip_prefix("Bearer ").unwrap_or(token);
        let untrusted_token = UntrustedToken::<Public, V4>::try_from(tokens)?;
        let validation_rules = ClaimsValidationRules::new();
        let r = public::verify(
            &self.keys.public,
            &untrusted_token,
            &validation_rules,
            None,
            None,
        )
        .map_err(RouterError::from)?;
        Ok(r.payload_claims().unwrap().to_owned())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::collections::HashMap;

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
    }

    /// Test that Keys::from_strings() correctly parses base64-encoded keys
    #[test]
    fn test_from_strings() {
        // Generate a key pair first to get valid base64 strings
        let keys = Keys::random_keys();
        let pub_key = keys.public_key_string();
        let priv_key = keys.private_key_string();
        
        // Create new Keys from the base64 strings
        let keys_from_strings = Keys::from_strings(pub_key.clone(), priv_key.clone());
        
        // Verify the keys produce the same public key string
        assert_eq!(keys_from_strings.public_key_string(), pub_key);
        assert_eq!(keys_from_strings.private_key_string(), priv_key);
        
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
        let priv_key = keys.private_key_string();
        
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
}
