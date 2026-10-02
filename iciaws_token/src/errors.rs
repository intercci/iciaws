#![allow(dead_code)]
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TokenError {
    #[error("[Unauthenticated] {0}")]
    Unauthenticated(String), // status code 401
    #[error("Key pair error: {0}")]
    KeyPairError(String),
    #[error("serde_json error")]
    SerdeJsonError(#[from] serde_json::Error),
    #[error("UTF8 convert error")]
    Utf8ConvertError(#[from] std::str::Utf8Error),
    #[error("base64 error")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("pasetos error")]
    PasetosError(#[from] pasetors::errors::Error),
}
