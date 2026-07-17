#![allow(dead_code)]
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RouterError {
    #[error("{0} not found!")]
    NotFound(String), // status code 404
    #[error("[Unauthenticated] {0}")]
    Unauthenticated(String), // status code 401
    #[error("[Unauthorized] {0}")]
    Unauthorized(String), // status code 403
    #[error("Bad request: {0}")]
    BadRequest(String), // status code 400
    #[error("Conflict: {0}")]
    DataExist(String), // status code 409
    #[error("Addon error: {0}")]
    AddonMissing(String), // status code 500
    #[error("Internal error: {0}")]
    InternalService(String), // status code 500
    #[error("Database error: {0}")]
    Database(String), // dynamodb error, 500
    #[error("Key pair error: {0}")]
    KeyPairError(String),
    #[error("HTTP error: {0}")]
    LambdaHttpError(#[from] lambda_http::Error),
    #[error("HTTP builder error: {0}")]
    HttpBuilderError(#[from] http::Error),
    #[error("serde_json error")]
    SerdeJsonError(#[from] serde_json::Error),
    #[error("UTF8 convert error")]
    Utf8ConvertError(#[from] std::str::Utf8Error),
    #[error("base64 error")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("pasetos error")]
    PasetosError(#[from] pasetors::errors::Error),
}

pub struct ErrorCode {}

impl ErrorCode {
    pub fn status_code(error: &RouterError) -> u16 {
        match error {
            RouterError::NotFound(_) => 404,
            RouterError::Unauthenticated(_) => 401,
            RouterError::Unauthorized(_) => 403,
            RouterError::BadRequest(_) => 400,
            RouterError::DataExist(_) => 409,
            _ => 500,
        }
    }
}

// shortcut functions

pub fn not_found_error(msg: &str) -> RouterError {
    RouterError::NotFound(msg.to_owned())
}

pub fn data_exist(what: &str) -> RouterError {
    RouterError::DataExist(format!("`{}` already exist", what))
}

pub fn bad_request_error(msg: &str) -> RouterError {
    RouterError::BadRequest(msg.to_owned())
}

pub fn wrong_datatype(var_name: &str, mustbe_type: &str) -> RouterError {
    bad_request_error(&format!("`{}` must be of type `{}`", var_name, mustbe_type))
}

pub fn missing_parameter(param: &str, inwhat: &str) -> RouterError {
    RouterError::BadRequest(format!("Missing {} parameter `{}`", inwhat, param))
}

pub fn missing_query_param(param: &str) -> RouterError {
    missing_parameter(param, "query")
}

pub fn missing_path_param(param: &str) -> RouterError {
    missing_parameter(param, "path")
}

pub fn missing_body_field(field: &str) -> RouterError {
    RouterError::BadRequest(format!("Missing field `{}` in body", field))
}

pub fn missing_token_claim(claim: &str) -> RouterError {
    RouterError::BadRequest(format!("Missing claim `{}` in token", claim))
}

pub fn invalid_token(token_name: &str) -> RouterError {
    RouterError::BadRequest(format!("Invalid token `{}`", token_name))
}

pub fn unauthenticated_error(msg: &str) -> RouterError {
    RouterError::Unauthenticated(msg.to_string())
}

pub fn unauthorized_error(msg: &str) -> RouterError {
    RouterError::Unauthorized(msg.to_string())
}

pub fn internal_service_error(msg: &str) -> RouterError {
    RouterError::InternalService(msg.to_string())
}

pub fn internal_error<E: std::fmt::Display>(e: E) -> RouterError {
    RouterError::InternalService(e.to_string())
}
