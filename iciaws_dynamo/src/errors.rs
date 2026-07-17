use thiserror::Error;
use serde_dynamo;
use serde_json;
use base64;

#[derive(Error, Debug)]
pub enum DynamoError {
    #[error("UpdateExpression build error {0}")]
    BuildError(String),
    #[error("Missing Sort Key: {0}")]
    MissingSortKey(String),
    #[error("Delete Item error: {0}")]
    DeleteItem(String),
    #[error("serde_json error")]
    SerdeJsonError(#[from] serde_json::Error),
    #[error("serde_dynamo error")]
    SerdeDynamoError(#[from] serde_dynamo::Error),
    #[error("base64 error")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("UTF8 convert error")]
    Utf8ConvertError(#[from] std::str::Utf8Error),
    #[error("DynamoDB error: {0}")]
    DynDbError(String),
}
