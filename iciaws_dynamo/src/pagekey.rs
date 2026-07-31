use serde_dynamo;
use serde_json;
use std::collections::HashMap;
use super::errors::DynamoError;
use aws_sdk_dynamodb::types::AttributeValue;
use base64::{engine::general_purpose::URL_SAFE, Engine as _};

/// Convert a item key into a JSON string and then encode it in base64 for URL passing
/// 
/// # Arguments
/// 
/// * last_evaluated_key: HashMap<String, AttributeValue> - from DynamoDB query
/// 
/// # Returns base64(jsonize(last_evaluated_key)) or error
/// 
pub fn last_evaluated_key_to_base64(last_evaluated_key: HashMap<String, AttributeValue>) -> Result<String, DynamoError> {
    let jsv: serde_json::Value = serde_dynamo::from_item(last_evaluated_key)
        .map_err(DynamoError::from)?;
    let js = serde_json::to_string(&jsv)?;
    // println!("    to_base64, json:{}", js);
    Ok(URL_SAFE.encode(js.as_bytes()))
}

/// Convert a base64-encoded JSON string back to an item key.
/// 
/// # Arguments
/// 
/// * last_evaluated_key_b64: JSON key string encoded with base64
/// 
/// # Returns item key of HashMap<String, AttributeValue> or DynamoError
/// 
pub fn base64_to_exclusive_start_key(last_evaluated_key_b64: &str) -> Result<HashMap<String, AttributeValue>, DynamoError> {
    let decodedu8 = URL_SAFE.decode(last_evaluated_key_b64)?;
    let sv: serde_json::Value = serde_json::from_str(std::str::from_utf8(&decodedu8)?)?;
    let m: HashMap<String, AttributeValue> = serde_dynamo::to_item(sv)?;
    Ok(m)
}

pub fn make_start_key(last_key_b64: Option<String>) -> Option<HashMap<String, AttributeValue>> {
    match last_key_b64.as_deref() {
        Some(s) => base64_to_exclusive_start_key(s).ok(),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convertion() {
        let v: HashMap<String, AttributeValue> = HashMap::from([
                ("first_name".to_string(), AttributeValue::S("Admon".to_string())),
                ("last_name".to_string(), AttributeValue::S("Smith".to_string())),
            ]);
        println!("v = {:?}", v);
        let b64 = last_evaluated_key_to_base64(v.clone()).unwrap();
        println!("b64={}", b64);
        let v2 = base64_to_exclusive_start_key(&b64).unwrap();
        println!("back v2={:?}", v2);
        assert_eq!(v, v2);
    }
}
