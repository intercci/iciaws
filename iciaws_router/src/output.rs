#![allow(dead_code)]
use std::collections::HashMap;

use super::errors::{ErrorCode, RouterError};
use http::StatusCode;
use lambda_http::tracing;
use serde::Serialize;
use serde_json::{Value, json, to_string};
use anyhow::Result;

#[derive(Debug, Default, Clone)]
pub struct HeaderEntry {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Default)]
pub struct RouteHandlerOutput {
    pub status: StatusCode,
    pub body: String,
    pub headers: Option<Vec<HeaderEntry>>,
    pub cookies: Option<Vec<String>>,
}

pub fn gen_cors_hdrs(origin: &str) -> Vec<HeaderEntry> {
    vec![
        HeaderEntry{name: "access-control-allow-origin".to_string(), value: origin.to_string()},
        HeaderEntry{name: "access-control-allow-headers".to_string(), value: "Content-Type,Authorization".to_string()},
        HeaderEntry{name: "access-control-allow-methods".to_string(), value: "OPTIONS,POST,GET,PUT,DELETE".to_string()},
        HeaderEntry{name: "access-control-allow-credentials".to_string(), value: "true".to_string()},
    ]
}

impl RouteHandlerOutput {
    pub fn new(status: StatusCode, data_str: String) -> Self {
        Self {
            status: status,
            body: data_str,
            headers: None,
            cookies: None,
        }
    }

    pub fn from_error(error: &anyhow::Error) -> Self {
        let scode = error.downcast_ref::<RouterError>()
            .map(ErrorCode::status_code)
            .unwrap_or(500);

        Self::new(
            StatusCode::from_u16(scode).unwrap(),
            format!(r#"{{"status":"Fail","message":"{error}"}}"#),
        )
    }

    pub fn message_output(status: StatusCode, message: impl Into<String>) -> Self {
        let msg: String = message.into();
        if msg.starts_with("{") {
            return RouteHandlerOutput::new(status, msg);
        }
        let sts = if status.is_success() {
            "OK".to_string()
        } else {
            "Fail".to_string()
        };
        let bs = format!(r#"{{"status":"{}","message":"{}"}}"#, sts, msg);
        Self::new(status, bs)
    }

    pub fn json_output(status: StatusCode, data: Value) -> Self {
        let obs = serde_json::to_string(&data);
        match obs {
            Ok(s) => Self::new(status, s),
            Err(e) => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(r#"{{"status":"Fail","message":"{:?}"}}"#, e),
            ),
        }
    }

    pub fn add_cors(mut self, origin: &str) -> Self {
        let mut cors_hdrs = gen_cors_hdrs(origin);
        if let Some(ref mut hds) = self.headers {
            hds.append(&mut cors_hdrs);
        } else {
            self.headers = Some(cors_hdrs);
        }
        tracing::info!("\n>## RouteHandlerOutput.add_cors(origin={}), headers:{:?}", origin, self.headers);
        self
    }
}

pub fn ok_json(js: String) -> RouteHandlerOutput {
    RouteHandlerOutput::new(StatusCode::OK, js)
}

pub fn ok_output<T: Serialize>(item_name: &str, field_name: &str, item: T) -> Result<RouteHandlerOutput> {
    let rd = json!({
        "status": "OK",
        "name": item_name,
        field_name: item,
    });
    let r = RouteHandlerOutput::new(StatusCode::OK, to_string(&rd)?);
    Ok(r)
}

pub fn get_ok<T: Serialize>(item_name: &str, item: T) -> Result<RouteHandlerOutput> {
    ok_output(item_name, "item", item)
}

pub fn get_failed(item_name: &str) -> Result<RouteHandlerOutput> {
    let rd = json!({
        "status": "Fail",
        "message": format!("{} not found", item_name),
    });
    let r = RouteHandlerOutput::new(StatusCode::OK, to_string(&rd)?);
    Ok(r)
}

pub fn query_ok<T: Serialize>(item_name: &str, items: T) -> Result<RouteHandlerOutput> {
    ok_output(item_name, "items", items)
}

pub fn query_page_ok<T: Serialize>(item_name: &str, items: T, last: Option<String>) -> Result<RouteHandlerOutput> {
    let rd = json!({
        "status": "OK",
        "name": item_name,
        "last": last,
        "items": items,
    });
    let r = RouteHandlerOutput::new(StatusCode::OK, to_string(&rd)?);
    Ok(r)
}

pub fn item_created(item_name: &str, id_name: &str, id_val: &str) -> Result<RouteHandlerOutput> {
    let rd = json!({
        "status": "OK",
        "name": item_name,
        "message": format!("{} created", item_name),
        id_name: id_val,
    });
    let r = RouteHandlerOutput::new(StatusCode::CREATED, to_string(&rd)?);
    Ok(r)
}

pub fn ok_with_message(item_name: &str, message: &str) -> Result<RouteHandlerOutput> {
    let rd = json!({
        "status": "OK",
        "name": item_name,
        "message": message,
    });
    let r = RouteHandlerOutput::new(StatusCode::OK, to_string(&rd)?);
    Ok(r)
}

pub fn fail_with_message(item_name: &str, message: &str) -> Result<RouteHandlerOutput> {
    let rd = json!({
        "status": "Fail",
        "name": item_name,
        "message": message,
    });
    let r = RouteHandlerOutput::new(StatusCode::OK, to_string(&rd)?);
    Ok(r)
}

pub fn ok_with_extra(item_name: &str, extra: HashMap<String, Value>) -> Result<RouteHandlerOutput> {
    let mut rd = json!({
        "status": "OK",
        "name": item_name,
    });
    if let Some(d) = rd.as_object_mut() {
        d.extend(extra);
    }
    let r = RouteHandlerOutput::new(StatusCode::OK, to_string(&rd)?);
    Ok(r)
}

pub fn ok_with_items_extra<T: Serialize>(item_name: &str, items: T, extra: HashMap<String, Value>) -> Result<RouteHandlerOutput> {
    let mut rd = json!({
        "status": "OK",
        "name": item_name,
        "items": items,
    });
    if let Some(d) = rd.as_object_mut() {
        d.extend(extra);
    }
    let r = RouteHandlerOutput::new(StatusCode::OK, to_string(&rd)?);
    Ok(r)
}

pub fn item_updated(item_name: &str) -> Result<RouteHandlerOutput> {
    ok_with_message(item_name, &format!("{} updated", item_name))
}

pub fn item_deleted(item_name: &str) -> Result<RouteHandlerOutput> {
    let rd = json!({
        "status": "OK",
        "name": item_name,
        "message": format!("{} deleted", item_name),
    });
    let r = RouteHandlerOutput::new(StatusCode::NO_CONTENT, to_string(&rd)?); // status 204
    Ok(r)
}

pub fn ok_with_headers(js: String, hdrs: Vec<HeaderEntry>) -> RouteHandlerOutput {
    RouteHandlerOutput {
        status: StatusCode::OK,
        body: js,
        headers: Some(hdrs),
        cookies: None,
    }
}

pub fn preflight(origin: &str) -> RouteHandlerOutput {
    RouteHandlerOutput {
        status: StatusCode::OK,
        body: "".to_string(),
        headers: Some(gen_cors_hdrs(origin)),
        cookies: None,
    }
}

pub fn ok_with_tokens_by_cookie(
    js: String,
    jwt: &str,
    rtk: &str,
    domain: Option<&str>,
) -> RouteHandlerOutput {
    let coos = match domain {
        Some(ds) => {
            vec![
                format!(
                    "jwt={}; HttpOnly; Secure; Domain={}; Path=/; SameSite=Lax",
                    jwt, ds
                ),
                format!(
                    "rtk={}; HttpOnly; Secure; Domain={}; Path=/; SameSite=Lax",
                    rtk, ds
                ),
            ]
        }
        None => {
            vec![format!("jwt={}", jwt), format!("rtk={}", rtk)]
        }
    };
    RouteHandlerOutput {
        status: StatusCode::OK,
        body: js,
        headers: None,
        cookies: Some(coos),
    }
}

impl TryFrom<RouteHandlerOutput> for lambda_http::Response<lambda_http::Body> {
    type Error = RouterError;
    fn try_from(value: RouteHandlerOutput) -> Result<Self, RouterError> {
        let mut b = lambda_http::Response::builder()
            .status(value.status)
            .header("content-type", "application/json");
        if let Some(coos) = value.cookies {
            let hdr = b.headers_mut().unwrap();
            for coo in coos.iter() {
                hdr.append("set-cookie", coo.parse().unwrap());
            }
        }
        if let Some(hdrs) = value.headers {
            let hdr = b.headers_mut().unwrap();
            for hd in hdrs.iter() {
                hdr.append(
                    hd.name.parse::<http::HeaderName>().unwrap(),
                    hd.value.parse::<http::HeaderValue>().unwrap(),
                );
            }
        }
        let r = b.body(value.body.into()).map_err(RouterError::from)?;
        Ok(r)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use http::StatusCode;

    #[test]
    fn test_add_cors_new_headers() {
        let output = RouteHandlerOutput::new(StatusCode::OK, "test".to_string());
        let output = output.add_cors("https://example.com");

        let headers = output.headers.expect("headers should be present");
        assert_eq!(headers.len(), 4);
        assert!(headers.iter().any(|h| h.name == "access-control-allow-origin"));
        assert!(headers.iter().any(|h| h.value == "https://example.com"));
        assert!(headers.iter().any(|h| h.name == "access-control-allow-credentials" && h.value == "true"));
    }

    #[test]
    fn test_add_cors_existing_headers() {
        let mut output = RouteHandlerOutput::new(StatusCode::OK, "test".to_string());
        output.headers = Some(vec![HeaderEntry {
            name: "x-custom".to_string(),
            value: "custom-value".to_string(),
        }]);

        let output = output.add_cors("https://example.com");

        let headers = output.headers.expect("headers should be present");
        assert_eq!(headers.len(), 5);
        assert!(headers.iter().any(|h| h.name == "x-custom" && h.value == "custom-value"));
        assert!(headers.iter().any(|h| h.name == "access-control-allow-origin"));
    }
}
