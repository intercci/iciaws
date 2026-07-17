#![allow(dead_code)]
// use crate::routes::add_routes;
use anyhow::{Result, anyhow};
use aws_sdk_dynamodb::{error::DisplayErrorContext, types::AttributeValue};
use iciaws_dynamo::{DynamoClient, get_dynamo_client};
use http::{Request, Response};
use iciaws_router::{addons::AddonHolder, router::Router};
use lambda_http::{
    Body, RequestExt, aws_lambda_events::apigw::ApiGatewayV2httpRequestContext,
    request::RequestContext,
};
use regex::Regex;
use iciaws_s3::get_s3_client;
use serde_dynamo;
use serde_json::{Value, json};
use iciaws_ses::get_ses_client;
use iciaws_sns::get_sns_client;
use std::collections::HashMap;

/// Create a router with DynamoClient injected, this should work with a local DynamoDB instance running.
pub async fn create_router(tablename: &str) -> Router {
    let dynamo_client = get_dynamo_client(Some(tablename)).await;
    let addon_map = AddonHolder::new();
    addon_map.put_addon("dynamo", dynamo_client);
    let router = Router::new(addon_map);
    // add_routes(&mut router); // call this in the caller fn after return
    router
}

/// Create a router with s3, ses, sns etc attached
/// # Arguments:
/// * tablename -
/// * other_services - string separated by commas, like "ses,s3,sns" (no spaces)
pub async fn create_router_extra(tablename: &str, other_services: &str) -> Router {
    let dynamo_client = get_dynamo_client(Some(tablename)).await;
    let addon_map = AddonHolder::new();
    addon_map.put_addon("dynamo", dynamo_client);
    for s in other_services.split(',').into_iter() {
        match s {
            "ses" => {
                let ses = get_ses_client().await;
                addon_map.put_addon("ses", ses);
            }
            "s3" => {
                let s3 = get_s3_client().await;
                addon_map.put_addon("s3", s3);
            }
            "sns" => {
                let sns = get_sns_client().await;
                addon_map.put_addon("sns", sns);
            }
            _ => (),
        }
    }
    let router = Router::new(addon_map);
    router
}

#[derive(Debug)]
pub struct StatusValue {
    pub status: http::StatusCode,
    pub value: Value,
}

/// Call router.route(req) to return serde_json::Value as the response json
pub async fn call_router(router: &Router, req: Request<Body>) -> Result<StatusValue> {
    println!("\x1b[91mCall router with {:?}\x1b[0m", req);
    let result = router.route(req).await;
    println!("\x1b[92m result = {:?}\x1b[0m", result);
    let resp: Response<Body> = match result.try_into() {
        Ok(r) => r,
        Err(e) => {
            print_bg(
                &format!("match result error: {}", DisplayErrorContext(&e)),
                "red",
            );
            return Err(e.into());
        }
    };
    if resp.status().as_u16() > 299 {
        print_fg(
            &format!("status={}, body={:?}", resp.status(), resp.body()),
            "blue",
        );
    }
    println!("\x1b[93mStatus:{}\x1b[0m", resp.status());
    // assert_eq!(resp.status(), 200);
    let body_bytes = resp.body().to_vec();
    let body_string = String::from_utf8(body_bytes)?;
    println!("\x1b[46m result = {:?}\x1b[0m", body_string);
    let body: serde_json::Value = match serde_json::from_str(&body_string) {
        Ok(v) => v,
        Err(e) => {
            print_bg(
                &format!("serde_json::from_str error: {}", DisplayErrorContext(&e)),
                "red",
            );
            print_bg(&body_string, "yellow");
            return Err(e.into());
        }
    };
    let result = StatusValue {
        status: resp.status(),
        value: body,
    };
    Ok(result)
}

///
/// # Example:
///
/// ```rust,ignore
/// let req = create_request(http::Method::GET, "/apps/{appid:a35}/roles/{rid:34}?param=...&param2=...", "1234", "app", None);
///
/// ```
pub fn create_request(
    method: http::Method,
    raw_path: &str,
    uid: &str,
    role: &str,
    body: Option<Value>,
) -> Request<Body> {
    let bd = match body {
        Some(bod) => {
            let bs = serde_json::to_string(&bod).unwrap();
            Body::Text(bs)
        }
        None => Body::Empty,
    };

    // Define your authorizer claims
    let mut auth_fields: HashMap<String, Value> = HashMap::new();
    auth_fields.insert("uid".to_string(), json!(uid));
    auth_fields.insert("role".to_string(), json!(role));

    // Create the Context (API Gateway V2 is the modern standard)
    let mut context_v2 = ApiGatewayV2httpRequestContext::default();
    context_v2.authorizer = Some(
        serde_json::from_value(json!({
            "lambda": auth_fields
        }))
        .unwrap(),
    );

    let mut query_params = HashMap::new();
    let path1 = if raw_path.contains('?') {
        let ps: Vec<&str> = raw_path.splitn(2, '?').collect();
        let qs: Vec<&str> = ps[1].split('&').collect();
        for q in qs {
            let ss: Vec<&str> = q.splitn(2, '=').collect();
            query_params.insert(ss[0].to_string(), ss[1].to_string());
        }
        ps[0]
    } else {
        raw_path
    };

    let mut path_params = HashMap::new();
    let path2 = if path1.contains('{') {
        let re = Regex::new(r"\{(?P<key>[^:]+):(?P<val>[^}]+)\}").unwrap();
        for cap in re.captures_iter(path1) {
            path_params.insert(cap["key"].to_string(), cap["val"].to_string());
        }
        let path2 = re.replace_all(path1, "$val").into_owned();
        let rk = re.replace_all(path1, "{$key}").into_owned();
        context_v2.route_key = Some(format!("ANY {}", rk));
        // println!("\x1b[94m----------{}  => {}----{}----\x1b[0m]", path1, path2, rk);
        path2
    } else {
        context_v2.route_key = Some(format!("ANY {}", path1));
        path1.to_string()
    };
    // println!("\x1b[94mPath={}; Params={:?}\x1b[0m", path2, path_params);

    // Build the base request
    let req = Request::builder()
        .uri(&path2)
        .method(method)
        .header("content-type", "application/json")
        .body(bd)
        .unwrap();
    // println!("\x1b[96m req={:?}\x1b[0m", req);

    // Assemble the request with the mock context
    let request = req
        .with_raw_http_path(&path2)
        .with_query_string_parameters(query_params)
        .with_path_parameters(path_params)
        .with_request_context(RequestContext::ApiGatewayV2(context_v2));
    // println!("\x1b[93m request={:?}\x1b[0m", request);

    // Verification
    // let claims = request.request_context();
    // println!("\x1b[6;30;41mRequest created with claims: {:?}\nPath params: {:?}\x1b[0m", claims, request.path_parameters());

    request
}

/// shortcut for create_request(GET)
pub fn create_get(raw_path: &str) -> Request<Body> {
    create_request(http::Method::GET, raw_path, "1234", "", None)
}

/// shortcut for create_request(POST)
pub fn create_post(raw_path: &str, body: Value) -> Request<Body> {
    create_request(http::Method::POST, raw_path, "1234", "", Some(body))
}

/// shortcut for create_request(PUT)
pub fn create_put(raw_path: &str, body: Value) -> Request<Body> {
    create_request(http::Method::PUT, raw_path, "1234", "", Some(body))
}

/// shortcut for create_request(DELETE)
pub fn create_delete(raw_path: &str) -> Request<Body> {
    create_request(http::Method::DELETE, raw_path, "1234", "", None)
}

// dynamodb get shortcut
pub async fn get_dynamo_item(
    dynamo: &DynamoClient,
    pk: &str,
    sk: &str,
    tablename: Option<&str>,
) -> Result<HashMap<String, AttributeValue>> {
    let go = dynamo.get_by_pksk(pk, sk, tablename).await?;
    match go.item {
        Some(item) => Ok(item),
        None => Err(anyhow!("Not found")),
    }
}

pub async fn create_dynamo_item(dynamo: &DynamoClient, item: serde_json::Value) -> Result<()> {
    let pitem: HashMap<String, AttributeValue> = serde_dynamo::to_item(item)?;
    let _d = dynamo.put(pitem, None).await?;
    Ok(())
}

pub async fn delete_dynamo_item(
    dynamo: &DynamoClient,
    pk: &str,
    sk: &str,
    tablename: Option<&str>,
) -> Result<()> {
    let _ = dynamo.delete_by_pksk(pk, sk, tablename).await?;
    Ok(())
}

/// color terminal
const CCODES: [&str; 8] = [
    "black", "red", "green", "yellow", "blue", "magenta", "cyan", "white",
];

/// Print string with colours on terminal
pub fn colorit(s: &dyn std::fmt::Display, c: &str, bg: bool) -> String {
    let cn = CCODES.iter().position(|s| s.eq_ignore_ascii_case(c)).unwrap_or(0);
    let dn = if bg { 40 } else { 30 };
    format!("\x1b[{}]{}\x1b[0m", dn + cn, s)
}

pub fn fmt_fg(s: &dyn std::fmt::Display, fgc: &str) -> String {
    colorit(s, fgc, false)
}

pub fn fmt_bg(s: &dyn std::fmt::Display, bgc: &str) -> String {
    colorit(s, bgc, true)
}

pub fn print_fg(s: &dyn std::fmt::Display, fgc: &str) {
    println!("{}", colorit(s, fgc, false));
}

pub fn print_bg(s: &dyn std::fmt::Display, bgc: &str) {
    println!("{}", colorit(s, bgc, true));
}

pub fn fmt_error(s: &dyn std::fmt::Display) -> String {
    colorit(s, "red", true)
}

pub fn fmt_ok(s: &dyn std::fmt::Display) -> String {
    colorit(s, "green", true)
}

pub fn fmt_warn(s: &dyn std::fmt::Display) -> String {
    colorit(s, "yellow", true)
}

pub fn fmt_info(s: &dyn std::fmt::Display) -> String {
    colorit(s, "blue", true)
}

pub fn fmt_notice(s: &dyn std::fmt::Display) -> String {
    colorit(s, "cyan", true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_colorit() {
        // assert_eq!(colorit("OK", "red", true), "\x1b[41mOK\x1b[0m".to_string());
        // assert_eq!(colorit("OK", "green", true), "\x1b[32mOK\x1b[0m".to_string());
    }
}
