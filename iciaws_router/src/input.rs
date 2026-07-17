#![allow(dead_code)]
use super::errors::{
    RouterError, bad_request_error, missing_body_field, missing_parameter, missing_path_param,
    missing_token_claim, unauthorized_error,
};
use super::tokens::Keys;
use aws_lambda_events::query_map::QueryMap;
use lambda_http::request::RequestContext;
use lambda_http::{Body, Request, RequestExt, tracing};
use pasetors::claims::Claims;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::LazyLock;

static PASETO_KEYS: LazyLock<Keys> = LazyLock::new(|| Keys::from_env().unwrap());

#[derive(Debug, Default)]
pub struct RouteHandlerInput {
    pub mpath: String,
    pub query: QueryMap,
    pub paths: QueryMap,
    pub claims: HashMap<String, Value>,
    pub body: Option<Value>,
    pub cookies: Option<HashMap<String, String>>, // added for rtk (refresh_token key)
    pub localhost: Option<bool>,  // true if local debugging
}

/// Get route_key from request context if available, else the raw_http_path
/// 
/// route_key example: "ANY /users/{uid}"
/// raw_http_path equivalent: "/stage/users/1234"
/// 
/// # Returns "/users/{uid}"
/// 
fn get_route_key(request: &Request) -> String {
    if let Some(req_ctx) = request.request_context_ref() {
        if let RequestContext::ApiGatewayV1(rcx) = req_ctx {
            // for REST API and local sam local start-api
            if let Some(rk) = &rcx.resource_path {
                return rk.to_owned();
            } else {
                tracing::warn!("No resource_path in request_context")
            }
            // return rcx.path.as_deref().unwrap_or("").to_owned();
        } else if let RequestContext::ApiGatewayV2(rcx) = req_ctx {
            if let Some(rk) = &rcx.route_key {
                // println!("\x1b[43m---route_key:{}---\x1b[0m", rk);
                let ss: Vec<&str> = rk.split(' ').collect();
                // println!("\x1b[46m---ss:{:?}---\x1b[0m", ss);
                if ss.len() > 1 {
                    return ss[1].to_owned();
                } else {
                    tracing::error!("RequestContext.route_key error: '{}'", rk);
                }
            } else {
                tracing::warn!("No route_key found in request context, use raw_http_path instead!");
            }
        }
    }
    request.raw_http_path().to_owned()
}

/// Merge method and real path (without stage) as one string.
/// 
/// The route_key example: "ANY /users/{uid}" where raw path = "/stage/users/1234"
/// 
/// # Return "GET/users/{uid}" (and 1234 should be in path_parameters)
/// 
fn get_method_path(request: &Request) -> String {
    let route_key = get_route_key(request);
    format!("{}{}", request.method(), route_key)
}

/// Get requestContext.authorizer.lambda as Map<String, serde_json::Value>
fn get_claims(request: &Request) -> HashMap<String, Value> {
    if let Some(rc) = request.request_context_ref() {
        // tracing::info!("\n>> iciaws_router.input.get_claims(): request_context: {:?}", rc);
        if let Some(au) = rc.authorizer() {
            tracing::info!("rc.autorizer: {:?}", au);
            // if let Some(lambda) = au.lambda {
            //     return lambda.as_object().unwrap().to_owned();
            // } else
            if let Some(_uid) = au.fields.get("uid") {
                return au.fields.to_owned();
            } else {
                tracing::warn!("No fields in request_context.authorizer!")
            }
        } else {
            tracing::warn!("No autorizer in request_context: {:?}", rc);
        }
    } else {
        tracing::warn!("No request_context!")
    }
    HashMap::new()
}

/// Get body as serde_json::Value which could be an array or object. None if body missing or invalid
fn get_body_value(request: &Request) -> Option<Value> {
    match request.body() {
        Body::Text(bs) => serde_json::from_str(bs).ok(),
        _ => None,
    }
}

/// Get a cookie string by cookie name, eg rtk=...
/// Multiple cookies may exist separated by semicolon, and cookie name and value are separated by =
fn get_cookies(request: &Request) -> Option<HashMap<String, String>> {
    let cookies = request.headers().get("cookie")?;
    let cs = cookies.to_str().ok()?;
    let cks: HashMap<String, String> = cs
        .split(';')
        .filter_map(|s| {
            let mut parts = s.splitn(2, '=');
            let name = parts.next()?.split_ascii_whitespace().collect::<String>();
            parts.next().map(|value| (name, value.to_string()))
        })
        .collect();

    if cks.is_empty() {
        tracing::warn!("\n>>> input.get_cookies found No cookies");
        None
    } else {
        tracing::info!("\n>>> input.get_cookies found: {:?}", cks);
        Some(cks)
    }
}

/// Parse PASETOS token to get sub as uid, aud as appid, and role to save in claims.
///
/// # Arguments
///
/// * jwt - PASETOS token string
/// * claims - the hash map to save the parsed uid, appid, and role
///
/// # Returns the updated claims
///
fn parse_jwt_for_claims(jwt: &str, mut claims: HashMap<String, Value>) -> HashMap<String, Value> {
    let k = &PASETO_KEYS;
    let token_claims: Result<Claims, RouterError> = k.verify_token(jwt);
    if let Ok(tclaims) = token_claims {
        if let Some(uid) = tclaims.get_claim("sub") {
            claims.insert("uid".to_string(), uid.to_owned());
        }
        if let Some(aud) = tclaims.get_claim("aud") {
            claims.insert("appid".to_string(), aud.to_owned());
        }
        if let Some(role) = tclaims.get_claim("role") {
            claims.insert("role".to_string(), role.to_owned());
        }
    }
    claims
}

impl RouteHandlerInput {
    pub fn from_request(request: &Request) -> Self {
        tracing::info!("\n>> from_request({:?})", request);
        let mut rclaims = get_claims(request);
        let rcookies = get_cookies(request);
        if let Some(ref cookies) = rcookies {
            if let Some(jwt) = cookies.get("jwt") {
                rclaims = parse_jwt_for_claims(jwt, rclaims);
            }
        }
        tracing::info!("\n>># parsed claims: {:?}", rclaims);
        let is_localhost: Option<bool> = request.uri().host().map(|h| h.eq("localhost"));
        Self {
            mpath: get_method_path(request),
            query: request.query_string_parameters(),
            paths: request.path_parameters(),
            claims: rclaims,
            body: get_body_value(request),
            cookies: rcookies,
            localhost: is_localhost,
        }
    }

    pub fn get_body_prop_as_str(&self, attr_name: &str) -> Option<&str> {
        self.body.as_ref().and_then(|b| b.get(attr_name)).and_then(Value::as_str)
    }

    pub fn get_optional_body_prop(&self, property_name: &str) -> Option<String> {
        self.body
            .as_ref()
            .and_then(|b| b.get(property_name))
            .and_then(Value::as_str)
            .map(str::to_string)
    }

    pub fn get_required_body_prop(&self, property_name: &str) -> Result<&Value, RouterError> {
        if let Some(b) = &self.body {
            if let Some(v) = b.get(property_name) {
                return Ok(v);
            }
        }
        Err(missing_body_field(property_name))
    }

    pub fn get_required_body_prop_as_str(&self, property_name: &str) -> Result<&str, RouterError> {
        let v = self.get_required_body_prop(property_name)?;
        // println!("\x1b[41mBody[{}]={:?}\x1b[0m", property_name, v);
        if let Some(vs) = v.as_str() {
            Ok(vs)
        } else {
            Err(missing_body_field(property_name))
        }
    }

    pub fn get_body_or_error(&self) -> Result<&Value, RouterError> {
        self.body.as_ref().ok_or_else(|| bad_request_error("Missing body"))
    }

    /// Get a value as Result<String> from a QueryMap by a key.
    pub fn get_value(
        &self,
        query: &QueryMap,
        key: &str,
        inwhat: &str,
    ) -> Result<String, RouterError> {
        query
            .all(key)
            .and_then(|vals| vals.first().map(|k| k.to_string()))
            .ok_or_else(|| missing_parameter(key, inwhat))
    }

    pub fn get_query_value(&self, key: &str) -> Result<String, RouterError> {
        self.get_value(&self.query, key, "query")
    }

    pub fn get_path_value(&self, key: &str) -> Result<String, RouterError> {
        self.get_value(&self.paths, key, "path")
    }

    pub fn get_claim(&self, key: &str) -> Result<String, RouterError> {
        self.claims
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| missing_token_claim(key))
    }

    pub fn get_cookie(&self, key: &str) -> Option<&String> {
        match &self.cookies {
            Some(cs) => cs.get(key),
            None => None,
        }
    }

    /// Check uid in claims equals uid or hid on path
    pub fn its_my_path(&self, path_id: &str) -> Result<String, RouterError> {
        let path_uid = match self.get_path_value(path_id) {
            Ok(uid) => uid,
            Err(_) => match self.get_path_value("hid") {
                Ok(pid) => pid,
                Err(_) => {
                    return Err(missing_path_param("uid or hid"));
                }
            },
        };
        // println!("\x1b[42m{:?}\x1b[0m", self);
        if let Some(true) = self.localhost {
            return Ok(path_uid);
        }
        let claim_uid = self.get_claim("uid")?;
        if path_uid == claim_uid {
            Ok(path_uid)
        } else {
            Err(unauthorized_error("/{uid} not mine"))
        }
    }

    pub fn i_am_owner(&self) -> bool {
        match self.its_my_path("uid") {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    /// Return true if my role matches the specified one (exact string match)
    ///
    /// # Parameters
    ///
    /// * role - role string for exact match
    ///
    /// # Returns
    ///
    /// * true if the role exists in the JWT claims and matches
    pub fn am_i_a(&self, role: &str) -> bool {
        match self.get_claim("role") {
            Ok(r) => r.eq(role),
            Err(_) => false,
        }
    }

    /// Throws error if jwt has no 'role' claim or no matches found.
    ///
    /// # Parameters
    ///
    /// * role - role string for exact match
    ///
    /// # Returns
    ///
    /// Ok(()) or Unauthorized error
    pub fn i_am_a(&self, role: &str) -> Result<(), RouterError> {
        match self.get_claim("role") {
            Ok(r) if r.eq(role) => Ok(()),
            _ => Err(unauthorized_error("Unauthorized role").into()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use http::Request;
use serde_json::json;
    use aws_lambda_events::apigw::ApiGatewayV2httpRequestContext;

    #[test]
    fn test_get_method_path() {
        let mut hm: HashMap<String, String> = HashMap::new();
        hm.insert("uid".to_string(), "1234".to_string());
        hm.insert("bid".to_string(), "abcd".to_string());
        let mut ctx = ApiGatewayV2httpRequestContext::default();
        ctx.route_key = Some("ANY /blog/{uid}/{aid}".to_owned());

        let request = Request::new(Body::Empty)
            .with_raw_http_path("/stage/blog/1234/abcd")
            .with_request_context(RequestContext::ApiGatewayV2(ctx))
            .with_path_parameters(QueryMap::from(hm));
        // *request.method_mut() = Method::GET;
        let s = get_method_path(&request);
        assert_eq!(s, "GET/blog/{uid}/{aid}".to_string());
        // route_key test
    }

    #[test]
    fn test_get_claims() {
        let mut auth = aws_lambda_events::event::apigw::ApiGatewayRequestAuthorizer::default();
        auth.fields
            .insert("uid".to_string(), Value::String("1234".to_string()));

        let mut actx = aws_lambda_events::event::apigw::ApiGatewayV2httpRequestContext::default();
        actx.authorizer = Some(auth);

        let context = lambda_http::request::RequestContext::ApiGatewayV2(actx);
        let request = Request::new(Body::Empty).with_request_context(context);

        let claims = get_claims(&request);
        assert_eq!(
            claims.get("uid").unwrap(),
            &Value::String("1234".to_string())
        );
    }

    #[test]
    fn test_get_body_props() {
        let mut r = RouteHandlerInput::default();
        let v = json!({"name":"Name","age":25_u32});
        r.body = Some(v);
        assert_eq!(r.get_body_prop_as_str("name"), Some("Name"));
        assert_eq!(r.get_required_body_prop_as_str("name").unwrap(), "Name");
        assert_eq!(r.get_optional_body_prop("no"), None);
        assert_eq!(r.get_required_body_prop("age").unwrap(), &json!(25));
        if let Ok(_) = r.get_required_body_prop("no") {
            assert!(false, "should return error");
        }
    }

    #[test]
    fn test_get_query_props() {
        let mut r = RouteHandlerInput::default();
        let mut hm: HashMap<String, String> = HashMap::new();
        hm.insert("uid".to_string(), "123".to_string());
        hm.insert("bid".to_string(), "abc".to_string());
        r.query = QueryMap::from(hm);
        assert_eq!(r.get_query_value("uid").unwrap(), "123");
        assert_eq!(r.get_query_value("bid").unwrap(), "abc");
    }

    #[test]
    fn test_get_path_props() {
        let mut r = RouteHandlerInput::default();
        let mut hm: HashMap<String, String> = HashMap::new();
        hm.insert("uid".to_string(), "123".to_string());
        hm.insert("bid".to_string(), "abc".to_string());
        r.paths = QueryMap::from(hm);
        assert_eq!(r.get_path_value("uid").unwrap(), "123");
        assert_eq!(r.get_path_value("bid").unwrap(), "abc");
    }

    #[test]
    fn test_get_claim() {
        let mut r = RouteHandlerInput::default();
        let mut hm: HashMap<String, Value> = HashMap::new();
        hm.insert("uid".to_string(), json!("123".to_string()));
        r.claims = hm;
        assert_eq!(r.get_claim("uid").unwrap(), "123");
    }

    #[test]
    fn test_get_body_value() {
        // let mut ctx = ApiGatewayV2httpRequestContext::default();
        // ctx.route_key = Some("ANY /blog/{uid}/{aid}".to_owned());

        let body_text = "{\r\n  \"email\": \"qywen@hotmail.com\",\r\n  \"password\": \"1234\",\r\n  \"appid\": \"ici_email\",\r\n\t\"role\": \"admin\"\r\n}";
        // let body_text = "{ \"email\": \"qywen@hotmail.com\",\r\n  \"appid\": \"ici_email\"}";
        let request = Request::new(Body::Text(body_text.to_string()))
            .with_raw_http_path("/users");

            if let Some(body) = get_body_value(&request) {
            // check body content
            assert_eq!(body["email"].as_str(), Some("qywen@hotmail.com"));
            assert_eq!(body["appid"].as_str(), Some("ici_email"));
        } else {
            assert!(false, "{}", "get_body_value returned None");
        };
    }

    #[test]
    fn test_from_request() {
        let body_text = "{\r\n  \"email\": \"qywen@hotmail.com\",\r\n  \"password\": \"1234\",\r\n  \"appid\": \"ici_email\",\r\n\t\"role\": \"admin\"\r\n}";
        let request = Request::new(Body::Text(body_text.to_string())).with_raw_http_path("/users");
        let ri = RouteHandlerInput::from_request(&request);
        let pe = ri.get_required_body_prop("email");
        assert!(pe.is_ok());
        assert_eq!(pe.unwrap().as_str(), Some("qywen@hotmail.com"));
        let pa = ri.get_required_body_prop_as_str("appid");
        assert_eq!(pa.unwrap(), "ici_email");
    }
}
