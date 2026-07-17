use crate::output::preflight;

use super::{
    addons::AddonHolder,
    input::RouteHandlerInput,
    output::RouteHandlerOutput,
    types::{RouteHandler, RouteHandlerType},
};
use http::{Method, StatusCode};
use lambda_http::{Request, RequestExt, tracing};
use std::collections::HashMap;
use std::sync::Arc;

type RouteMapType = HashMap<&'static str, RouteHandlerType>;

pub struct Router {
    route_map: RouteMapType,
    addon_map: Arc<AddonHolder>,
}

impl Router {
    pub fn new(addons: AddonHolder) -> Self {
        Self {
            route_map: HashMap::new(),
            addon_map: Arc::new(addons),
        }
    }

    pub fn print_map(&self) {
        for (mpath, _) in &self.route_map {
            println!("{}", mpath);
        }
    }

    pub fn add_route(&mut self, mpath: &'static str, handler: Box<dyn RouteHandler>) {
        self.route_map.insert(mpath, handler);
    }

    pub async fn route(&self, request: Request) -> RouteHandlerOutput {
        let input = RouteHandlerInput::from_request(&request);

        let origin = request
            .headers()
            .get("origin")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("*");

        tracing::info!(
            "\n># Router(request).route(): method={}; origin={}\n>## input={:?}\n>## query parameters: {:?}\n>## path parameters: {:?}",
            request.method(), origin, input,
            request.query_string_parameters(),
            request.path_parameters()
        );

        match self.route_map.get(input.mpath.as_str()) {
            Some(handler) => {
                // tracing::info!("\n\tRoute matched...");
                match handler.handle(input, &self.addon_map).await {
                    Ok(output) => output.add_cors(origin),
                    Err(e) => {
                        tracing::warn!("\n>## Handler error: {:?}", e);
                        RouteHandlerOutput::from_error(&e).add_cors(origin)
                    }
                }
            }
            None if request.method() == Method::OPTIONS => {
                tracing::info!("\n>## OPTIONS return CORS");
                preflight(origin)
            }
            _ => {
                tracing::warn!("\n>## Handler not found for path {:?}", input.mpath);
                let msg = format!("Route for {} not found!", input.mpath);
                RouteHandlerOutput::new(StatusCode::FORBIDDEN, msg)
                    .add_cors(origin)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::addons::AddonHolder;
    use anyhow::Result;
    use http::Request;
    use lambda_http::{Body, RequestExt};
    use std::future::Future;
    use std::pin::Pin;

    struct MockHandler {
        status: StatusCode,
        body: String,
    }

    impl RouteHandler for MockHandler {
        fn handle<'a>(
            &self,
            _input: RouteHandlerInput,
            _addons: &'a AddonHolder,
        ) -> Pin<Box<dyn Future<Output = Result<RouteHandlerOutput>> + Send + 'a>> {
            let status = self.status;
            let body = self.body.clone();
            Box::pin(async move { Ok(RouteHandlerOutput::new(status, body)) })
        }
    }

    fn create_request(path: &str, method: Method) -> Request<Body> {
        let mut request = Request::builder()
            .method(method)
            .body(Body::Empty)
            .unwrap();
        *request.uri_mut() = path.parse().unwrap();
        request.with_raw_http_path(path)
    }

    #[tokio::test]
    async fn test_router_new() {
        let addons = AddonHolder::new();
        let router = Router::new(addons);
        assert!(router.route_map.is_empty());
    }

    #[tokio::test]
    async fn test_router_add_route() {
        let addons = AddonHolder::new();
        let mut router = Router::new(addons);

        let handler: Box<dyn RouteHandler> = Box::new(MockHandler {
            status: StatusCode::OK,
            body: "test".to_string(),
        });
        router.add_route("GET/test", handler);

        assert_eq!(router.route_map.len(), 1);
        assert!(router.route_map.contains_key("GET/test"));
    }

    #[tokio::test]
    async fn test_router_route_found() {
        let addons = AddonHolder::new();
        let mut router = Router::new(addons);

        let handler: Box<dyn RouteHandler> = Box::new(MockHandler {
            status: StatusCode::OK,
            body: "success".to_string(),
        });
        router.add_route("GET/hello", handler);

        let request = create_request("/hello", Method::GET);
        let response = router.route(request).await;

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, "success");
    }

    #[tokio::test]
    async fn test_router_route_not_found() {
        let addons = AddonHolder::new();
        let router = Router::new(addons);

        let request = create_request("/nonexistent", Method::GET);
        let response = router.route(request).await;

        assert_eq!(response.status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_router_preflight() {
        let addons = AddonHolder::new();
        let router = Router::new(addons);

        let mut request = create_request("/any", Method::OPTIONS);
        request.headers_mut().insert("origin", "https://example.com".parse().unwrap());

        let response = router.route(request).await;

        assert_eq!(response.status, StatusCode::OK);
        assert!(response.headers.is_some());
        let headers = response.headers.unwrap();
        assert!(headers.iter().any(|h| h.name == "access-control-allow-origin"));
    }
}
