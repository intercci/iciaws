use anyhow::Result;
use aws_lambda_events::query_map::QueryMap;
use http::{Method, StatusCode};
use iciaws_router::{
    addons::AddonHolder, input::RouteHandlerInput, output::RouteHandlerOutput, router::Router,
    types::RouteHandler,
};
use iciaws_macros::route;
use lambda_http::{Body, Request, RequestExt};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

#[route("GET/homes")]
pub fn get_homes(input: RouteHandlerInput, addons: &AddonHolder) -> Result<RouteHandlerOutput> {
    println!("Entered get_homes({:?})", input);
    let r =
        RouteHandlerOutput::message_output(StatusCode::OK, "get_homes() returns OK".to_string());
    Ok(r)
}

#[route("PUT/homes/{id}")]
pub fn update_home(input: RouteHandlerInput, addons: &AddonHolder) -> Result<RouteHandlerOutput> {
    println!("Entered update_home({:?})", input);
    let r =
        RouteHandlerOutput::message_output(StatusCode::OK, "update_home() returns OK".to_string());
    Ok(r)
}

#[tokio::main]
async fn main() {
    println!(
        "Test method-paths created by macros: {}, {}",
        GetHomesHandler::get_key(),
        UPDATEHOMEKEY
    );

    let addons = AddonHolder::new();
    let mut router = Router::new(addons);
    router.add_route(GetHomesHandler::get_key(), Box::new(GetHomesHandler));
    router.add_route(UpdateHomeHandler::get_key(), Box::new(UpdateHomeHandler));

    let req1 = Request::new(Body::Empty).with_raw_http_path("/homes");
    let res1 = router.route(req1).await;
    println!("1. {:?}", res1);

    let mut hm: HashMap<String, String> = HashMap::new();
    hm.insert("id".to_string(), "1234".to_string());

    let mut req2 = Request::new(Body::Empty)
        .with_raw_http_path("/homes/1234")
        .with_path_parameters(QueryMap::from(hm));
    *req2.method_mut() = Method::PUT;
    let res2 = router.route(req2).await;
    println!("2. {:?}", res2);
}
