# Lamb-Route

A light-weight router crate for AWS Lambda functions.

## Features

- Provides a simple routing mechanism

## Import

```sh
cargo add iciaws_router --git https://github.com/intercci/iciawsaid.git
```

- import the macro

```sh
cargo add iciaws_macros --git https://github.com/intercci/iciawsaid.git --package iciaws_macros
```

## Strategy

### Do not use {proxy+}

As this article [How you should - and should not - use API Gateway Proxy Integration With Lambda](https://ben11kehoe.medium.com/how-you-should-and-should-not-use-the-api-gateway-proxy-integration-f9e35479b993) puts it, the {proxy+} integration can be costly, insecure and less self-documenting. We agree not to waste the features of API Gateway, so our **lambrouter** only allows specific routes that are passed on to the lambda function. To make the route building easier, we use scripts or AI agents to generate the OpenAPI schema that can be imported into API Gateway directly.

### Use scripts as vibe coding

#### Generate routes file

> gen_lamb_routes routes ./ (@see iciawsaid/tools)

#### Generate E2E testing data files

> gen_lamb_routes template .

### Usage

```rust
use iciaws_router::{addons::AddonHolder, router::Router};
use lambda_http::{Body, Error, Request, Response, run, service_fn, tracing};
mod handlers;
mod models;
mod routes;
use dynamo::get_dynamo_client;
use routes::add_routes;

async fn function_handler(event: Request, router: &Router) -> Result<Response<Body>, Error> {
    let rs = router.route(event).await;

    let resp = Response::builder()
        .status(rs.status)
        .header("content-type", "application/json")
        .body(rs.body.into())
        .map_err(Box::new)?;
    Ok(resp)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing::init_default_subscriber();

    let dynamo_client = get_dynamo_client(None::<String>).await;
    let addon_map = AddonHolder::new();
    addon_map.put_addon("dynamo", dynamo_client);

    let mut router = Router::new(addon_map);
    add_routes(&mut router);

    let router_ref = &router;

    run(service_fn(move |event| async move {
        function_handler(event, router_ref).await
    }))
    .await
}
```
