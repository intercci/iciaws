# iciaws

A collection of Rust crates for building **AWS serverless backends** with Lambda, DynamoDB, S3, SES, SNS, and API Gateway.

Pick only what you need — every crate is independent. While not yet published to crates.io, add directly from this repo:

```bash
cargo add iciaws_dynamo --git https://github.com/intercci/iciaws
cargo add iciaws_s3 --git https://github.com/intercci/iciaws
cargo add iciaws_ses --git https://github.com/intercci/iciaws
cargo add iciaws_sns --git https://github.com/intercci/iciaws
cargo add iciaws_router --git https://github.com/intercci/iciaws
cargo add iciaws_macros --git https://github.com/intercci/iciaws
cargo add iciaws_test_helper --git https://github.com/intercci/iciaws
```

Once the crates are mature enough, they will be published to [crates.io](https://crates.io) for easier dependency management.

---

## Crates

| Crate | Purpose | Cargo name |
|-------|---------|------------|
| `iciaws_dynamo` | DynamoDB client with composite keys, pagination, batch operations | `iciaws_dynamo` |
| `iciaws_s3` | S3 client — get/put objects, presigned URLs, image listing | `iciaws_s3` |
| `iciaws_ses` | SES v2 client for email sending and receiving | `iciaws_ses` |
| `iciaws_sns` | SNS client for pub/sub notifications | `iciaws_sns` |
| `iciaws_router` | Lightweight router for Lambda behind API Gateway | `iciaws_router` |
| `iciaws_macros` | Procedural macros powering `iciaws_router` | `iciaws_macros` |
| `iciaws_test_helper` | Test utilities for Lambda routing | `iciaws_test_helper` |

---

## iciaws_dynamo

Drop-in DynamoDB client built on `aws-sdk-dynamodb`. Designed for composite key schemas (`pk~sk`) common in serverless apps.

### Features

- **CRUD**: `put`, `get`, `query`, `update`, `delete`
- **Composite keys**: automatic `pk`/`sk` encoding from human-readable strings like `"User#alice~Profile"`
- **Pagination**: base64-encoded exclusive start keys for URL-safe query parameters
- **Batch operations**: `batch_put`, `batch_delete` (auto-chunked to 25)
- **GSI queries**: full support for global secondary index queries with filter expressions
- **Typed updates**: `update_s`, `update_n`, `update_add` (atomic counters), `update_add_list_str`, `update_add_list`, `update_remove_attr`
- **Static singleton**: `get_dynamo_client()` returns a `&'static DynamoClient` initialized once per Lambda invocation

### Quick start

```rust
use iciaws_dynamo::DynamoClient;

let dynamo = DynamoClient::new("my-table".to_string()).await;

// Put an item (composite key "Resource#abc123~detail")
let mut item: HashMap<String, AttributeValue> = HashMap::new();
item.insert("pk".into(), AttributeValue::S("Resource#abc123".into()));
item.insert("sk".into(), AttributeValue::S("detail".into()));
dynamo.put(item, None).await?;

// Query by pk with pagination
let page = dynamo
    .query_page_by_pk("Resource#abc123", None, Some(10), None)
    .await?;
```

---

## iciaws_s3

S3 client with presigned URL support and typed convenience methods.

### Features

- **Object operations**: `get_object`, `put_object`, `get_bytes`, `get_string`, `get_json`
- **Presigned URLs**: `get_presign` (60s default), `put_presign` (5min default)
- **Image listing**: `list_images` filters by common image extensions under a folder prefix
- **Default bucket**: reads from `BUCKET` env var (falls back to `"ici-uploads"`)
- **Static singleton**: `get_s3_client()` returns a `&'static S3Client`

### Quick start

```rust
use iciaws_s3::S3Client;

let s3 = S3Client::new(None).await;

// Get JSON from S3
let config: Value = s3.get_json("config/app.json", None).await?;

// Generate a presigned download URL
let url = s3.get_presign("photos/vacation.jpg", None).await?;

// Upload bytes
s3.put_object("uploads/report.pdf", byte_stream, None).await?;
```

---

## iciaws_ses

SES v2 client for sending and receiving email.

### Features

- Async email operations via `aws-sdk-sesv2`
- Error handling with `thiserror`
- Loads credentials from environment, `.env`, or AWS config chain

---

## iciaws_sns

SNS client for pub/sub notification publishing.

### Features

- Async publish operations via `aws-sdk-sns`
- Error handling with `thiserror`
- Loads credentials from environment, `.env`, or AWS config chain

---

## iciaws_router

Lightweight router framework for AWS Lambda behind API Gateway. Maps HTTP routes to handler functions with dependency injection via the **addon pattern**.

### Features

- **Route registration**: declarative route definitions with method/path/handler
- **Addon pattern**: inject `DynamoClient`, `S3Client`, `SESClient`, `SNSClient` into handlers
- **Request parsing**: typed input extraction from query params, headers, and JSON bodies
- **Response helpers**: structured output builders for JSON, redirects, and errors
- **Token handling**: JWT/PASETO token extraction and validation
- **API Gateway ready**: works with `lambda_http` for both REST and HTTP API payloads
- **Test helpers**: `iciaws_test_helper` crate for unit-testing routes without AWS infrastructure

### Quick start

```rust
use iciaws_router::router::Router;
use iciaws_router::addons::Addons;

#[tokio::main]
async fn main() {
    let mut router = Router::new();

    // Register a route with DynamoDB and S3 addons
    router.get(
        "/items/<id>",
        get_item,
        Addons::default()
            .with_dynamo("my-table")
            .with_s3(None),
    );

    lambda_http::run(router.into_service()).await?;
}

async fn get_item(
    path_params: PathParams,
    addons: Addons,
) -> Result<Response, AppError> {
    let dynamo = addons.dynamo.unwrap();
    let id = path_params.get("id").unwrap();
    // ... fetch and return
    todo!()
}
```

---

## Architecture

```
API Gateway
    |
    v
Lambda Function (iciaws_router)
    ├── iciaws_dynamo  ──►  DynamoDB
    ├── iciaws_s3      ──►  S3
    ├── iciaws_ses     ──►  SES (email)
    └── iciaws_sns     ──►  SNS (notifications)
```

Each service client is a standalone crate. The router ties them together with minimal boilerplate.

---

## Prerequisites

- **Rust 2024 edition** — all crates target `edition = "2024"`
- **Tokio** — async runtime (included as a workspace dependency)
- **AWS credentials** — via `~/.aws/credentials`, environment variables, or IAM roles

---

## Workspace

This repo is a Cargo workspace. To build everything locally:

```bash
cargo build --workspace
```

To run tests:

```bash
cargo test --workspace
```

---

## License

MIT
