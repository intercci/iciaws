# Lamb-Route

A light-weight router crate for AWS Lambda functions.

## Features

- Provides a simple routing mechanism
- PASETO v3/v4 token signing and verification via AWS KMS
- Async/await throughout — no blocking calls in the hot path
- `tokio::sync::OnceCell`-based verifier initialization (retries on transient KMS failures)
- Fail-open design: unverifiable tokens leave claims absent; handlers enforce via gatekeepers

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

---

## PASETO Token Authentication

The router supports PASETO v3 (P-384/ECDSA) and v4 (Ed25519) tokens, with keys managed by AWS KMS.

### Environment Variables

Configure the PASETO key source and key material through these environment variables:

| Variable | Required | Description |
|----------|----------|-------------|
| `PASETO_KEY_SOURCE` | No | `kms`, `env`, or `auto` (default: `auto`) |
| `KMS_KEY_ID` | Yes (KMS mode) | KMS key ID, ARN, or alias (e.g., `alias/paseto-signing`) |
| `PASETO_PUB_KEY` | Yes (env mode) | Base64url-encoded raw public key |
| `PASETO_PRV_KEY` | Yes (env mode) | Base64url-encoded raw secret key (signer only) |

**`auto` mode** (default): Selects `kms` on Lambda (when `LAMBDA_TASK_ROOT` is set) and `env` locally. This means:
- **Production**: Keys live in KMS; the Lambda process never sees the private key.
- **Local development**: Keys are read from environment variables or `.env`; no AWS credentials needed.

**Loading `.env`**: When running locally, `.env` is loaded automatically before key resolution.

### Creating KMS Keys

Create asymmetric KMS keys for PASETO signing. The key type determines the PASETO version:

#### PASETO v4 (Ed25519)

```bash
aws kms create-key \
  --description "PASETO v4 signing key for my-service" \
  --key-spec ECC_NIST_EDWARDS25519 \
  --key-usage SIGN_VERIFY \
  --tags TagKey=Service,TagValue=my-app
```

Output:
```json
{
  "KeyMetadata": {
    "KeyId": "12345678-1234-1234-1234-123456789012",
    "Arn": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
    "KeySpec": "ECC_NIST_EDWARDS25519",
    "KeyUsage": "SIGN_VERIFY"
  }
}
```

Set the environment variable:
```bash
export KMS_KEY_ID=12345678-1234-1234-1234-123456789012
```

#### PASETO v3 (P-384 / ECDSA)

```bash
aws kms create-key \
  --description "PASETO v3 signing key for my-service" \
  --key-spec ECC_NIST_P384 \
  --key-usage SIGN_VERIFY \
  --tags TagKey=Service,TagValue=my-app
```

#### Local Development Keys (no KMS required)

For local development without AWS credentials, generate keys and set environment variables:

```bash
# Generate Ed25519 v4 keys (64 bytes = 86 base64url chars)
openssl genpkey -algorithm Ed25519 -out privkey.pem
openssl pkey -in privkey.pem -outform DER | base64 -w0 > PASETO_PRV_KEY
openssl pkey -pubout -in privkey.pem -outform DER | tail -c 32 | base64 -w0 > PASETO_PUB_KEY

# Set environment variables
export PASETO_KEY_SOURCE=env
export PASETO_PUB_KEY=<base64url-public-key>
export PASETO_PRV_KEY=<base64url-private-key>
```

Or create a `.env` file:
```bash
PASETO_KEY_SOURCE=env
PASETO_PUB_KEY=xxxxx
PASETO_PRV_KEY=xxxxx
```

### Using the Signer

```rust
use iciaws_router::signer::Signer;
use std::collections::HashMap;

// Build signer (async — fetches public key from KMS if using KMS source)
let signer = Signer::new(None).await?;

// Generate an access token (1-hour lifetime)
let token = signer
    .gen_access_token(
        "user-123",           // sub: subject identifier
        "my-app",             // aud: audience
        Some(HashMap::from([  // extra claims
            ("role".into(), "admin".into()),
            ("tenant".into(), "acme".into()),
        ])),
    )
    .await?;

// Generate a refresh token (2-day lifetime, typ="refresh")
let refresh = signer
    .gen_refresh_token("user-123", "my-app", None)
    .await?;
```

### Using the Verifier

```rust
use iciaws_router::verifier::Verifier;

// Build verifier (async)
let verifier = Verifier::new(None).await?;

// Verify a token
let claims = verifier.verify_token(&token).await?;

// Access claims
let sub = claims.get_claim("sub").and_then(|v| v.as_str()).unwrap();
let aud = claims.get_claim("aud").and_then(|v| v.as_str()).unwrap();
let role = claims.get_claim("role").and_then(|v| v.as_str()).unwrap();

// Verify with footer binding (optional)
let claims = verifier
    .verify_token_with_footer(&token, Some(b"my-footer"))
    .await?;
```

### Integrating with the Router

The router automatically extracts PASETO claims from the `jwt` cookie and populates the `claims` HashMap:

```rust
use iciaws_router::input::RouteHandlerInput;

#[route("GET/users/me")]
pub fn get_user(input: RouteHandlerInput) -> Result<RouteHandlerOutput, RouterError> {
    // Automatic claim extraction from JWT cookie:
    // sub -> uid, aud -> appid, role -> role
    // Plus any custom claims from the token
    
    let uid = input.get_claim("uid")?;       // from sub claim
    let appid = input.get_claim("appid")?;   // from aud claim  
    let role = input.get_claim("role")?;     // from role claim
    let tenant = input.get_claim("tenant")?; // custom claim
    
    // Authorization checks
    if !input.am_i_a("admin") {
        return Err(RouterError::Unauthorized("admin only".into()));
    }
    
    Ok(RouteHandlerOutput::message_output(
        StatusCode::OK,
        format!("Hello {} in tenant {}", uid, tenant),
    ))
}
```

**Claim mapping** (automatic):

| PASETO Claim | Handler Key | Description |
|--------------|-------------|-------------|
| `sub` | `uid` | User identifier |
| `aud` | `appid` | Application identifier |
| `role` | `role` | Role string |
| Any other | <same name> | Custom claims passed through directly |

**Registered claims** (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`) are handled internally and do not appear in the claims HashMap under their original names. Only `sub`→`uid` and `aud`→`appid` are remapped; `role` and all other non-registered claims are preserved as-is.

### Token Lifecycle

| Token Type | Lifetime | typ Claim | Use Case |
|------------|----------|-----------|----------|
| Access token | 1 hour | None | Short-lived API access |
| Refresh token | 2 days | `refresh` | Obtain new access tokens |

### Key Rotation

**Important**: Rotating a KMS key invalidates **all existing v3 tokens immediately**. This is by design — PASETO v3 binds the public key into the signature's pre-authentication encoding (PAE). For graceful key rotation, issue v4 tokens instead, or maintain dual verifiers during transition.

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
