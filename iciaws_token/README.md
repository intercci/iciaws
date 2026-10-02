# iciaws-token

A Rust library for generating and verifying PASETO (Platform-Agnostic Security Tokens) v3 and v4 tokens, with first-class support for AWS KMS.

## Features

- **PASETO Support**: Full support for PASETO v3 (P-384) and v4 (Ed25519) public-mode tokens.
- **AWS KMS Integration**: Securely sign tokens using AWS KMS without the private key ever leaving the KMS environment.
- **Dual Signing Sources**:
  - `kms`: Remote signing via AWS KMS.
  - `env`: Local signing using a secret key provided via environment variables (ideal for development).
- **High Performance**:
  - `Signer` performs I/O only during signing (for KMS mode).
  - `Verifier` fetches the public key once at construction; `verify_token` performs no network I/O, making it suitable for high-throughput hot paths.
- **Strict Versioning**: The PASETO version is pinned at configuration time, preventing "version switching" attacks.

## Key Differences: v3 vs v4

| Feature | PASETO v3 | PASETO v4 |
| :--- | :--- | :--- |
| **Algorithm** | ECDSA (P-384) | Ed25519 |
| **KMS Signature** | DER-encoded $\rightarrow$ 96-byte raw | 64-byte raw |
| **PAE Ordering** | `[public_key, header, ...]` | `[header, message, ...]` |
| **Rotation Impact** | **Immediate Invalidation**: Rotating the KMS key invalidates all existing v3 tokens because the public key is part of the PAE. | **Standard Rotation**: Rotating the key only invalidates tokens signed by the old key. |

## Configuration

The library uses environment variables for configuration.

### Environment Variables

| Variable | Description |
| :--- | :--- |
| `PASETO_KEY_SOURCE` | `kms`, `env`, or `auto`. `auto` loads `.env` if present. |
| `KMS_KEY_ID` | The AWS KMS Key ID, ARN, or Alias (used when source is `kms`). |
| `PASETO_PRV_KEY` | The raw base64url secret key (used when source is `env`). |
| `PASETO_PUB_KEY` | The raw base64url public key (used when source is `env`). |

## Usage

### Signer

The `Signer` is used to mint new tokens.

```rust
// Using AWS KMS
let signer = Signer::with_source(KeySource::Kms(kms_key_id)).await?;
let token = signer.sign(claims).await?;

// Using Local Environment
let signer = Signer::with_source(KeySource::Env)?;
let token = signer.sign(claims)?;
```

### Verifier

The `Verifier` is used to validate inbound tokens. It is designed for high performance and does **not** perform network I/O during the verification step.

```rust
// Build once (e.g., at application startup)
let verifier = Verifier::with_source(KeySource::Kms(kms_key_id)).await?;

// Verify many times (hot path)
let claims = verifier.verify_token(token_string).await?;
println!("Authenticated subject: {}", claims.sub);
```

## Error Handling

The library provides a `TokenError` enum for common failure scenarios:

- `Unauthenticated`: The token was rejected (invalid signature, expired, etc.).
- `KeyPairError`: Issues with key material.
- `PasetosError`: Errors originating from the underlying `pasetors` crate.
- `SerdeJsonError`: Failures in payload serialization/deserialization.

## Security Note

When using **PASETO v3**, remember that the public key is cryptographically bound into the Pre-Authentication Encoding (PAE). **Rotating your AWS KMS key will immediately invalidate all existing v3 tokens because the public key is part of the PAE.** If you require graceful key rotation, please use **PASETO v4**.
