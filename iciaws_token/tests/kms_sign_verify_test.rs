use iciaws_token::signer::Signer;
use iciaws_token::verifier::Verifier;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn kms_sign_and_verify_round_trip() {
    // Sign a token using AWS KMS (Sign API). KMS_KEY_ID is loaded from .env
    // by Signer::with_source via kms::load_dotenv_if_local().
    let signer = Signer::with_source(None, Some("kms"))
        .await
        .expect("Failed to create KMS signer");

    assert!(signer.is_kms(), "Signer should be using KMS source");
    assert!(
        !signer.kms_key_id().is_empty(),
        "KMS key ID should be resolved"
    );

    // Generate an access token
    let token = signer
        .gen_access_token("user-1", "iciaws-test", None)
        .await
        .expect("Failed to sign token with KMS");

    // Verify token header format (PASETO v3.public or v4.public)
    assert!(
        token.starts_with("v3.public.") || token.starts_with("v4.public."),
        "Token should start with v3.public. or v4.public., got: {}",
        token
    );

    // Verify the token using the public key fetched from KMS (GetPublicKey API)
    let verifier = Verifier::with_source(None, Some("kms"))
        .await
        .expect("Failed to create KMS verifier");

    assert!(verifier.is_kms(), "Verifier should be using KMS source");
    assert_eq!(verifier.version(), signer.version());

    let claims = verifier
        .verify_token(&token)
        .await
        .expect("Failed to verify token");

    // Assert claims round-trip correctly
    assert_eq!(
        claims.get_claim("sub").and_then(|v| v.as_str()),
        Some("user-1"),
        "Subject claim should match"
    );
    assert_eq!(
        claims.get_claim("aud").and_then(|v| v.as_str()),
        Some("iciaws-test"),
        "Audience claim should match"
    );
}

#[tokio::test]
#[serial]
async fn kms_verify_rejects_tampered_token() {
    // Sign a token using AWS KMS
    let signer = Signer::with_source(None, Some("kms"))
        .await
        .expect("Failed to create KMS signer");

    let token = signer
        .gen_access_token("user-1", "iciaws-test", None)
        .await
        .expect("Failed to sign token with KMS");

    // Tamper the token payload - flip a character in the last segment
    let mut tampered = token.clone();
    if let Some(last_char) = tampered.pop() {
        // Flip the last character to a different one
        let tampered_char = if last_char == 'A' { 'B' } else { 'A' };
        tampered.push(tampered_char);
    } else {
        tampered.push('X');
    }

    // Verify the tampered token should fail
    let verifier = Verifier::with_source(None, Some("kms"))
        .await
        .expect("Failed to create KMS verifier");

    let result = verifier.verify_token(&tampered).await;
    assert!(
        result.is_err(),
        "Tampered token should fail verification"
    );
}
