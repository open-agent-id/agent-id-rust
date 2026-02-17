use open_agent_id::crypto::{base64url_decode, sha256_hex};
use open_agent_id::AgentIdentity;

const TEST_DID: &str = "did:agent:tokli:agt_a1B2c3D4e5";
const TEST_PRIVATE_KEY_B64: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
const TEST_PUBLIC_KEY_B64: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

#[test]
fn test_load_identity() {
    let identity = AgentIdentity::load(TEST_DID, TEST_PRIVATE_KEY_B64).unwrap();
    assert_eq!(identity.did(), TEST_DID);
    assert_eq!(identity.public_key_base64url(), TEST_PUBLIC_KEY_B64);
}

#[test]
fn test_sign_empty_payload() {
    let identity = AgentIdentity::load(TEST_DID, TEST_PRIVATE_KEY_B64).unwrap();
    let sig = identity.sign("").unwrap();
    let sig_bytes = base64url_decode(&sig).unwrap();
    let expected = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
    assert_eq!(hex::encode(&sig_bytes), expected);
}

#[test]
fn test_sign_and_local_verify() {
    // Sign with one identity, then verify locally using the same key
    let identity = AgentIdentity::load(TEST_DID, TEST_PRIVATE_KEY_B64).unwrap();
    let payload = "hello world";
    let sig = identity.sign(payload).unwrap();

    // Manually verify using the public key
    let sig_bytes = base64url_decode(&sig).unwrap();
    let pub_bytes = base64url_decode(TEST_PUBLIC_KEY_B64).unwrap();

    let sig_array: [u8; 64] = sig_bytes.try_into().unwrap();
    let pub_array: [u8; 32] = pub_bytes.try_into().unwrap();

    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pub_array).unwrap();
    let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

    use ed25519_dalek::Verifier;
    assert!(verifying_key.verify(payload.as_bytes(), &signature).is_ok());
}

#[test]
fn test_canonical_payload_get_no_body() {
    // Test vector: GET request with no body
    let method = "GET";
    let url = "https://api.example.com/v1/agents/did:agent:tokli:agt_a1B2c3D4e5";
    let body = "";
    let timestamp = 1708123456u64;
    let nonce = "a3f1b2c4d5e6f708";

    let body_hash = sha256_hex(body.as_bytes());
    let canonical = format!("{}\n{}\n{}\n{}\n{}", method, url, body_hash, timestamp, nonce);

    let expected = "GET\nhttps://api.example.com/v1/agents/did:agent:tokli:agt_a1B2c3D4e5\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n1708123456\na3f1b2c4d5e6f708";
    assert_eq!(canonical, expected);
}

#[test]
fn test_canonical_payload_post_with_body() {
    // Test vector: POST request with JSON body
    let method = "POST";
    let url = "https://api.example.com/v1/tasks";
    let body = "{\"task\":\"search\"}";
    let timestamp = 1708123456u64;
    let nonce = "b4f2c3d5e6a7f809";

    let body_hash = sha256_hex(body.as_bytes());
    assert_eq!(
        body_hash,
        "0dfd9a0e52fe94a5e6311a6ef4643304c65636ae7fc316a0334e91c9665370af"
    );

    let canonical = format!("{}\n{}\n{}\n{}\n{}", method, url, body_hash, timestamp, nonce);

    let expected = "POST\nhttps://api.example.com/v1/tasks\n0dfd9a0e52fe94a5e6311a6ef4643304c65636ae7fc316a0334e91c9665370af\n1708123456\nb4f2c3d5e6a7f809";
    assert_eq!(canonical, expected);
}

#[test]
fn test_sign_request_produces_all_headers() {
    let identity = AgentIdentity::load(TEST_DID, TEST_PRIVATE_KEY_B64).unwrap();
    let headers = identity
        .sign_request("POST", "https://api.example.com/v1/tasks", "{\"task\":\"search\"}")
        .unwrap();

    assert_eq!(headers.get("X-Agent-DID").unwrap(), TEST_DID);
    assert!(headers.contains_key("X-Agent-Timestamp"));
    assert!(headers.contains_key("X-Agent-Nonce"));
    assert!(headers.contains_key("X-Agent-Signature"));

    // Timestamp should be a valid number
    let ts: u64 = headers.get("X-Agent-Timestamp").unwrap().parse().unwrap();
    assert!(ts > 0);

    // Nonce should be 32 hex chars (16 bytes)
    let nonce = headers.get("X-Agent-Nonce").unwrap();
    assert_eq!(nonce.len(), 32);
    assert!(nonce.chars().all(|c| c.is_ascii_hexdigit()));

    // Signature should be valid base64url and decode to 64 bytes
    let sig = headers.get("X-Agent-Signature").unwrap();
    let sig_bytes = base64url_decode(sig).unwrap();
    assert_eq!(sig_bytes.len(), 64);
}

#[test]
fn test_sign_request_signature_verifiable() {
    let identity = AgentIdentity::load(TEST_DID, TEST_PRIVATE_KEY_B64).unwrap();
    let body = "{\"task\":\"search\"}";
    let headers = identity
        .sign_request("POST", "https://api.example.com/v1/tasks", body)
        .unwrap();

    // Reconstruct the canonical payload
    let body_hash = sha256_hex(body.as_bytes());
    let timestamp = headers.get("X-Agent-Timestamp").unwrap();
    let nonce = headers.get("X-Agent-Nonce").unwrap();
    let canonical = format!(
        "POST\nhttps://api.example.com/v1/tasks\n{}\n{}\n{}",
        body_hash, timestamp, nonce
    );

    // Verify signature
    let sig_bytes = base64url_decode(headers.get("X-Agent-Signature").unwrap()).unwrap();
    let pub_bytes = base64url_decode(TEST_PUBLIC_KEY_B64).unwrap();

    let sig_array: [u8; 64] = sig_bytes.try_into().unwrap();
    let pub_array: [u8; 32] = pub_bytes.try_into().unwrap();

    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pub_array).unwrap();
    let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

    use ed25519_dalek::Verifier;
    assert!(
        verifying_key
            .verify(canonical.as_bytes(), &signature)
            .is_ok(),
        "Signature should be valid for the reconstructed canonical payload"
    );
}

#[test]
fn test_load_32_byte_seed() {
    // Load with just the 32-byte seed (base64url of the hex seed from vectors.json)
    let seed_b64 = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
    let identity = AgentIdentity::load(TEST_DID, seed_b64).unwrap();
    assert_eq!(identity.did(), TEST_DID);
    assert_eq!(identity.public_key_base64url(), TEST_PUBLIC_KEY_B64);
}
