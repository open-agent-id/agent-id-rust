use open_agent_id::crypto::{self, base64url_encode};
use open_agent_id::signing::{
    build_http_payload, build_msg_payload, canonical_json, canonicalize_url, sign_http, sign_msg,
    verify_http, verify_msg, HttpSignInput, MsgSignInput,
};

// ---------------------------------------------------------------------------
// Canonical URL tests
// ---------------------------------------------------------------------------

#[test]
fn canonical_url_lowercases_host() {
    let result = canonicalize_url("https://API.Example.COM/v1/agents").unwrap();
    assert_eq!(result, "https://api.example.com/v1/agents");
}

#[test]
fn canonical_url_sorts_query_params() {
    let result =
        canonicalize_url("https://api.example.com/v1/agents?offset=0&limit=10&b=2&a=1").unwrap();
    assert_eq!(
        result,
        "https://api.example.com/v1/agents?a=1&b=2&limit=10&offset=0"
    );
}

#[test]
fn canonical_url_no_query_no_question_mark() {
    let result = canonicalize_url("https://api.example.com/path").unwrap();
    assert!(!result.contains('?'));
}

#[test]
fn canonical_url_strips_fragment() {
    let result = canonicalize_url("https://api.example.com/path?a=1#section").unwrap();
    assert!(!result.contains('#'));
    assert!(result.ends_with("?a=1"));
}

#[test]
fn canonical_url_preserves_port() {
    let result = canonicalize_url("https://localhost:8080/api").unwrap();
    assert_eq!(result, "https://localhost:8080/api");
}

// ---------------------------------------------------------------------------
// Canonical JSON tests
// ---------------------------------------------------------------------------

#[test]
fn canonical_json_sorts_keys() {
    let val: serde_json::Value =
        serde_json::from_str(r#"{"z":1,"a":"hello","m":[3,2,1]}"#).unwrap();
    assert_eq!(canonical_json(&val), r#"{"a":"hello","m":[3,2,1],"z":1}"#);
}

#[test]
fn canonical_json_nested_objects() {
    let val: serde_json::Value =
        serde_json::from_str(r#"{"b":{"d":4,"c":3},"a":1}"#).unwrap();
    assert_eq!(canonical_json(&val), r#"{"a":1,"b":{"c":3,"d":4}}"#);
}

#[test]
fn canonical_json_empty_object() {
    let val: serde_json::Value = serde_json::from_str("{}").unwrap();
    assert_eq!(canonical_json(&val), "{}");
}

// ---------------------------------------------------------------------------
// HTTP signing payload
// ---------------------------------------------------------------------------

#[test]
fn http_payload_format() {
    let payload = build_http_payload(
        "post",
        "https://API.Example.com/v1/agents?offset=0&limit=10",
        b"",
        1708123456,
        "deadbeef00000000deadbeef00000000",
    )
    .unwrap();

    let lines: Vec<&str> = payload.split('\n').collect();
    assert_eq!(lines.len(), 6);
    assert_eq!(lines[0], "oaid-http/v1");
    assert_eq!(lines[1], "POST");
    assert_eq!(
        lines[2],
        "https://api.example.com/v1/agents?limit=10&offset=0"
    );
    // SHA-256 of empty body
    assert_eq!(
        lines[3],
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(lines[4], "1708123456");
    assert_eq!(lines[5], "deadbeef00000000deadbeef00000000");
}

#[test]
fn http_payload_with_body() {
    let payload = build_http_payload(
        "POST",
        "https://api.example.com/v1/tasks",
        b"{\"task\":\"search\"}",
        1708123456,
        "b4f2c3d5e6a7f809b4f2c3d5e6a7f809",
    )
    .unwrap();

    let lines: Vec<&str> = payload.split('\n').collect();
    assert_eq!(lines[0], "oaid-http/v1");
    assert_eq!(
        lines[3],
        "0dfd9a0e52fe94a5e6311a6ef4643304c65636ae7fc316a0334e91c9665370af"
    );
}

// ---------------------------------------------------------------------------
// HTTP sign/verify roundtrip
// ---------------------------------------------------------------------------

#[test]
fn http_sign_verify_roundtrip() {
    let (sk, vk) = crypto::generate_keypair();

    let input = HttpSignInput {
        method: "POST",
        url: "https://api.example.com/v1/agents",
        body: b"{\"name\":\"bot\"}",
        timestamp: Some(1708123456),
        nonce: Some("a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8".to_string()),
    };

    let output = sign_http(&input, &sk).unwrap();

    let valid = verify_http(
        input.method,
        input.url,
        input.body,
        output.timestamp,
        &output.nonce,
        &output.signature,
        &vk,
    )
    .unwrap();
    assert!(valid);
}

#[test]
fn http_sign_with_auto_timestamp_and_nonce() {
    let (sk, vk) = crypto::generate_keypair();

    let input = HttpSignInput {
        method: "GET",
        url: "https://api.example.com/v1/agents/did:oaid:base:0x0000000000000000000000000000000000000001",
        body: b"",
        timestamp: None,
        nonce: None,
    };

    let output = sign_http(&input, &sk).unwrap();
    assert!(output.timestamp > 0);
    assert_eq!(output.nonce.len(), 32);

    let valid = verify_http(
        input.method,
        input.url,
        input.body,
        output.timestamp,
        &output.nonce,
        &output.signature,
        &vk,
    )
    .unwrap();
    assert!(valid);
}

#[test]
fn http_tampered_body_fails_verification() {
    let (sk, vk) = crypto::generate_keypair();

    let input = HttpSignInput {
        method: "POST",
        url: "https://api.example.com/test",
        body: b"original",
        timestamp: Some(1000),
        nonce: Some("0".repeat(32)),
    };

    let output = sign_http(&input, &sk).unwrap();

    let valid = verify_http(
        "POST",
        "https://api.example.com/test",
        b"tampered",
        output.timestamp,
        &output.nonce,
        &output.signature,
        &vk,
    )
    .unwrap();
    assert!(!valid);
}

#[test]
fn http_wrong_key_fails_verification() {
    let (sk, _) = crypto::generate_keypair();
    let (_, other_vk) = crypto::generate_keypair();

    let input = HttpSignInput {
        method: "GET",
        url: "https://api.example.com/test",
        body: b"",
        timestamp: Some(1000),
        nonce: Some("f".repeat(32)),
    };

    let output = sign_http(&input, &sk).unwrap();

    let valid = verify_http(
        "GET",
        "https://api.example.com/test",
        b"",
        output.timestamp,
        &output.nonce,
        &output.signature,
        &other_vk,
    )
    .unwrap();
    assert!(!valid);
}

// ---------------------------------------------------------------------------
// Message signing payload
// ---------------------------------------------------------------------------

#[test]
fn msg_payload_sorted_to_dids() {
    let body = serde_json::json!({});
    let payload = build_msg_payload(
        "test",
        "id1",
        "did:oaid:base:0x1111111111111111111111111111111111111111",
        &[
            "did:oaid:base:0xcccccccccccccccccccccccccccccccccccccccc",
            "did:oaid:base:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ],
        "",
        100,
        0,
        &body,
    );
    let lines: Vec<&str> = payload.split('\n').collect();
    assert_eq!(lines[0], "oaid-msg/v1");
    // to DIDs should be sorted
    assert_eq!(
        lines[4],
        "did:oaid:base:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,did:oaid:base:0xcccccccccccccccccccccccccccccccccccccccc"
    );
}

#[test]
fn msg_payload_empty_to() {
    let body = serde_json::json!({});
    let payload = build_msg_payload("test", "id1", "from", &[], "", 100, 0, &body);
    let lines: Vec<&str> = payload.split('\n').collect();
    assert_eq!(lines[4], ""); // empty sorted_to
}

#[test]
fn msg_payload_empty_ref() {
    let body = serde_json::json!({});
    let payload = build_msg_payload("test", "id1", "from", &[], "", 100, 0, &body);
    let lines: Vec<&str> = payload.split('\n').collect();
    assert_eq!(lines[5], ""); // empty ref
}

#[test]
fn msg_payload_expires_at_zero() {
    let body = serde_json::json!({});
    let payload = build_msg_payload("test", "id1", "from", &[], "", 100, 0, &body);
    let lines: Vec<&str> = payload.split('\n').collect();
    assert_eq!(lines[7], "0"); // expires_at = 0
}

// ---------------------------------------------------------------------------
// Message sign/verify roundtrip
// ---------------------------------------------------------------------------

#[test]
fn msg_sign_verify_roundtrip() {
    let (sk, vk) = crypto::generate_keypair();

    let body = serde_json::json!({"proposal": "do-something", "quorum": 3});
    let input = MsgSignInput {
        msg_type: "consensus/ballot",
        id: "019504a0-0000-7000-8000-000000000001",
        from: "did:oaid:base:0x0000000000000000000000000000000000000001",
        to: &[
            "did:oaid:base:0x0000000000000000000000000000000000000003",
            "did:oaid:base:0x0000000000000000000000000000000000000002",
        ],
        reference: "",
        timestamp: Some(1708123456),
        expires_at: 0,
        body: &body,
    };

    let output = sign_msg(&input, &sk);

    let valid = verify_msg(
        input.msg_type,
        input.id,
        input.from,
        input.to,
        input.reference,
        output.timestamp,
        input.expires_at,
        input.body,
        &output.signature,
        &vk,
    )
    .unwrap();
    assert!(valid);
}

#[test]
fn msg_tampered_body_fails() {
    let (sk, vk) = crypto::generate_keypair();

    let body = serde_json::json!({"vote": "yes"});
    let input = MsgSignInput {
        msg_type: "consensus/ballot",
        id: "msg-1",
        from: "did:oaid:base:0x0000000000000000000000000000000000000001",
        to: &["did:oaid:base:0x0000000000000000000000000000000000000002"],
        reference: "",
        timestamp: Some(1000),
        expires_at: 0,
        body: &body,
    };

    let output = sign_msg(&input, &sk);

    let tampered_body = serde_json::json!({"vote": "no"});
    let valid = verify_msg(
        input.msg_type,
        input.id,
        input.from,
        input.to,
        input.reference,
        output.timestamp,
        input.expires_at,
        &tampered_body,
        &output.signature,
        &vk,
    )
    .unwrap();
    assert!(!valid);
}

// ---------------------------------------------------------------------------
// Known key test vector: sign raw payload, verify with public key
// ---------------------------------------------------------------------------

#[test]
fn known_key_http_signature() {
    let seed_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    let seed_bytes = hex::decode(seed_hex).unwrap();
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed_bytes.try_into().unwrap());
    let vk = sk.verifying_key();

    let input = HttpSignInput {
        method: "GET",
        url: "https://api.openagentid.org/v1/agents/did:oaid:base:0x0000000000000000000000000000000000000001",
        body: b"",
        timestamp: Some(1708123456),
        nonce: Some("a3f1b2c4d5e6f708a3f1b2c4d5e6f708".to_string()),
    };

    let output = sign_http(&input, &sk).unwrap();

    // The signature should be base64url, 64 bytes when decoded
    let sig_bytes = open_agent_id::crypto::base64url_decode(&output.signature).unwrap();
    assert_eq!(sig_bytes.len(), 64);

    // Verify
    let valid = verify_http(
        input.method,
        input.url,
        input.body,
        output.timestamp,
        &output.nonce,
        &output.signature,
        &vk,
    )
    .unwrap();
    assert!(valid);

    // Ensure public key matches expected base64url
    assert_eq!(
        base64url_encode(vk.as_bytes()),
        "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    );
}
