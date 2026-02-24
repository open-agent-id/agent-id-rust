//! Canonical payload construction, signing, and verification for the two V2 signing domains.
//!
//! # Domains
//!
//! - **`oaid-http/v1`** — HTTP request signing
//! - **`oaid-msg/v1`** — Agent-to-agent message signing

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

use crate::crypto;
use crate::error::Error;

/// Protocol constant: maximum clock skew allowed for HTTP signatures (seconds).
pub const HTTP_TIMESTAMP_WINDOW: u64 = 300;

/// Protocol constant: default expiration for messages when `expires_at` is not set.
pub const DEFAULT_EXPIRE_SECONDS: u64 = 300;

// ---------------------------------------------------------------------------
// oaid-http/v1
// ---------------------------------------------------------------------------

/// Input parameters for constructing an HTTP signature.
#[derive(Debug, Clone)]
pub struct HttpSignInput<'a> {
    /// HTTP method (e.g. `"POST"`). Will be uppercased.
    pub method: &'a str,
    /// The full request URL. Will be canonicalized.
    pub url: &'a str,
    /// The raw request body bytes (empty slice for bodyless requests).
    pub body: &'a [u8],
    /// Unix timestamp in seconds. If `None`, the current time is used.
    pub timestamp: Option<u64>,
    /// 16-byte hex nonce. If `None`, a random one is generated.
    pub nonce: Option<String>,
}

/// The result of constructing an HTTP signature, containing the headers to attach.
#[derive(Debug, Clone)]
pub struct HttpSignOutput {
    /// Unix timestamp used in the signature.
    pub timestamp: u64,
    /// The hex nonce used in the signature.
    pub nonce: String,
    /// Base64url-encoded Ed25519 signature.
    pub signature: String,
}

/// Build the canonical payload for `oaid-http/v1`.
///
/// Format:
/// ```text
/// oaid-http/v1\n{METHOD}\n{CANONICAL_URL}\n{BODY_HASH}\n{TIMESTAMP}\n{NONCE}
/// ```
pub fn build_http_payload(
    method: &str,
    url: &str,
    body: &[u8],
    timestamp: u64,
    nonce: &str,
) -> Result<String, Error> {
    let canonical_url = canonicalize_url(url)?;
    let body_hash = crypto::sha256_hex(body);

    Ok(format!(
        "oaid-http/v1\n{}\n{}\n{}\n{}\n{}",
        method.to_uppercase(),
        canonical_url,
        body_hash,
        timestamp,
        nonce,
    ))
}

/// Sign an HTTP request using `oaid-http/v1`.
///
/// Returns the signature output containing timestamp, nonce, and the base64url signature.
pub fn sign_http(input: &HttpSignInput, key: &SigningKey) -> Result<HttpSignOutput, Error> {
    let timestamp = input.timestamp.unwrap_or_else(now_unix);
    let nonce = input
        .nonce
        .clone()
        .unwrap_or_else(crypto::generate_nonce);

    let payload = build_http_payload(input.method, input.url, input.body, timestamp, &nonce)?;
    let sig = crypto::sign(payload.as_bytes(), key);

    Ok(HttpSignOutput {
        timestamp,
        nonce,
        signature: crypto::base64url_encode(&sig.to_bytes()),
    })
}

/// Verify an `oaid-http/v1` signature.
///
/// Reconstructs the canonical payload from the provided parameters and verifies
/// the Ed25519 signature. Does **not** check timestamp freshness (caller should
/// enforce the +-300s window).
pub fn verify_http(
    method: &str,
    url: &str,
    body: &[u8],
    timestamp: u64,
    nonce: &str,
    signature_b64: &str,
    key: &VerifyingKey,
) -> Result<bool, Error> {
    let payload = build_http_payload(method, url, body, timestamp, nonce)?;
    let sig_bytes = crypto::base64url_decode(signature_b64)?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| Error::Verification("signature must be 64 bytes".into()))?;
    let sig = Signature::from_bytes(&sig_arr);
    Ok(crypto::verify(payload.as_bytes(), &sig, key))
}

// ---------------------------------------------------------------------------
// oaid-msg/v1
// ---------------------------------------------------------------------------

/// Input parameters for constructing a message signature.
#[derive(Debug, Clone)]
pub struct MsgSignInput<'a> {
    /// Message type (e.g. `"consensus/ballot"`).
    pub msg_type: &'a str,
    /// Message UUID (v7 recommended).
    pub id: &'a str,
    /// Sender DID.
    pub from: &'a str,
    /// Recipient DIDs.
    pub to: &'a [&'a str],
    /// Optional reference ID (e.g. parent message). Use `""` for none.
    pub reference: &'a str,
    /// Unix timestamp in seconds. If `None`, the current time is used.
    pub timestamp: Option<u64>,
    /// Expiration as Unix seconds. `0` means use default (`timestamp + DEFAULT_EXPIRE_SECONDS`).
    pub expires_at: u64,
    /// The message body as a JSON value. Will be canonicalized (sorted keys, no whitespace).
    pub body: &'a serde_json::Value,
}

/// The result of constructing a message signature.
#[derive(Debug, Clone)]
pub struct MsgSignOutput {
    /// Unix timestamp used in the signature.
    pub timestamp: u64,
    /// Base64url-encoded Ed25519 signature.
    pub signature: String,
}

/// Build the canonical payload for `oaid-msg/v1`.
///
/// Format:
/// ```text
/// oaid-msg/v1\n{TYPE}\n{ID}\n{FROM}\n{SORTED_TO}\n{REF}\n{TIMESTAMP}\n{EXPIRES_AT}\n{BODY_HASH}
/// ```
pub fn build_msg_payload(
    msg_type: &str,
    id: &str,
    from: &str,
    to: &[&str],
    reference: &str,
    timestamp: u64,
    expires_at: u64,
    body: &serde_json::Value,
) -> String {
    let sorted_to = {
        let mut v: Vec<&str> = to.to_vec();
        v.sort();
        v.join(",")
    };

    let body_hash = crypto::sha256_hex(canonical_json(body).as_bytes());

    format!(
        "oaid-msg/v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        msg_type, id, from, sorted_to, reference, timestamp, expires_at, body_hash,
    )
}

/// Sign an agent-to-agent message using `oaid-msg/v1`.
pub fn sign_msg(input: &MsgSignInput, key: &SigningKey) -> MsgSignOutput {
    let timestamp = input.timestamp.unwrap_or_else(now_unix);

    let payload = build_msg_payload(
        input.msg_type,
        input.id,
        input.from,
        input.to,
        input.reference,
        timestamp,
        input.expires_at,
        input.body,
    );

    let sig = crypto::sign(payload.as_bytes(), key);

    MsgSignOutput {
        timestamp,
        signature: crypto::base64url_encode(&sig.to_bytes()),
    }
}

/// Verify an `oaid-msg/v1` signature.
///
/// Does **not** check expiration (caller should enforce that).
pub fn verify_msg(
    msg_type: &str,
    id: &str,
    from: &str,
    to: &[&str],
    reference: &str,
    timestamp: u64,
    expires_at: u64,
    body: &serde_json::Value,
    signature_b64: &str,
    key: &VerifyingKey,
) -> Result<bool, Error> {
    let payload = build_msg_payload(msg_type, id, from, to, reference, timestamp, expires_at, body);
    let sig_bytes = crypto::base64url_decode(signature_b64)?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| Error::Verification("signature must be 64 bytes".into()))?;
    let sig = Signature::from_bytes(&sig_arr);
    Ok(crypto::verify(payload.as_bytes(), &sig, key))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Canonicalize a URL according to the V2 spec:
///
/// 1. Scheme + host (lowercased) + path + sorted query params
/// 2. No fragment
/// 3. Empty query omits the `?`
pub fn canonicalize_url(raw: &str) -> Result<String, Error> {
    let parsed =
        url::Url::parse(raw).map_err(|e| Error::InvalidUrl(format!("{e}: {raw}")))?;

    let scheme = parsed.scheme();
    let host = parsed
        .host_str()
        .ok_or_else(|| Error::InvalidUrl(format!("URL has no host: {raw}")))?
        .to_ascii_lowercase();
    let port_suffix = match parsed.port() {
        Some(p) => format!(":{p}"),
        None => String::new(),
    };
    let path = parsed.path();

    // Sort query parameters by key
    let query_string = {
        let pairs: BTreeMap<String, String> = parsed
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();

        if pairs.is_empty() {
            String::new()
        } else {
            let parts: Vec<String> = pairs
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            format!("?{}", parts.join("&"))
        }
    };

    Ok(format!("{scheme}://{host}{port_suffix}{path}{query_string}"))
}

/// Produce canonical JSON: sorted keys, no extra whitespace.
///
/// This is used for body hashing in `oaid-msg/v1`.
pub fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut sorted: BTreeMap<&str, &serde_json::Value> = BTreeMap::new();
            for (k, v) in map {
                sorted.insert(k.as_str(), v);
            }
            let entries: Vec<String> = sorted
                .iter()
                .map(|(k, v)| format!("\"{}\":{}", k, canonical_json(v)))
                .collect();
            format!("{{{}}}", entries.join(","))
        }
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", items.join(","))
        }
        _ => serde_json::to_string(value).unwrap_or_default(),
    }
}

/// Get the current Unix timestamp in seconds.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_url_basic() {
        let result = canonicalize_url("https://API.Example.com/v1/agents").unwrap();
        assert_eq!(result, "https://api.example.com/v1/agents");
    }

    #[test]
    fn canonical_url_sorted_query() {
        let result =
            canonicalize_url("https://api.example.com/v1/agents?offset=0&limit=10").unwrap();
        assert_eq!(
            result,
            "https://api.example.com/v1/agents?limit=10&offset=0"
        );
    }

    #[test]
    fn canonical_url_no_query() {
        let result = canonicalize_url("https://api.example.com/path").unwrap();
        assert!(!result.contains('?'));
    }

    #[test]
    fn canonical_url_strips_fragment() {
        let result =
            canonicalize_url("https://api.example.com/path?a=1#section").unwrap();
        assert!(!result.contains('#'));
        assert_eq!(result, "https://api.example.com/path?a=1");
    }

    #[test]
    fn canonical_url_with_port() {
        let result = canonicalize_url("https://localhost:8080/api").unwrap();
        assert_eq!(result, "https://localhost:8080/api");
    }

    #[test]
    fn canonical_json_sorted_keys() {
        let val: serde_json::Value =
            serde_json::from_str(r#"{"z":1,"a":"hello","m":[3,2,1]}"#).unwrap();
        let result = canonical_json(&val);
        assert_eq!(result, r#"{"a":"hello","m":[3,2,1],"z":1}"#);
    }

    #[test]
    fn canonical_json_nested() {
        let val: serde_json::Value =
            serde_json::from_str(r#"{"b":{"d":4,"c":3},"a":1}"#).unwrap();
        let result = canonical_json(&val);
        assert_eq!(result, r#"{"a":1,"b":{"c":3,"d":4}}"#);
    }

    #[test]
    fn canonical_json_empty_object() {
        let val: serde_json::Value = serde_json::from_str(r#"{}"#).unwrap();
        assert_eq!(canonical_json(&val), "{}");
    }

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
    fn msg_payload_sorted_to() {
        let body = serde_json::json!({});
        let payload = build_msg_payload(
            "test",
            "id1",
            "from",
            &["did:oaid:base:0xbbbb", "did:oaid:base:0xaaaa"],
            "",
            100,
            0,
            &body,
        );
        let lines: Vec<&str> = payload.split('\n').collect();
        // to DIDs should be sorted
        assert_eq!(lines[4], "did:oaid:base:0xaaaa,did:oaid:base:0xbbbb");
    }

    #[test]
    fn msg_payload_empty_to() {
        let body = serde_json::json!({});
        let payload = build_msg_payload("test", "id1", "from", &[], "", 100, 0, &body);
        let lines: Vec<&str> = payload.split('\n').collect();
        assert_eq!(lines[4], ""); // empty sorted_to
    }

    #[test]
    fn http_verify_wrong_body_fails() {
        let (sk, vk) = crypto::generate_keypair();

        let input = HttpSignInput {
            method: "POST",
            url: "https://api.example.com/test",
            body: b"original",
            timestamp: Some(1000),
            nonce: Some("0".repeat(32)),
        };

        let output = sign_http(&input, &sk).unwrap();

        // Verify with different body should fail
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
}
