use agent_id::crypto::{self, base64url_decode, base64url_encode, sha256_hex};
use ed25519_dalek::SigningKey;

#[test]
fn test_sha256_empty_string() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn test_sha256_json_body() {
    assert_eq!(
        sha256_hex(b"{\"task\":\"search\"}"),
        "0dfd9a0e52fe94a5e6311a6ef4643304c65636ae7fc316a0334e91c9665370af"
    );
}

#[test]
fn test_sign_verify_roundtrip() {
    let (signing, verifying) = crypto::generate_keypair();
    let payload = b"test payload";
    let signature = crypto::sign(payload, &signing);
    assert!(crypto::verify(payload, &signature, &verifying));
}

#[test]
fn test_sign_verify_wrong_payload() {
    let (signing, verifying) = crypto::generate_keypair();
    let signature = crypto::sign(b"correct", &signing);
    assert!(!crypto::verify(b"wrong", &signature, &verifying));
}

#[test]
fn test_known_keypair_empty_signature() {
    // Test vector from vectors.json
    let private_seed_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    let seed_bytes = hex::decode(private_seed_hex).unwrap();
    let signing_key = SigningKey::from_bytes(&seed_bytes.try_into().unwrap());

    let sig = crypto::sign(b"", &signing_key);
    let expected = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
    assert_eq!(hex::encode(sig.to_bytes()), expected);
}

#[test]
fn test_known_public_key_base64url() {
    let private_seed_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    let seed_bytes = hex::decode(private_seed_hex).unwrap();
    let signing_key = SigningKey::from_bytes(&seed_bytes.try_into().unwrap());
    let verifying_key = signing_key.verifying_key();

    assert_eq!(
        base64url_encode(verifying_key.as_bytes()),
        "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    );
}

#[test]
fn test_base64url_roundtrip() {
    let data = vec![0u8, 1, 2, 3, 255, 254, 253];
    let encoded = base64url_encode(&data);
    let decoded = base64url_decode(&encoded).unwrap();
    assert_eq!(data, decoded);
}
