use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Generate a new Ed25519 keypair.
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let mut csprng = rand::rngs::OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Sign payload bytes with the given signing key.
pub fn sign(payload: &[u8], key: &SigningKey) -> Signature {
    key.sign(payload)
}

/// Verify a signature against payload bytes and a verifying key.
pub fn verify(payload: &[u8], signature: &Signature, key: &VerifyingKey) -> bool {
    key.verify(payload, signature).is_ok()
}

/// Compute the SHA-256 hex digest of the given data.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Encode bytes as base64url (no padding).
pub fn base64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decode base64url (no padding) to bytes.
pub fn base64url_decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let (signing, verifying) = generate_keypair();
        let msg = b"hello";
        let sig = sign(msg, &signing);
        assert!(verify(msg, &sig, &verifying));
    }

    #[test]
    fn test_sha256_empty() {
        let hash = sha256_hex(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_json_body() {
        let hash = sha256_hex(b"{\"task\":\"search\"}");
        assert_eq!(
            hash,
            "0dfd9a0e52fe94a5e6311a6ef4643304c65636ae7fc316a0334e91c9665370af"
        );
    }

    #[test]
    fn test_base64url_roundtrip() {
        let data = b"hello world";
        let encoded = base64url_encode(data);
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_known_keypair_sign_empty() {
        // Test vector: known keypair from vectors.json
        let private_key_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        let private_bytes = hex::decode(private_key_hex).unwrap();
        let signing_key =
            SigningKey::from_bytes(&private_bytes.try_into().expect("32 bytes"));

        let sig = sign(b"", &signing_key);
        let expected_sig_hex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
        assert_eq!(hex::encode(sig.to_bytes()), expected_sig_hex);
    }
}
