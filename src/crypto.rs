//! Ed25519 key generation, signing, verification, and encoding utilities.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::Error;

/// Generate a new Ed25519 keypair using the OS CSPRNG.
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let mut csprng = rand::rngs::OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Sign `payload` bytes with the given Ed25519 signing key.
pub fn sign(payload: &[u8], key: &SigningKey) -> Signature {
    key.sign(payload)
}

/// Verify an Ed25519 signature against the given payload and verifying key.
pub fn verify(payload: &[u8], signature: &Signature, key: &VerifyingKey) -> bool {
    key.verify(payload, signature).is_ok()
}

/// Compute the SHA-256 hash of `data` and return it as a lowercase hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Encode bytes as base64url (no padding, RFC 4648 Section 5).
pub fn base64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decode a base64url (no padding) string to bytes.
pub fn base64url_decode(data: &str) -> Result<Vec<u8>, Error> {
    URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|e| Error::InvalidKey(format!("base64url decode failed: {e}")))
}

/// Decode a base64url-encoded Ed25519 public key (32 bytes) into a [`VerifyingKey`].
pub fn decode_verifying_key(b64: &str) -> Result<VerifyingKey, Error> {
    let bytes = base64url_decode(b64)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::InvalidKey("public key must be 32 bytes".into()))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| Error::InvalidKey(format!("invalid Ed25519 public key: {e}")))
}

/// Decode a base64url-encoded Ed25519 private key (32-byte seed) into a [`SigningKey`].
///
/// Accepts either 32 bytes (seed only) or 64 bytes (seed + public key, only the
/// first 32 bytes are used).
pub fn decode_signing_key(b64: &str) -> Result<SigningKey, Error> {
    let bytes = base64url_decode(b64)?;
    if bytes.len() != 32 && bytes.len() != 64 {
        return Err(Error::InvalidKey(format!(
            "private key must be 32 or 64 bytes, got {}",
            bytes.len()
        )));
    }
    let seed: [u8; 32] = bytes[..32]
        .try_into()
        .map_err(|_| Error::InvalidKey("invalid private key bytes".into()))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Generate a random 16-byte nonce and return it as a 32-character hex string.
pub fn generate_nonce() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rng.gen();
    hex::encode(bytes)
}

// ---------------------------------------------------------------------------
// End-to-end encryption (NaCl box: X25519-XSalsa20-Poly1305)
// ---------------------------------------------------------------------------

use crypto_box::{
    aead::{Aead, AeadCore, OsRng},
    PublicKey as BoxPublicKey, SalsaBox, SecretKey as BoxSecretKey,
};
use curve25519_dalek::edwards::CompressedEdwardsY;

/// Convert an Ed25519 public key (32 bytes) to an X25519 public key.
pub fn ed25519_to_x25519_public(ed25519_pub: &[u8; 32]) -> Result<[u8; 32], Error> {
    let compressed = CompressedEdwardsY::from_slice(ed25519_pub)
        .map_err(|e| Error::InvalidKey(format!("invalid Ed25519 public key: {e}")))?;
    let edwards = compressed
        .decompress()
        .ok_or_else(|| Error::InvalidKey("failed to decompress Ed25519 point".into()))?;
    Ok(edwards.to_montgomery().to_bytes())
}

/// Convert an Ed25519 private key (signing key) to an X25519 private key.
///
/// This uses the standard procedure: SHA-512 hash of the seed, take the first
/// 32 bytes and clamp.
pub fn ed25519_to_x25519_private(signing_key: &SigningKey) -> [u8; 32] {
    // Standard conversion: SHA-512(seed), take first 32 bytes, clamp.
    use sha2::Sha512;
    let hash = <Sha512 as Digest>::digest(signing_key.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash[..32]);
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
    key
}

/// Encrypt plaintext for a recipient using NaCl box (X25519-XSalsa20-Poly1305).
///
/// Returns `[24-byte nonce][ciphertext + 16-byte MAC]`.
pub fn encrypt_for(
    plaintext: &[u8],
    recipient_ed25519_pub: &[u8; 32],
    sender_signing_key: &SigningKey,
) -> Result<Vec<u8>, Error> {
    let sender_x25519 = ed25519_to_x25519_private(sender_signing_key);
    let recipient_x25519 = ed25519_to_x25519_public(recipient_ed25519_pub)?;

    let sender_secret = BoxSecretKey::from(sender_x25519);
    let recipient_public = BoxPublicKey::from(recipient_x25519);

    let salsa_box = SalsaBox::new(&recipient_public, &sender_secret);
    let nonce = SalsaBox::generate_nonce(&mut OsRng);
    let encrypted = salsa_box
        .encrypt(&nonce, plaintext)
        .map_err(|e| Error::Signing(format!("encryption failed: {e}")))?;

    let mut result = Vec::with_capacity(24 + encrypted.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&encrypted);
    Ok(result)
}

/// Decrypt ciphertext from a sender using NaCl box.
///
/// The ciphertext must include the 24-byte nonce prefix.
pub fn decrypt_from(
    ciphertext: &[u8],
    sender_ed25519_pub: &[u8; 32],
    recipient_signing_key: &SigningKey,
) -> Result<Vec<u8>, Error> {
    if ciphertext.len() < 24 {
        return Err(Error::InvalidKey("ciphertext too short".into()));
    }

    let recipient_x25519 = ed25519_to_x25519_private(recipient_signing_key);
    let sender_x25519 = ed25519_to_x25519_public(sender_ed25519_pub)?;

    let recipient_secret = BoxSecretKey::from(recipient_x25519);
    let sender_public = BoxPublicKey::from(sender_x25519);

    let salsa_box = SalsaBox::new(&sender_public, &recipient_secret);

    let nonce = crypto_box::Nonce::from_slice(&ciphertext[..24]);
    salsa_box
        .decrypt(nonce, &ciphertext[24..])
        .map_err(|e| Error::Verification(format!("decryption failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_sign_verify_roundtrip() {
        let (signing, verifying) = generate_keypair();
        let msg = b"hello oaid v2";
        let sig = sign(msg, &signing);
        assert!(verify(msg, &sig, &verifying));
    }

    #[test]
    fn wrong_key_rejects() {
        let (signing, _) = generate_keypair();
        let (_, other_verifying) = generate_keypair();
        let sig = sign(b"hello", &signing);
        assert!(!verify(b"hello", &sig, &other_verifying));
    }

    #[test]
    fn sha256_empty() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_json() {
        assert_eq!(
            sha256_hex(b"{\"task\":\"search\"}"),
            "0dfd9a0e52fe94a5e6311a6ef4643304c65636ae7fc316a0334e91c9665370af"
        );
    }

    #[test]
    fn base64url_roundtrip() {
        let data = b"open agent id v2";
        let encoded = base64url_encode(data);
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn decode_verifying_key_valid() {
        let (_, vk) = generate_keypair();
        let b64 = base64url_encode(vk.as_bytes());
        let decoded = decode_verifying_key(&b64).unwrap();
        assert_eq!(decoded.as_bytes(), vk.as_bytes());
    }

    #[test]
    fn decode_signing_key_32_bytes() {
        let (sk, _) = generate_keypair();
        let b64 = base64url_encode(&sk.to_bytes());
        let decoded = decode_signing_key(&b64).unwrap();
        assert_eq!(decoded.to_bytes(), sk.to_bytes());
    }

    #[test]
    fn nonce_length() {
        let nonce = generate_nonce();
        assert_eq!(nonce.len(), 32);
        assert!(nonce.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn key_conversion_deterministic() {
        let (sk, vk) = generate_keypair();
        let x_pub1 = ed25519_to_x25519_public(vk.as_bytes()).unwrap();
        let x_pub2 = ed25519_to_x25519_public(vk.as_bytes()).unwrap();
        assert_eq!(x_pub1, x_pub2);
        assert_eq!(x_pub1.len(), 32);

        let x_priv1 = ed25519_to_x25519_private(&sk);
        let x_priv2 = ed25519_to_x25519_private(&sk);
        assert_eq!(x_priv1, x_priv2);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let (sender_sk, _sender_vk) = generate_keypair();
        let (recipient_sk, recipient_vk) = generate_keypair();

        let plaintext = b"hello agent world";
        let ciphertext =
            encrypt_for(plaintext, recipient_vk.as_bytes(), &sender_sk).unwrap();

        // nonce (24) + MAC (16) + plaintext
        assert_eq!(ciphertext.len(), 24 + 16 + plaintext.len());

        let decrypted =
            decrypt_from(&ciphertext, _sender_vk.as_bytes(), &recipient_sk).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let (sender_sk, sender_vk) = generate_keypair();
        let (_recipient_sk, recipient_vk) = generate_keypair();
        let (wrong_sk, _) = generate_keypair();

        let plaintext = b"secret message";
        let ciphertext =
            encrypt_for(plaintext, recipient_vk.as_bytes(), &sender_sk).unwrap();

        let result = decrypt_from(&ciphertext, sender_vk.as_bytes(), &wrong_sk);
        assert!(result.is_err());
    }

    #[test]
    fn encrypt_decrypt_empty_message() {
        let (sender_sk, sender_vk) = generate_keypair();
        let (recipient_sk, recipient_vk) = generate_keypair();

        let ciphertext = encrypt_for(b"", recipient_vk.as_bytes(), &sender_sk).unwrap();
        let decrypted =
            decrypt_from(&ciphertext, sender_vk.as_bytes(), &recipient_sk).unwrap();
        assert_eq!(decrypted, b"");
    }

    #[test]
    fn rfc8032_test_vector_1() {
        let seed_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        let seed_bytes = hex::decode(seed_hex).unwrap();
        let sk = SigningKey::from_bytes(&seed_bytes.try_into().unwrap());
        let sig = sign(b"", &sk);
        let expected = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
        assert_eq!(hex::encode(sig.to_bytes()), expected);
    }
}
