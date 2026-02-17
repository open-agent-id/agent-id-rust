use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

use crate::cache::KeyCache;
use crate::client::{self, AgentInfo, RegisterOptions};
use crate::crypto::{self, base64url_decode, base64url_encode, sha256_hex};
use crate::did;
use crate::error::AgentIdError;

/// Lazily initialized global key cache.
fn global_cache() -> &'static KeyCache {
    use std::sync::OnceLock;
    static CACHE: OnceLock<KeyCache> = OnceLock::new();
    CACHE.get_or_init(KeyCache::default_ttl)
}

/// The main identity struct representing an AI agent.
///
/// Holds the DID, keypair, and provides methods for signing and verification.
pub struct AgentIdentity {
    did: String,
    private_key: Option<SigningKey>,
    public_key: VerifyingKey,
}

impl AgentIdentity {
    /// Register a new agent with the registry API.
    ///
    /// Returns an `AgentIdentity` with the private key, ready for signing.
    pub async fn register(opts: RegisterOptions) -> Result<Self, AgentIdError> {
        let resp = client::register_agent(&opts).await?;

        let private_bytes = base64url_decode(&resp.private_key)
            .map_err(|e| AgentIdError::InvalidKey(format!("Invalid private key encoding: {}", e)))?;

        // The private key from the API is 64 bytes: 32-byte seed + 32-byte public key.
        // ed25519-dalek SigningKey expects the 32-byte seed.
        if private_bytes.len() < 32 {
            return Err(AgentIdError::InvalidKey(
                "Private key too short".to_string(),
            ));
        }

        let seed: [u8; 32] = private_bytes[..32]
            .try_into()
            .map_err(|_| AgentIdError::InvalidKey("Invalid private key length".to_string()))?;

        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        if !did::validate_did(&resp.did) {
            return Err(AgentIdError::InvalidDid(format!(
                "Registry returned invalid DID: {}",
                resp.did
            )));
        }

        Ok(Self {
            did: resp.did,
            private_key: Some(signing_key),
            public_key: verifying_key,
        })
    }

    /// Load an identity from an existing DID and base64url-encoded private key.
    ///
    /// The private key can be either 32 bytes (seed only) or 64 bytes (seed + public key).
    pub fn load(did_str: &str, private_key_base64url: &str) -> Result<Self, AgentIdError> {
        if !did::validate_did(did_str) {
            return Err(AgentIdError::InvalidDid(format!(
                "Invalid DID: {}",
                did_str
            )));
        }

        let private_bytes = base64url_decode(private_key_base64url)
            .map_err(|e| AgentIdError::InvalidKey(format!("Invalid base64url encoding: {}", e)))?;

        if private_bytes.len() != 32 && private_bytes.len() != 64 {
            return Err(AgentIdError::InvalidKey(format!(
                "Private key must be 32 or 64 bytes, got {}",
                private_bytes.len()
            )));
        }

        let seed: [u8; 32] = private_bytes[..32]
            .try_into()
            .map_err(|_| AgentIdError::InvalidKey("Invalid private key bytes".to_string()))?;

        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            did: did_str.to_string(),
            private_key: Some(signing_key),
            public_key: verifying_key,
        })
    }

    /// Sign a payload string and return the base64url-encoded signature.
    pub fn sign(&self, payload: &str) -> Result<String, AgentIdError> {
        let signing_key = self
            .private_key
            .as_ref()
            .ok_or_else(|| AgentIdError::SigningError("No private key available".to_string()))?;

        let signature = crypto::sign(payload.as_bytes(), signing_key);
        Ok(base64url_encode(&signature.to_bytes()))
    }

    /// Sign an HTTP request and return a HashMap of headers to attach.
    ///
    /// Constructs the canonical payload as:
    /// `{method}\n{url}\n{body_hash}\n{timestamp}\n{nonce}`
    ///
    /// Returns headers: X-Agent-DID, X-Agent-Timestamp, X-Agent-Nonce, X-Agent-Signature.
    pub fn sign_request(
        &self,
        method: &str,
        url: &str,
        body: &str,
    ) -> Result<HashMap<String, String>, AgentIdError> {
        let body_hash = sha256_hex(body.as_bytes());
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AgentIdError::SigningError(format!("System time error: {}", e)))?
            .as_secs();
        let nonce = generate_nonce();

        let canonical = format!(
            "{}\n{}\n{}\n{}\n{}",
            method.to_uppercase(),
            url,
            body_hash,
            timestamp,
            nonce
        );

        let signature = self.sign(&canonical)?;

        let mut headers = HashMap::new();
        headers.insert("X-Agent-DID".to_string(), self.did.clone());
        headers.insert("X-Agent-Timestamp".to_string(), timestamp.to_string());
        headers.insert("X-Agent-Nonce".to_string(), nonce);
        headers.insert("X-Agent-Signature".to_string(), signature);

        Ok(headers)
    }

    /// Verify another agent's signature.
    ///
    /// Resolves the agent's public key from cache or the registry API,
    /// then verifies the Ed25519 signature against the payload.
    pub async fn verify(
        did_str: &str,
        payload: &str,
        signature: &str,
        api_url: Option<&str>,
    ) -> Result<bool, AgentIdError> {
        // Try cache first
        let cache = global_cache();
        let verifying_key = if let Some(key) = cache.get(did_str).await {
            key
        } else {
            // Fetch from API
            let info = client::get_agent(did_str, api_url).await?;
            let pub_bytes = base64url_decode(&info.public_key).map_err(|e| {
                AgentIdError::InvalidKey(format!("Invalid public key encoding: {}", e))
            })?;
            let key_bytes: [u8; 32] = pub_bytes.try_into().map_err(|_| {
                AgentIdError::InvalidKey("Public key must be 32 bytes".to_string())
            })?;
            let key = VerifyingKey::from_bytes(&key_bytes).map_err(|e| {
                AgentIdError::InvalidKey(format!("Invalid Ed25519 public key: {}", e))
            })?;
            cache.set(did_str, key).await;
            key
        };

        let sig_bytes = base64url_decode(signature).map_err(|e| {
            AgentIdError::VerificationError(format!("Invalid signature encoding: {}", e))
        })?;
        let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|_| {
            AgentIdError::VerificationError("Signature must be 64 bytes".to_string())
        })?;
        let sig = Signature::from_bytes(&sig_array);

        Ok(crypto::verify(payload.as_bytes(), &sig, &verifying_key))
    }

    /// Look up agent info by DID from the registry API.
    pub async fn lookup(
        did_str: &str,
        api_url: Option<&str>,
    ) -> Result<AgentInfo, AgentIdError> {
        client::get_agent(did_str, api_url).await
    }

    /// Get the DID string.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// Get the base64url-encoded public key.
    pub fn public_key_base64url(&self) -> String {
        base64url_encode(self.public_key.as_bytes())
    }
}

/// Generate a random 16-byte hex nonce.
fn generate_nonce() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rng.gen();
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_and_sign() {
        // Use the test vector keypair (32-byte seed derived from the hex in vectors.json)
        let private_key_b64 = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
        let did = "did:agent:tokli:agt_a1B2c3D4e5";

        let identity = AgentIdentity::load(did, private_key_b64).unwrap();
        assert_eq!(identity.did(), did);
        assert_eq!(identity.public_key_base64url(), "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");

        // Sign empty payload (RFC 8032 test vector 1)
        let sig = identity.sign("").unwrap();
        let sig_bytes = base64url_decode(&sig).unwrap();
        let expected_hex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
        assert_eq!(hex::encode(&sig_bytes), expected_hex);
    }

    #[test]
    fn test_load_invalid_did() {
        let result = AgentIdentity::load("invalid", "AAAA");
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_request_headers() {
        let private_key_b64 = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
        let did = "did:agent:tokli:agt_a1B2c3D4e5";

        let identity = AgentIdentity::load(did, private_key_b64).unwrap();
        let headers = identity
            .sign_request("POST", "https://api.example.com/v1/tasks", "{\"task\":\"search\"}")
            .unwrap();

        assert_eq!(headers.get("X-Agent-DID").unwrap(), did);
        assert!(headers.contains_key("X-Agent-Timestamp"));
        assert!(headers.contains_key("X-Agent-Nonce"));
        assert!(headers.contains_key("X-Agent-Signature"));

        // Nonce should be 32 hex chars (16 bytes)
        let nonce = headers.get("X-Agent-Nonce").unwrap();
        assert_eq!(nonce.len(), 32);
    }
}
