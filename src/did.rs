use crate::error::AgentIdError;
use regex::Regex;

/// Components of a parsed DID.
#[derive(Debug, Clone, PartialEq)]
pub struct DidComponents {
    /// The full DID string.
    pub did: String,
    /// The DID method (always "agent").
    pub method: String,
    /// The platform identifier (e.g. "tokli", "openai").
    pub platform: String,
    /// The unique agent ID (e.g. "agt_a1B2c3D4e5").
    pub unique_id: String,
}

/// Validate whether a DID string matches the Open Agent ID format.
///
/// Rules:
/// 1. Method must be "agent"
/// 2. Platform must be 3-20 chars, lowercase [a-z0-9]
/// 3. Unique ID must be "agt_" + exactly 10 base62 chars [0-9A-Za-z]
/// 4. Total length must not exceed 60 characters
pub fn validate_did(did: &str) -> bool {
    if did.is_empty() || did.len() > 60 {
        return false;
    }
    let re = Regex::new(r"^did:agent:[a-z0-9]{3,20}:agt_[0-9A-Za-z]{10}$").unwrap();
    re.is_match(did)
}

/// Parse a DID string into its components.
pub fn parse_did(did: &str) -> Result<DidComponents, AgentIdError> {
    if !validate_did(did) {
        return Err(AgentIdError::InvalidDid(format!(
            "Invalid DID format: {}",
            did
        )));
    }

    let parts: Vec<&str> = did.splitn(4, ':').collect();
    // parts = ["did", "agent", "{platform}", "{unique_id}"]
    Ok(DidComponents {
        did: did.to_string(),
        method: parts[1].to_string(),
        platform: parts[2].to_string(),
        unique_id: parts[3].to_string(),
    })
}

/// Generate a random unique ID in the format "agt_" + 10 base62 characters.
pub fn generate_unique_id() -> String {
    use rand::Rng;
    const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut rng = rand::thread_rng();
    let id: String = (0..10)
        .map(|_| {
            let idx = rng.gen_range(0..62);
            BASE62[idx] as char
        })
        .collect();
    format!("agt_{}", id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_dids() {
        let valid = vec![
            "did:agent:tokli:agt_a1B2c3D4e5",
            "did:agent:openai:agt_X9yZ8wV7u6",
            "did:agent:langchain:agt_Q3rS4tU5v6",
            "did:agent:abc:agt_0000000000",
        ];
        for did in valid {
            assert!(validate_did(did), "Expected valid: {}", did);
        }
    }

    #[test]
    fn test_invalid_dids() {
        let invalid = vec![
            "did:agent:AB:agt_a1B2c3D4e5",
            "did:agent:toolongplatformnamehere:agt_a1B2c3D4e5",
            "did:agent:tokli:a1B2c3D4e5",
            "did:agent:tokli:agt_short",
            "did:agent:tokli:agt_a1B2c3D4e5!",
            "did:other:tokli:agt_a1B2c3D4e5",
            "did:agent:UPPER:agt_a1B2c3D4e5",
            "",
        ];
        for did in invalid {
            assert!(!validate_did(did), "Expected invalid: {}", did);
        }
    }

    #[test]
    fn test_parse_did() {
        let components = parse_did("did:agent:tokli:agt_a1B2c3D4e5").unwrap();
        assert_eq!(components.method, "agent");
        assert_eq!(components.platform, "tokli");
        assert_eq!(components.unique_id, "agt_a1B2c3D4e5");
    }

    #[test]
    fn test_parse_invalid_did() {
        assert!(parse_did("invalid").is_err());
    }

    #[test]
    fn test_generate_unique_id() {
        let id = generate_unique_id();
        assert!(id.starts_with("agt_"));
        assert_eq!(id.len(), 14); // "agt_" (4) + 10 chars
        // Validate it produces a valid DID when combined
        let did = format!("did:agent:test:{}", id);
        assert!(validate_did(&did));
    }
}
