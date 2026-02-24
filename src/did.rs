//! DID parsing, validation, and formatting for the `did:oaid` method.
//!
//! The V2 DID format is: `did:oaid:{chain}:{agent_address}`
//!
//! - `chain`: lowercase chain identifier (e.g. `"base"`, `"base-sepolia"`)
//! - `agent_address`: `0x` + 40 lowercase hex characters
//!
//! Total length must not exceed 80 characters.

use crate::error::Error;

/// Parsed components of a `did:oaid` DID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Did {
    /// The chain identifier (e.g. `"base"`).
    pub chain: String,
    /// The agent contract address (`0x` + 40 hex chars, lowercase).
    pub address: String,
}

impl Did {
    /// Parse and validate a DID string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidDid`] if the string does not match the
    /// `did:oaid:{chain}:{0x...}` format.
    pub fn parse(did: &str) -> Result<Self, Error> {
        let normalized = did.to_ascii_lowercase();

        if normalized.len() > 80 {
            return Err(Error::InvalidDid(format!(
                "DID exceeds 80 characters: {did}"
            )));
        }

        let parts: Vec<&str> = normalized.splitn(4, ':').collect();
        if parts.len() != 4 {
            return Err(Error::InvalidDid(format!(
                "expected 4 colon-separated parts: {did}"
            )));
        }

        if parts[0] != "did" {
            return Err(Error::InvalidDid(format!(
                "must start with 'did:': {did}"
            )));
        }

        if parts[1] != "oaid" {
            return Err(Error::InvalidDid(format!(
                "method must be 'oaid': {did}"
            )));
        }

        let chain = parts[2];
        if chain.is_empty() || !chain.chars().all(|c| c.is_ascii_lowercase() || c == '-' || c.is_ascii_digit()) {
            return Err(Error::InvalidDid(format!(
                "invalid chain identifier: {chain}"
            )));
        }

        let address = parts[3];
        if !is_valid_address(address) {
            return Err(Error::InvalidDid(format!(
                "invalid agent address (expected 0x + 40 hex chars): {address}"
            )));
        }

        Ok(Self {
            chain: chain.to_string(),
            address: address.to_string(),
        })
    }

    /// Format this DID back into its canonical string representation.
    pub fn to_string(&self) -> String {
        format!("did:oaid:{}:{}", self.chain, self.address)
    }

    /// Build a DID from chain and address components.
    ///
    /// The address is normalized to lowercase.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidDid`] if the address is not a valid `0x` + 40 hex chars.
    pub fn new(chain: &str, address: &str) -> Result<Self, Error> {
        let normalized = address.to_ascii_lowercase();
        if !is_valid_address(&normalized) {
            return Err(Error::InvalidDid(format!(
                "invalid agent address: {address}"
            )));
        }
        let chain = chain.to_ascii_lowercase();
        Ok(Self {
            chain,
            address: normalized,
        })
    }
}

impl std::fmt::Display for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "did:oaid:{}:{}", self.chain, self.address)
    }
}

/// Check if a string is a valid Ethereum-style address: `0x` + 40 hex characters.
fn is_valid_address(s: &str) -> bool {
    s.len() == 42
        && s.starts_with("0x")
        && s[2..].chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// Validate a DID string without returning the parsed result.
pub fn validate(did: &str) -> bool {
    Did::parse(did).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_did() {
        let did = Did::parse("did:oaid:base:0x7f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e").unwrap();
        assert_eq!(did.chain, "base");
        assert_eq!(did.address, "0x7f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e");
    }

    #[test]
    fn normalizes_to_lowercase() {
        let did = Did::parse("did:oaid:Base:0x7F4E3D2C1B0A9F8E7D6C5B4A3F2E1D0C9B8A7F6E").unwrap();
        assert_eq!(did.chain, "base");
        assert_eq!(did.address, "0x7f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e");
    }

    #[test]
    fn valid_did_base_sepolia() {
        let did = Did::parse("did:oaid:base-sepolia:0x0000000000000000000000000000000000000001").unwrap();
        assert_eq!(did.chain, "base-sepolia");
    }

    #[test]
    fn display_roundtrip() {
        let input = "did:oaid:base:0x7f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e";
        let did = Did::parse(input).unwrap();
        assert_eq!(did.to_string(), input);
    }

    #[test]
    fn reject_v1_did() {
        assert!(Did::parse("did:agent:tokli:agt_a1B2c3D4e5").is_err());
    }

    #[test]
    fn reject_bad_method() {
        assert!(Did::parse("did:xxx:base:0x0000000000000000000000000000000000000001").is_err());
    }

    #[test]
    fn reject_short_address() {
        assert!(Did::parse("did:oaid:base:0x1234").is_err());
    }

    #[test]
    fn reject_missing_0x() {
        assert!(Did::parse("did:oaid:base:7f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e").is_err());
    }

    #[test]
    fn reject_uppercase_hex_only() {
        // After normalization, uppercase hex becomes lowercase, so this should pass
        let result = Did::parse("did:oaid:base:0xABCDEF0000000000000000000000000000000000");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().address, "0xabcdef0000000000000000000000000000000000");
    }

    #[test]
    fn reject_empty() {
        assert!(Did::parse("").is_err());
    }

    #[test]
    fn reject_too_long() {
        // chain name that makes total > 80
        let long_chain = "a".repeat(60);
        let did_str = format!("did:oaid:{long_chain}:0x0000000000000000000000000000000000000001");
        assert!(Did::parse(&did_str).is_err());
    }

    #[test]
    fn new_constructs_correctly() {
        let did = Did::new("base", "0xAbCdEf0000000000000000000000000000000000").unwrap();
        assert_eq!(did.address, "0xabcdef0000000000000000000000000000000000");
        assert_eq!(did.chain, "base");
    }

    #[test]
    fn validate_helper() {
        assert!(validate("did:oaid:base:0x0000000000000000000000000000000000000001"));
        assert!(!validate("garbage"));
    }
}
