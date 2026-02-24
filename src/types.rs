//! Shared types used across the SDK.

use serde::{Deserialize, Serialize};

/// Public information about a registered agent, as returned by the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    /// The agent's DID (`did:oaid:{chain}:{address}`).
    pub did: String,
    /// Human-readable display name.
    #[serde(default)]
    pub name: Option<String>,
    /// Base64url-encoded Ed25519 public key.
    pub public_key: String,
    /// The owner wallet address.
    pub wallet_address: String,
    /// The agent's contract address.
    pub agent_address: String,
    /// The chain identifier.
    pub chain: String,
    /// Optional list of capabilities.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Optional platform metadata.
    #[serde(default)]
    pub platform: Option<String>,
    /// Optional inbox endpoint URL.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Endpoint type: `"http"`, `"ws"`, or `"registry"`.
    #[serde(default)]
    pub endpoint_type: Option<String>,
    /// Chain anchoring status: `"pending"`, `"submitted"`, or `"anchored"`.
    pub chain_status: String,
    /// Whether the agent wallet contract has been deployed.
    #[serde(default)]
    pub wallet_deployed: bool,
    /// Creation timestamp (ISO 8601).
    pub created_at: String,
    /// Last update timestamp (ISO 8601).
    pub updated_at: String,
}

/// Request body for registering a new agent.
#[derive(Debug, Clone, Serialize)]
pub struct RegistrationRequest {
    /// Human-readable display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Optional list of capabilities.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
    /// Base64url-encoded Ed25519 public key (BYOK).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

/// Response from the registration endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct RegistrationResponse {
    /// The newly assigned DID.
    pub did: String,
    /// The computed agent contract address.
    pub agent_address: String,
    /// Base64url-encoded Ed25519 public key.
    pub public_key: String,
    /// Chain anchoring status.
    pub chain_status: String,
    /// Creation timestamp.
    pub created_at: String,
}

/// Challenge returned by `POST /v1/auth/challenge`.
#[derive(Debug, Clone, Deserialize)]
pub struct Challenge {
    /// Unique identifier for this challenge.
    pub challenge_id: String,
    /// Human-readable text to sign with the wallet.
    pub text: String,
}

/// Request body for `POST /v1/auth/wallet`.
#[derive(Debug, Clone, Serialize)]
pub struct WalletAuthRequest {
    /// The wallet address (checksummed or lowercase).
    pub wallet: String,
    /// The challenge ID from the challenge endpoint.
    pub challenge_id: String,
    /// The wallet's signature of the challenge text.
    pub signature: String,
}

/// Response from `POST /v1/auth/wallet`.
#[derive(Debug, Clone, Deserialize)]
pub struct WalletAuthResponse {
    /// The bearer token (`oaid_...`).
    pub token: String,
}

/// Request body for `POST /v1/verify`.
#[derive(Debug, Clone, Serialize)]
pub struct VerifyRequest {
    /// The domain: `"oaid-http/v1"` or `"oaid-msg/v1"`.
    pub domain: String,
    /// The canonical payload that was signed.
    pub payload: String,
    /// Base64url-encoded Ed25519 signature.
    pub signature: String,
    /// The signer's DID.
    pub did: String,
}

/// Response from `POST /v1/verify`.
#[derive(Debug, Clone, Deserialize)]
pub struct VerifyResponse {
    /// Whether the signature is valid.
    pub valid: bool,
}

/// Request body for `PUT /v1/agents/{did}/key` (key rotation).
#[derive(Debug, Clone, Serialize)]
pub struct RotateKeyRequest {
    /// The new base64url-encoded Ed25519 public key.
    pub public_key: String,
}
