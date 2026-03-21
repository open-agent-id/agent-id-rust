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
    /// Nonce (key rotation counter).
    #[serde(default)]
    pub nonce: i64,
    /// On-chain transaction hash, if submitted or anchored.
    #[serde(default)]
    pub chain_tx_hash: Option<String>,
    /// Credit score, if available.
    #[serde(default)]
    pub credit_score: Option<i32>,
    /// DID of the referring agent, if any.
    #[serde(default)]
    pub referred_by: Option<String>,
    /// Creation timestamp (ISO 8601).
    pub created_at: String,
    /// Last update timestamp (ISO 8601).
    pub updated_at: String,
}

/// Response from `GET /v1/agents` (list agents).
#[derive(Debug, Clone, Deserialize)]
pub struct ListAgentsResponse {
    /// The list of agents.
    pub agents: Vec<AgentInfo>,
    /// Cursor for the next page, if any.
    pub next_cursor: Option<String>,
}

/// Credit score information for an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditInfo {
    /// The agent's DID.
    pub did: String,
    /// Numeric credit score.
    pub credit_score: i32,
    /// Credit level (e.g. `"standard"`).
    pub level: String,
    /// Whether the agent is verified.
    pub verified: bool,
    /// Whether the agent is flagged.
    pub flagged: bool,
    /// Number of currently active reports (12-month window).
    pub active_reports: i64,
    /// Total lifetime reports.
    pub lifetime_reports: i64,
    /// Number of active verified referrals (12-month window).
    #[serde(default)]
    pub active_referrals: i64,
    /// Total lifetime referrals.
    #[serde(default)]
    pub lifetime_referrals: i64,
    /// Registration timestamp (ISO 8601).
    pub registered_at: String,
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
    /// Base64url-encoded Ed25519 public key.
    pub public_key: String,
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
    pub challenge: String,
}

/// Request body for `POST /v1/auth/wallet`.
#[derive(Debug, Clone, Serialize)]
pub struct WalletAuthRequest {
    /// The wallet address (checksummed or lowercase).
    pub wallet_address: String,
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
