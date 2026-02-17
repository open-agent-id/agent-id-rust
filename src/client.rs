use crate::error::AgentIdError;
use serde::{Deserialize, Serialize};

/// Default API base URL for the Open Agent ID registry.
pub const DEFAULT_API_URL: &str = "https://api.openagentid.org/v1";

/// Options for registering a new agent.
#[derive(Debug, Clone, Serialize)]
pub struct RegisterOptions {
    /// Display name for the agent.
    pub name: String,
    /// Optional list of capabilities.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
    /// Platform API key for authentication.
    #[serde(skip)]
    pub api_key: Option<String>,
    /// Bearer token from wallet auth (alternative to api_key).
    #[serde(skip)]
    pub user_token: Option<String>,
    /// Optional custom API base URL.
    #[serde(skip)]
    pub api_url: Option<String>,
    /// Base64url-encoded Ed25519 public key for BYOK mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// Owner wallet address (for platform-key auth).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<String>,
}

/// Response from the register endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct RegisterResponse {
    pub did: String,
    pub public_key: String,
    /// Only present in legacy mode (when public_key was not provided).
    pub private_key: Option<String>,
    pub chain_status: String,
    pub created_at: String,
}

/// Public agent info returned from the lookup endpoint.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentInfo {
    pub did: String,
    pub name: String,
    pub public_key: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub status: String,
    pub chain_status: String,
    #[serde(default)]
    pub chain_tx_hash: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Register a new agent with the registry API.
pub async fn register_agent(opts: &RegisterOptions) -> Result<RegisterResponse, AgentIdError> {
    let base_url = opts
        .api_url
        .as_deref()
        .unwrap_or(DEFAULT_API_URL);

    let url = format!("{}/agents", base_url);

    let client = reqwest::Client::new();
    let mut req = client.post(&url).json(opts);

    // Add auth header
    if let Some(ref api_key) = opts.api_key {
        req = req.header("X-Platform-Key", api_key);
    } else if let Some(ref user_token) = opts.user_token {
        req = req.header("Authorization", format!("Bearer {}", user_token));
    }

    let resp = req
        .send()
        .await
        .map_err(|e| AgentIdError::ApiError(format!("Request failed: {}", e)))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp
            .text()
            .await
            .unwrap_or_else(|_| "unknown error".to_string());
        return Err(AgentIdError::ApiError(format!(
            "Registration failed ({}): {}",
            status, body
        )));
    }

    resp.json::<RegisterResponse>()
        .await
        .map_err(|e| AgentIdError::ApiError(format!("Failed to parse response: {}", e)))
}

/// Look up an agent by DID from the registry API.
pub async fn get_agent(did: &str, api_url: Option<&str>) -> Result<AgentInfo, AgentIdError> {
    let base_url = api_url.unwrap_or(DEFAULT_API_URL);
    let url = format!("{}/agents/{}", base_url, did);

    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| AgentIdError::ApiError(format!("Request failed: {}", e)))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp
            .text()
            .await
            .unwrap_or_else(|_| "unknown error".to_string());
        return Err(AgentIdError::ApiError(format!(
            "Lookup failed ({}): {}",
            status, body
        )));
    }

    resp.json::<AgentInfo>()
        .await
        .map_err(|e| AgentIdError::ApiError(format!("Failed to parse response: {}", e)))
}
