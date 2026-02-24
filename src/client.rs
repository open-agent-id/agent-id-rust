//! Registry API client for agent registration, lookup, and verification.
//!
//! All methods communicate with the Open Agent ID registry server over HTTPS.
//!
//! # Example
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), open_agent_id::Error> {
//! use open_agent_id::client::RegistryClient;
//!
//! let client = RegistryClient::new(None);
//!
//! // Look up an agent (no auth required)
//! let info = client.lookup("did:oaid:base:0x0000000000000000000000000000000000000001").await?;
//! println!("Agent: {:?}", info.name);
//! # Ok(())
//! # }
//! ```

use crate::error::Error;
use crate::types::*;

/// Default API base URL for the Open Agent ID registry.
pub const DEFAULT_API_URL: &str = "https://api.openagentid.org/v1";

/// HTTP client for the Open Agent ID registry API.
pub struct RegistryClient {
    base_url: String,
    http: reqwest::Client,
}

impl RegistryClient {
    /// Create a new client. If `base_url` is `None`, the default
    /// (`https://api.openagentid.org/v1`) is used.
    pub fn new(base_url: Option<&str>) -> Self {
        Self {
            base_url: base_url
                .unwrap_or(DEFAULT_API_URL)
                .trim_end_matches('/')
                .to_string(),
            http: reqwest::Client::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Auth
    // -----------------------------------------------------------------------

    /// Request a wallet authentication challenge.
    ///
    /// `POST /v1/auth/challenge`
    pub async fn challenge(&self) -> Result<Challenge, Error> {
        let url = format!("{}/auth/challenge", self.base_url);
        let resp = self
            .http
            .post(&url)
            .send()
            .await
            .map_err(|e| Error::Api(format!("challenge request failed: {e}")))?;
        Self::parse_response(resp).await
    }

    /// Authenticate with a wallet signature and receive a bearer token.
    ///
    /// `POST /v1/auth/wallet`
    pub async fn wallet_auth(&self, req: &WalletAuthRequest) -> Result<WalletAuthResponse, Error> {
        let url = format!("{}/auth/wallet", self.base_url);
        let resp = self
            .http
            .post(&url)
            .json(req)
            .send()
            .await
            .map_err(|e| Error::Api(format!("wallet auth request failed: {e}")))?;
        Self::parse_response(resp).await
    }

    // -----------------------------------------------------------------------
    // Agent CRUD
    // -----------------------------------------------------------------------

    /// Register a new agent.
    ///
    /// `POST /v1/agents` — requires wallet auth (`Authorization: Bearer oaid_...`).
    pub async fn register(
        &self,
        token: &str,
        req: &RegistrationRequest,
    ) -> Result<RegistrationResponse, Error> {
        let url = format!("{}/agents", self.base_url);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(token)
            .json(req)
            .send()
            .await
            .map_err(|e| Error::Api(format!("register request failed: {e}")))?;
        Self::parse_response(resp).await
    }

    /// Look up an agent by DID.
    ///
    /// `GET /v1/agents/{did}` — no auth required.
    pub async fn lookup(&self, did: &str) -> Result<AgentInfo, Error> {
        let url = format!("{}/agents/{}", self.base_url, did);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Api(format!("lookup request failed: {e}")))?;
        Self::parse_response(resp).await
    }

    /// List agents owned by a wallet address.
    ///
    /// `GET /v1/agents?owner={wallet}` — no auth required.
    pub async fn list_by_owner(
        &self,
        wallet: &str,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Vec<AgentInfo>, Error> {
        let mut url = format!("{}/agents?owner={}", self.base_url, wallet);
        if let Some(c) = cursor {
            url.push_str(&format!("&cursor={c}"));
        }
        if let Some(l) = limit {
            url.push_str(&format!("&limit={l}"));
        }
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Api(format!("list request failed: {e}")))?;
        Self::parse_response(resp).await
    }

    /// Delete (revoke) an agent.
    ///
    /// `DELETE /v1/agents/{did}` — requires wallet auth.
    pub async fn revoke(&self, token: &str, did: &str) -> Result<(), Error> {
        let url = format!("{}/agents/{}", self.base_url, did);
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| Error::Api(format!("revoke request failed: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::Api(format!("revoke failed ({status}): {body}")));
        }
        Ok(())
    }

    /// Rotate an agent's Ed25519 public key.
    ///
    /// `PUT /v1/agents/{did}/key` — requires wallet auth.
    pub async fn rotate_key(
        &self,
        token: &str,
        did: &str,
        req: &RotateKeyRequest,
    ) -> Result<(), Error> {
        let url = format!("{}/agents/{}/key", self.base_url, did);
        let resp = self
            .http
            .put(&url)
            .bearer_auth(token)
            .json(req)
            .send()
            .await
            .map_err(|e| Error::Api(format!("rotate key request failed: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::Api(format!(
                "rotate key failed ({status}): {body}"
            )));
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Verify
    // -----------------------------------------------------------------------

    /// Ask the registry to verify a signature.
    ///
    /// `POST /v1/verify` — no auth required.
    pub async fn verify(&self, req: &VerifyRequest) -> Result<VerifyResponse, Error> {
        let url = format!("{}/verify", self.base_url);
        let resp = self
            .http
            .post(&url)
            .json(req)
            .send()
            .await
            .map_err(|e| Error::Api(format!("verify request failed: {e}")))?;
        Self::parse_response(resp).await
    }

    // -----------------------------------------------------------------------
    // Deploy wallet
    // -----------------------------------------------------------------------

    /// Request deployment of the agent's on-chain wallet contract.
    ///
    /// `POST /v1/agents/{did}/deploy-wallet` — requires wallet auth.
    pub async fn deploy_wallet(&self, token: &str, did: &str) -> Result<(), Error> {
        let url = format!("{}/agents/{}/deploy-wallet", self.base_url, did);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| Error::Api(format!("deploy wallet request failed: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::Api(format!(
                "deploy wallet failed ({status}): {body}"
            )));
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    /// Parse a successful JSON response or return an API error.
    async fn parse_response<T: serde::de::DeserializeOwned>(
        resp: reqwest::Response,
    ) -> Result<T, Error> {
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::Api(format!("{status}: {body}")));
        }
        resp.json::<T>()
            .await
            .map_err(|e| Error::Api(format!("failed to parse response: {e}")))
    }
}
