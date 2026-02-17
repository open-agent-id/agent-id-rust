use thiserror::Error;

/// Error types for the Open Agent ID SDK.
#[derive(Debug, Error)]
pub enum AgentIdError {
    #[error("Invalid DID format: {0}")]
    InvalidDid(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Signing error: {0}")]
    SigningError(String),

    #[error("Verification error: {0}")]
    VerificationError(String),

    #[error("API error: {0}")]
    ApiError(String),

    #[error("Cache error: {0}")]
    CacheError(String),
}
