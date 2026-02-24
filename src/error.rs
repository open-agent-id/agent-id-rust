//! Error types for the Open Agent ID SDK.

use thiserror::Error;

/// Unified error type for all Open Agent ID operations.
#[derive(Debug, Error)]
pub enum Error {
    /// The DID string is malformed or does not conform to the `did:oaid:{chain}:{address}` format.
    #[error("invalid DID: {0}")]
    InvalidDid(String),

    /// An Ed25519 key is malformed or the wrong length.
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// A signing operation failed (e.g. no private key available).
    #[error("signing error: {0}")]
    Signing(String),

    /// Signature verification failed.
    #[error("verification error: {0}")]
    Verification(String),

    /// A registry API call failed.
    #[cfg(feature = "client")]
    #[error("API error: {0}")]
    Api(String),

    /// Communication with the oaid-signer daemon failed.
    #[cfg(feature = "signer")]
    #[error("signer error: {0}")]
    Signer(String),

    /// An invalid URL was provided for canonical construction.
    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    /// JSON serialization or deserialization failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}
