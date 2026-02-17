//! # Open Agent ID - Rust SDK
//!
//! A Rust SDK for the Open Agent ID protocol, allowing AI agents to register,
//! sign requests, and verify other agents' signatures using Ed25519 cryptography.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use agent_id::{AgentIdentity, RegisterOptions};
//!
//! # async fn example() -> Result<(), agent_id::AgentIdError> {
//! // Register a new agent
//! let identity = AgentIdentity::register(RegisterOptions {
//!     name: "my-agent".to_string(),
//!     capabilities: Some(vec!["search".to_string()]),
//!     api_key: "your-api-key".to_string(),
//!     api_url: None,
//! }).await?;
//!
//! // Sign a payload
//! let signature = identity.sign("hello")?;
//!
//! // Sign an HTTP request
//! let headers = identity.sign_request("POST", "https://example.com/api", "{}")?;
//!
//! // Verify another agent's signature
//! let valid = AgentIdentity::verify(
//!     "did:agent:tokli:agt_a1B2c3D4e5",
//!     "hello",
//!     &signature,
//!     None,
//! ).await?;
//! # Ok(())
//! # }
//! ```

pub mod cache;
pub mod client;
pub mod crypto;
pub mod did;
pub mod error;
pub mod identity;

// Re-export main types at the crate root for convenience.
pub use client::{AgentInfo, RegisterOptions, RegisterResponse};
pub use error::AgentIdError;
pub use identity::AgentIdentity;
