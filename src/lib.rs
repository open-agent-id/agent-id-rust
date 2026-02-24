//! # Open Agent ID — Rust SDK
//!
//! Sign, verify, and manage AI agent identities using the
//! [Open Agent ID](https://openagentid.org) protocol (V2).
//!
//! ## DID Format
//!
//! ```text
//! did:oaid:{chain}:{agent_address}
//! ```
//!
//! - `chain`: lowercase chain identifier (e.g. `"base"`)
//! - `agent_address`: `0x` + 40 lowercase hex chars (CREATE2-derived contract address)
//!
//! ## Quick Start
//!
//! ```rust
//! use open_agent_id::{crypto, did::Did, signing};
//!
//! // Generate a keypair
//! let (signing_key, verifying_key) = crypto::generate_keypair();
//!
//! // Parse a DID
//! let did = Did::parse("did:oaid:base:0x7f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e").unwrap();
//!
//! // Sign an HTTP request
//! let output = signing::sign_http(
//!     &signing::HttpSignInput {
//!         method: "POST",
//!         url: "https://api.example.com/v1/agents",
//!         body: b"{}",
//!         timestamp: None,
//!         nonce: None,
//!     },
//!     &signing_key,
//! ).unwrap();
//!
//! // Verify
//! let valid = signing::verify_http(
//!     "POST",
//!     "https://api.example.com/v1/agents",
//!     b"{}",
//!     output.timestamp,
//!     &output.nonce,
//!     &output.signature,
//!     &verifying_key,
//! ).unwrap();
//! assert!(valid);
//! ```

pub mod crypto;
pub mod did;
pub mod error;
pub mod signing;
pub mod types;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "signer")]
pub mod signer;

// Re-export primary types at the crate root.
pub use did::Did;
pub use error::Error;
pub use types::*;
