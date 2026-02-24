//! Client for the `oaid-signer` daemon.
//!
//! The signer daemon holds Ed25519 private keys and exposes a Unix socket
//! interface for signing operations. The wire protocol uses a 4-byte big-endian
//! length prefix followed by a JSON message body.
//!
//! # Example
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), open_agent_id::Error> {
//! use open_agent_id::signer::SignerClient;
//!
//! let client = SignerClient::connect("/var/run/oaid-signer.sock").await?;
//! let signature = client.sign("my-key-id", "http", b"payload-bytes").await?;
//! # Ok(())
//! # }
//! ```

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::error::Error;

/// A client that communicates with the `oaid-signer` daemon over a Unix socket.
pub struct SignerClient {
    path: String,
}

/// A request to the signer daemon.
#[derive(Debug, Serialize)]
enum SignerRequest {
    Sign {
        key_id: String,
        operation: String,
        data: String,
    },
}

/// A response from the signer daemon.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum SignerResponse {
    Ok { signature: String },
    Err { error: String },
}

impl SignerClient {
    /// Connect to the signer daemon at the given Unix socket path.
    ///
    /// This validates that the socket is reachable but does not keep a persistent
    /// connection; each signing request opens a new connection.
    pub async fn connect(path: &str) -> Result<Self, Error> {
        // Verify the socket exists by attempting a connection
        let stream = UnixStream::connect(path)
            .await
            .map_err(|e| Error::Signer(format!("cannot connect to {path}: {e}")))?;
        drop(stream);

        Ok(Self {
            path: path.to_string(),
        })
    }

    /// Create a client without verifying connectivity.
    ///
    /// Useful when the daemon may not be running yet.
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
        }
    }

    /// Request the signer daemon to sign data.
    ///
    /// # Arguments
    ///
    /// - `key_id`: The key identifier known to the signer daemon.
    /// - `operation`: The signing domain, e.g. `"http"` or `"msg"`.
    /// - `data`: The raw bytes to sign (will be base64url-encoded for the wire).
    ///
    /// # Returns
    ///
    /// The base64url-encoded Ed25519 signature.
    pub async fn sign(&self, key_id: &str, operation: &str, data: &[u8]) -> Result<String, Error> {
        let request = SignerRequest::Sign {
            key_id: key_id.to_string(),
            operation: operation.to_string(),
            data: crate::crypto::base64url_encode(data),
        };

        let request_json =
            serde_json::to_vec(&request).map_err(|e| Error::Signer(format!("serialize: {e}")))?;

        let mut stream = UnixStream::connect(&self.path)
            .await
            .map_err(|e| Error::Signer(format!("connect: {e}")))?;

        // Write: 4-byte big-endian length + JSON body
        let len = request_json.len() as u32;
        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| Error::Signer(format!("write length: {e}")))?;
        stream
            .write_all(&request_json)
            .await
            .map_err(|e| Error::Signer(format!("write body: {e}")))?;
        stream
            .flush()
            .await
            .map_err(|e| Error::Signer(format!("flush: {e}")))?;

        // Read: 4-byte big-endian length + JSON body
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| Error::Signer(format!("read length: {e}")))?;
        let resp_len = u32::from_be_bytes(len_buf) as usize;

        if resp_len > 1024 * 1024 {
            return Err(Error::Signer(format!(
                "response too large: {resp_len} bytes"
            )));
        }

        let mut resp_buf = vec![0u8; resp_len];
        stream
            .read_exact(&mut resp_buf)
            .await
            .map_err(|e| Error::Signer(format!("read body: {e}")))?;

        let response: SignerResponse = serde_json::from_slice(&resp_buf)
            .map_err(|e| Error::Signer(format!("deserialize response: {e}")))?;

        match response {
            SignerResponse::Ok { signature } => Ok(signature),
            SignerResponse::Err { error } => Err(Error::Signer(format!("signer error: {error}"))),
        }
    }
}
