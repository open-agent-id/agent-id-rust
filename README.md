# open-agent-id

Rust SDK for the [Open Agent ID](https://openagentid.org) protocol (V2). Sign and verify HTTP requests and P2P messages using Ed25519.

## Installation

```toml
[dependencies]
open-agent-id = "0.2"
```

Enable optional features:

```toml
open-agent-id = { version = "0.2", features = ["client", "signer"] }
```

## Quick Start

The most common use case is adding agent authentication headers to outbound requests:

```rust
use open_agent_id::signing::sign_agent_auth;

let headers = sign_agent_auth(
    "did:oaid:base:0x1234567890abcdef1234567890abcdef12345678",
    &signing_key, // ed25519_dalek::SigningKey
);
// Returns HashMap with:
//   "X-Agent-DID"       => "did:oaid:base:0x1234..."
//   "X-Agent-Timestamp" => "1708123456"
//   "X-Agent-Nonce"     => "a3f1b2c4d5e6f7089012abcd"
//   "X-Agent-Signature" => "<base64url signature>"

let resp = reqwest::Client::new()
    .post("https://api.example.com/v1/tasks")
    .headers(headers.try_into()?)
    .json(&serde_json::json!({"task": "search"}))
    .send()
    .await?;
```

## Registry Client

Requires the `client` feature.

```rust,no_run
use open_agent_id::client::RegistryClient;

let client = RegistryClient::new(None); // uses https://api.openagentid.org
```

### All methods

| Method | Auth required | Description |
|---|---|---|
| `client.challenge(wallet_address)` | No | Request a wallet auth challenge |
| `client.wallet_auth(&WalletAuthRequest)` | No | Verify wallet signature, returns auth token |
| `client.register(token, &RegistrationRequest)` | Yes | Register a new agent |
| `client.lookup(did)` | No | Look up an agent by DID |
| `client.list_my_agents(token, cursor, limit)` | Yes | List agents owned by the authenticated wallet |
| `client.update_agent(token, did, &UpdateAgentRequest)` | Yes | Update agent metadata |
| `client.revoke(token, did)` | Yes | Revoke an agent identity |
| `client.rotate_key(token, did, &RotateKeyRequest)` | Yes | Rotate an agent's public key |
| `client.deploy_wallet(token, did)` | Yes | Deploy an on-chain smart wallet for an agent |
| `client.get_credit(did)` | No | Look up an agent's credit score |
| `client.verify(&VerifyRequest)` | No | Verify a signature against the agent's registered key |

### Wallet auth flow

```rust,no_run
use open_agent_id::types::WalletAuthRequest;

// 1. Request challenge
let challenge = client.challenge(wallet_address).await?;

// 2. Sign the challenge text with your wallet
// let wallet_signature = ...;

// 3. Verify and get auth token
let auth = client.wallet_auth(&WalletAuthRequest {
    wallet_address: wallet_address.to_string(),
    challenge_id: challenge.challenge_id,
    signature: wallet_signature,
}).await?;
let token = auth.token;
```

### Register an agent

```rust,no_run
use open_agent_id::types::RegistrationRequest;

let agent = client.register(&token, &RegistrationRequest {
    name: Some("my-agent".into()),
    public_key: base64url_public_key,
    capabilities: Some(vec!["search".into(), "summarize".into()]),
}).await?;
```

### Look up and list agents

```rust,no_run
let info = client.lookup("did:oaid:base:0x1234...").await?;
let agents = client.list_my_agents(&token, None, None).await?;
```

### Manage agents

```rust,no_run
client.update_agent(&token, "did:oaid:base:0x1234...", &updates).await?;
client.rotate_key(&token, "did:oaid:base:0x1234...", &rotate_req).await?;
client.revoke(&token, "did:oaid:base:0x1234...").await?;
client.deploy_wallet(&token, "did:oaid:base:0x1234...").await?;
```

## Credit Score

```rust,no_run
let credit = client.get_credit("did:oaid:base:0x1234567890abcdef1234567890abcdef12345678").await?;
println!("Score: {}", credit.credit_score);  // 300
println!("Level: {}", credit.level);         // "verified"
```

## HTTP Signing

### Sign and verify an HTTP request

```rust
use open_agent_id::{crypto, signing};

let (signing_key, verifying_key) = crypto::generate_keypair();

let output = signing::sign_http(
    &signing::HttpSignInput {
        method: "POST",
        url: "https://api.example.com/v1/agents",
        body: b"{\"name\":\"bot\"}",
        timestamp: None,
        nonce: None,
    },
    &signing_key,
).unwrap();

let valid = signing::verify_http(
    "POST",
    "https://api.example.com/v1/agents",
    b"{\"name\":\"bot\"}",
    output.timestamp,
    &output.nonce,
    &output.signature,
    &verifying_key,
).unwrap();
assert!(valid);
```

### Signer daemon client

Requires the `signer` feature.

```rust,no_run
use open_agent_id::signer::SignerClient;

let client = SignerClient::connect("/var/run/oaid-signer.sock").await?;
let signature = client.sign("my-key-id", "http", b"payload").await?;
```

## Message Signing

### Sign and verify a P2P message

```rust
use open_agent_id::{crypto, signing};

let (signing_key, verifying_key) = crypto::generate_keypair();
let body = serde_json::json!({"action": "ping"});

let output = signing::sign_msg(
    &signing::MsgSignInput {
        msg_type: "ping",
        id: "019504a0-0000-7000-8000-000000000001",
        from: "did:oaid:base:0x0000000000000000000000000000000000000001",
        to: &["did:oaid:base:0x0000000000000000000000000000000000000002"],
        reference: "",
        timestamp: None,
        expires_at: 0, // defaults to timestamp + 300s
        body: &body,
    },
    &signing_key,
);

let valid = signing::verify_msg(
    "ping",
    "019504a0-0000-7000-8000-000000000001",
    "did:oaid:base:0x0000000000000000000000000000000000000001",
    &["did:oaid:base:0x0000000000000000000000000000000000000002"],
    "",
    output.timestamp,
    output.timestamp + 300,
    &body,
    &output.signature,
    &verifying_key,
).unwrap();
assert!(valid);
```

## E2E Encryption

```rust
use open_agent_id::crypto;

let ciphertext = crypto::encrypt_for(b"secret", &recipient_pub, &sender_signing_key)?;
let plaintext = crypto::decrypt_from(&ciphertext, &sender_pub, &recipient_signing_key)?;
```

Uses NaCl box (X25519-XSalsa20-Poly1305).

## DID Utilities

### Parse a DID

```rust
use open_agent_id::Did;

let did = Did::parse("did:oaid:base:0x7f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e").unwrap();
assert_eq!(did.chain, "base");
println!("{did}"); // did:oaid:base:0x7f4e...
```

### Canonical helpers

```rust
use open_agent_id::signing;

// Canonical URL (lowercased host, sorted query params, no fragment)
let url = signing::canonicalize_url("https://API.Example.com/path?z=1&a=2").unwrap();
assert_eq!(url, "https://api.example.com/path?a=2&z=1");

// Canonical JSON (sorted keys, no whitespace)
let val: serde_json::Value = serde_json::from_str(r#"{"z":1,"a":"hello"}"#).unwrap();
assert_eq!(signing::canonical_json(&val), r#"{"a":"hello","z":1}"#);
```

## Testing

```bash
cargo test
cargo test --all-features
```

## License

Apache-2.0
