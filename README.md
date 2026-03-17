# open-agent-id

Rust SDK for the [Open Agent ID](https://openagentid.org) protocol (V2). Sign and verify HTTP requests and P2P messages using Ed25519.

## Installation

```toml
[dependencies]
open-agent-id = "0.2"
```

## DID Format

```
did:oaid:{chain}:{address}
```

- **chain**: lowercase identifier (e.g. `base`, `base-sepolia`)
- **address**: `0x` + 40 lowercase hex characters

Examples:
```
did:oaid:base:0x7f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e
did:oaid:base-sepolia:0x0000000000000000000000000000000000000001
```

## Usage

### Parse a DID

```rust
use open_agent_id::Did;

let did = Did::parse("did:oaid:base:0x7f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e").unwrap();
assert_eq!(did.chain, "base");
println!("{did}"); // did:oaid:base:0x7f4e...
```

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
    output.timestamp + 300, // must match the resolved expires_at
    &body,
    &output.signature,
    &verifying_key,
).unwrap();
assert!(valid);
```

### Registry client (feature: `client`)

```rust,no_run
use open_agent_id::client::RegistryClient;

#[tokio::main]
async fn main() -> Result<(), open_agent_id::Error> {
    let client = RegistryClient::new(None); // uses https://api.openagentid.org/v1

    // Look up an agent (no auth required)
    let info = client.lookup("did:oaid:base:0x7f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e").await?;
    println!("Agent: {:?}", info.name);
    Ok(())
}
```

### Signer daemon client (feature: `signer`)

```rust,no_run
use open_agent_id::signer::SignerClient;

#[tokio::main]
async fn main() -> Result<(), open_agent_id::Error> {
    let client = SignerClient::connect("/var/run/oaid-signer.sock").await?;
    let signature = client.sign("my-key-id", "http", b"payload").await?;
    println!("Signature: {signature}");
    Ok(())
}
```

### Utilities

```rust
use open_agent_id::signing;

// Canonical URL (lowercased host, sorted query params, no fragment)
let url = signing::canonicalize_url("https://API.Example.com/path?z=1&a=2").unwrap();
assert_eq!(url, "https://api.example.com/path?a=2&z=1");

// Canonical JSON (sorted keys, no whitespace)
let val: serde_json::Value = serde_json::from_str(r#"{"z":1,"a":"hello"}"#).unwrap();
assert_eq!(signing::canonical_json(&val), r#"{"a":"hello","z":1}"#);
```

## Signing Domains

| Domain | Purpose | Payload format |
|---|---|---|
| `oaid-http/v1` | HTTP request signing | `oaid-http/v1\n{METHOD}\n{URL}\n{BODY_SHA256}\n{TIMESTAMP}\n{NONCE}` |
| `oaid-msg/v1` | P2P message signing | `oaid-msg/v1\n{TYPE}\n{ID}\n{FROM}\n{TO}\n{REF}\n{TIMESTAMP}\n{EXPIRES}\n{BODY_SHA256}` |

## License

Apache-2.0
