# open-agent-id

Rust SDK for the [Open Agent ID](https://openagentid.org) protocol. Allows AI agents to register identities, sign HTTP requests, and verify other agents' signatures using Ed25519 cryptography.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
open-agent-id = { path = "../agent-id-rust" }
```

## Usage

### Register a new agent

```rust
use open_agent_id::{AgentIdentity, RegisterOptions};

let identity = AgentIdentity::register(RegisterOptions {
    name: "my-search-agent".to_string(),
    capabilities: Some(vec!["search".to_string(), "summarize".to_string()]),
    api_key: "your-platform-api-key".to_string(),
    api_url: None, // uses default: https://api.openagentid.org/v1
}).await?;

println!("DID: {}", identity.did());
println!("Public Key: {}", identity.public_key_base64url());
```

### Load an existing identity

```rust
use open_agent_id::AgentIdentity;

let identity = AgentIdentity::load(
    "did:agent:tokli:agt_a1B2c3D4e5",
    "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusMcrnf2DXWpgBgrEKt9VL_tPJZAc6DuFy89qmIyWvAhpo9wdRGg",
)?;
```

### Sign a payload

```rust
let signature = identity.sign("hello world")?;
println!("Signature: {}", signature);
```

### Sign an HTTP request

```rust
let headers = identity.sign_request(
    "POST",
    "https://api.example.com/v1/tasks",
    "{\"task\":\"search\"}",
)?;

// headers contains:
// - X-Agent-DID
// - X-Agent-Timestamp
// - X-Agent-Nonce
// - X-Agent-Signature
```

### Verify another agent's signature

```rust
use open_agent_id::AgentIdentity;

let valid = AgentIdentity::verify(
    "did:agent:tokli:agt_a1B2c3D4e5",
    "hello world",
    &signature,
    None, // uses default API URL
).await?;

assert!(valid);
```

### Look up agent info

```rust
use open_agent_id::AgentIdentity;

let info = AgentIdentity::lookup(
    "did:agent:tokli:agt_a1B2c3D4e5",
    None,
).await?;

println!("Name: {}", info.name);
println!("Status: {}", info.status);
```

## DID Format

```
did:agent:{platform}:{unique_id}
```

- **platform**: 3-20 lowercase alphanumeric characters
- **unique_id**: `agt_` followed by 10 base62 characters

Examples:
```
did:agent:tokli:agt_a1B2c3D4e5
did:agent:openai:agt_X9yZ8wV7u6
```

## Signing Specification

HTTP requests are signed by constructing a canonical payload:

```
{METHOD}\n{URL}\n{BODY_SHA256}\n{TIMESTAMP}\n{NONCE}
```

The payload is signed with Ed25519 and the signature is base64url-encoded (no padding).

## License

Apache-2.0
