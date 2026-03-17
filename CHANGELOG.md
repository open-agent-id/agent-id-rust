# Changelog

## 0.2.0 (2026-02-24)

### Breaking Changes
- DID format changed from `did:agent:{platform}:{id}` to `did:oaid:{chain}:{address}`
- Complete API rewrite for V2 protocol

### Added
- Two signing domains: `oaid-http/v1` (HTTP requests) and `oaid-msg/v1` (P2P messages)
- `sign_msg()` for P2P message signing
- `Signer` client for oaid-signer daemon integration
- `RegistryClient` with wallet auth support
- `canonical_url()` and `canonical_json()` utilities

### Changed
- All signing payloads now include domain prefix

## 0.1.1 (2026-02-18)

### Changed

- **Client-side key generation**: `AgentIdentity::register()` now generates the Ed25519 keypair locally and sends only the public key to the registry. The private key never leaves the client.

### Added

- `user_token` field on `RegisterOptions` for wallet-based Bearer authentication (alternative to `api_key`).
- `owner_id` field on `RegisterOptions` for specifying the owner wallet address when using platform-key auth.

## 0.1.0 (2026-02-17)

- Initial release: register, sign, verify, and look up AI agent identities.
