# Changelog

## 0.1.1 (2026-02-18)

### Changed

- **Client-side key generation**: `AgentIdentity::register()` now generates the Ed25519 keypair locally and sends only the public key to the registry. The private key never leaves the client.

### Added

- `user_token` field on `RegisterOptions` for wallet-based Bearer authentication (alternative to `api_key`).
- `owner_id` field on `RegisterOptions` for specifying the owner wallet address when using platform-key auth.

## 0.1.0 (2026-02-17)

- Initial release: register, sign, verify, and look up AI agent identities.
