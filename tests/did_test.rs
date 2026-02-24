use open_agent_id::did::{validate, Did};

#[test]
fn valid_base_did() {
    let did = Did::parse("did:oaid:base:0x7f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e").unwrap();
    assert_eq!(did.chain, "base");
    assert_eq!(
        did.address,
        "0x7f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e"
    );
}

#[test]
fn valid_base_sepolia_did() {
    let did =
        Did::parse("did:oaid:base-sepolia:0x0000000000000000000000000000000000000001").unwrap();
    assert_eq!(did.chain, "base-sepolia");
}

#[test]
fn normalizes_to_lowercase() {
    let did = Did::parse("did:oaid:BASE:0x7F4E3D2C1B0A9F8E7D6C5B4A3F2E1D0C9B8A7F6E").unwrap();
    assert_eq!(did.chain, "base");
    assert_eq!(
        did.address,
        "0x7f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e"
    );
}

#[test]
fn display_roundtrip() {
    let input = "did:oaid:base:0x7f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e";
    let did = Did::parse(input).unwrap();
    assert_eq!(did.to_string(), input);
    assert_eq!(format!("{did}"), input);
}

#[test]
fn reject_v1_did() {
    assert!(Did::parse("did:agent:tokli:agt_a1B2c3D4e5").is_err());
}

#[test]
fn reject_wrong_method() {
    assert!(
        Did::parse("did:xxx:base:0x0000000000000000000000000000000000000001").is_err()
    );
}

#[test]
fn reject_short_address() {
    assert!(Did::parse("did:oaid:base:0x1234").is_err());
}

#[test]
fn reject_missing_0x_prefix() {
    assert!(
        Did::parse("did:oaid:base:7f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e").is_err()
    );
}

#[test]
fn reject_empty() {
    assert!(Did::parse("").is_err());
}

#[test]
fn reject_too_long() {
    let chain = "a".repeat(60);
    let did_str = format!("did:oaid:{chain}:0x0000000000000000000000000000000000000001");
    assert!(Did::parse(&did_str).is_err());
}

#[test]
fn new_constructs_and_normalizes() {
    let did = Did::new("base", "0xAbCdEf0000000000000000000000000000000000").unwrap();
    assert_eq!(did.address, "0xabcdef0000000000000000000000000000000000");
    assert_eq!(did.chain, "base");
}

#[test]
fn validate_helper() {
    assert!(validate(
        "did:oaid:base:0x0000000000000000000000000000000000000001"
    ));
    assert!(!validate("garbage"));
    assert!(!validate("did:agent:tokli:agt_a1B2c3D4e5"));
}
