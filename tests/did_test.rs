use open_agent_id::did::{generate_unique_id, parse_did, validate_did};

#[test]
fn test_valid_dids_from_vectors() {
    let valid = vec![
        "did:agent:tokli:agt_a1B2c3D4e5",
        "did:agent:openai:agt_X9yZ8wV7u6",
        "did:agent:langchain:agt_Q3rS4tU5v6",
        "did:agent:abc:agt_0000000000",
    ];
    for did in valid {
        assert!(validate_did(did), "Expected valid: {}", did);
    }
}

#[test]
fn test_invalid_dids_from_vectors() {
    let invalid = vec![
        "did:agent:AB:agt_a1B2c3D4e5",                          // platform too short
        "did:agent:toolongplatformnamehere:agt_a1B2c3D4e5",      // platform too long
        "did:agent:tokli:a1B2c3D4e5",                            // missing agt_ prefix
        "did:agent:tokli:agt_short",                              // unique_id too short
        "did:agent:tokli:agt_a1B2c3D4e5!",                       // invalid character
        "did:other:tokli:agt_a1B2c3D4e5",                        // wrong method
        "did:agent:UPPER:agt_a1B2c3D4e5",                        // uppercase platform
        "",                                                        // empty string
    ];
    for did in invalid {
        assert!(!validate_did(did), "Expected invalid: '{}'", did);
    }
}

#[test]
fn test_parse_did_components() {
    let c = parse_did("did:agent:tokli:agt_a1B2c3D4e5").unwrap();
    assert_eq!(c.did, "did:agent:tokli:agt_a1B2c3D4e5");
    assert_eq!(c.method, "agent");
    assert_eq!(c.platform, "tokli");
    assert_eq!(c.unique_id, "agt_a1B2c3D4e5");
}

#[test]
fn test_parse_did_langchain() {
    let c = parse_did("did:agent:langchain:agt_Q3rS4tU5v6").unwrap();
    assert_eq!(c.platform, "langchain");
    assert_eq!(c.unique_id, "agt_Q3rS4tU5v6");
}

#[test]
fn test_parse_invalid_did() {
    assert!(parse_did("").is_err());
    assert!(parse_did("did:other:tokli:agt_a1B2c3D4e5").is_err());
    assert!(parse_did("not-a-did").is_err());
}

#[test]
fn test_generate_unique_id_format() {
    for _ in 0..100 {
        let id = generate_unique_id();
        assert!(id.starts_with("agt_"), "ID should start with agt_: {}", id);
        assert_eq!(id.len(), 14, "ID should be 14 chars: {}", id);
        // Validate the generated ID produces a valid DID
        let did = format!("did:agent:test:{}", id);
        assert!(validate_did(&did), "Generated DID should be valid: {}", did);
    }
}

#[test]
fn test_generate_unique_id_uniqueness() {
    let ids: Vec<String> = (0..100).map(|_| generate_unique_id()).collect();
    let unique: std::collections::HashSet<_> = ids.iter().collect();
    assert_eq!(ids.len(), unique.len(), "Generated IDs should be unique");
}
