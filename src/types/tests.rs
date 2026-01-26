//! Tests for the types module

use super::*;

/// Creates a test FoundString with all optional fields set to None
fn create_test_found_string() -> FoundString {
    FoundString {
        text: "test_string".to_string(),
        original_text: None,
        encoding: Encoding::Ascii,
        offset: 0x1000,
        rva: Some(0x2000),
        section: Some(".rodata".to_string()),
        length: 11,
        tags: vec![Tag::Url],
        score: 100,
        section_weight: None,
        semantic_boost: None,
        noise_penalty: None,
        source: StringSource::SectionData,
        confidence: 0.85,
    }
}

#[test]
fn test_found_string_serde_optional_fields_none() {
    // Test that optional fields are skipped when None
    let found_string = create_test_found_string();
    let json = serde_json::to_string(&found_string).expect("Serialization failed");

    // Verify optional fields are not present in JSON
    assert!(!json.contains("original_text"));
    assert!(!json.contains("section_weight"));
    assert!(!json.contains("semantic_boost"));
    assert!(!json.contains("noise_penalty"));

    // Verify required fields are present
    assert!(json.contains("text"));
    assert!(json.contains("encoding"));
    assert!(json.contains("offset"));
}

#[test]
fn test_found_string_serde_optional_fields_some() {
    // Test that optional fields are included when Some
    let mut found_string = create_test_found_string();
    found_string.original_text = Some("_ZN4test6mangled".to_string());
    found_string.section_weight = Some(50);
    found_string.semantic_boost = Some(25);
    found_string.noise_penalty = Some(-10);

    let json = serde_json::to_string(&found_string).expect("Serialization failed");

    // Verify optional fields are present in JSON
    assert!(json.contains("original_text"));
    assert!(json.contains("_ZN4test6mangled"));
    assert!(json.contains("section_weight"));
    assert!(json.contains("semantic_boost"));
    assert!(json.contains("noise_penalty"));
}

#[test]
fn test_found_string_serde_roundtrip() {
    // Test serialization/deserialization roundtrip with all fields
    let mut found_string = create_test_found_string();
    found_string.original_text = Some("mangled_name".to_string());
    found_string.section_weight = Some(75);
    found_string.semantic_boost = Some(30);
    found_string.noise_penalty = Some(-5);

    let json = serde_json::to_string(&found_string).expect("Serialization failed");
    let deserialized: FoundString = serde_json::from_str(&json).expect("Deserialization failed");

    assert_eq!(found_string.text, deserialized.text);
    assert_eq!(found_string.original_text, deserialized.original_text);
    assert_eq!(found_string.section_weight, deserialized.section_weight);
    assert_eq!(found_string.semantic_boost, deserialized.semantic_boost);
    assert_eq!(found_string.noise_penalty, deserialized.noise_penalty);
}

#[test]
fn test_found_string_deserialize_missing_optional_fields() {
    // Test that missing optional fields default to None during deserialization
    let json = r#"{
        "text": "test",
        "encoding": "Ascii",
        "offset": 0,
        "rva": null,
        "section": null,
        "length": 4,
        "tags": [],
        "score": 0,
        "source": "SectionData",
        "confidence": 1.0
    }"#;

    let deserialized: FoundString = serde_json::from_str(json).expect("Deserialization failed");

    assert_eq!(deserialized.text, "test");
    assert_eq!(deserialized.original_text, None);
    assert_eq!(deserialized.section_weight, None);
    assert_eq!(deserialized.semantic_boost, None);
    assert_eq!(deserialized.noise_penalty, None);
}
