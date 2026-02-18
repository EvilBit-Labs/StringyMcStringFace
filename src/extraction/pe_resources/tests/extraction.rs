//! Phase 2 tests: string extraction, encoding detection, and integration

use super::*;
use crate::types::{Encoding, StringSource, Tag};

#[test]
fn test_decode_utf16le_valid() {
    // Test UTF-16LE decoding with valid input
    // "Hello" in UTF-16LE: 48 00 65 00 6C 00 6C 00 6F 00
    let bytes = [0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00];
    let result = decode_utf16le(&bytes);
    assert!(result.is_ok());
    assert_eq!(result.expect("decode should succeed"), "Hello");
}

#[test]
fn test_decode_utf16le_with_null() {
    // Test stripping trailing null terminators
    // "Hi" + null terminator: 48 00 69 00 00 00
    let bytes = [0x48, 0x00, 0x69, 0x00, 0x00, 0x00];
    let result = decode_utf16le(&bytes);
    assert!(result.is_ok());
    assert_eq!(result.expect("decode should succeed"), "Hi");
}

#[test]
fn test_decode_utf16le_odd_length() {
    // Test error handling for odd-length input
    // Should truncate last byte gracefully
    let bytes = [0x48, 0x00, 0x65, 0x00, 0x6C]; // Odd length
    let result = decode_utf16le(&bytes);
    // Should still decode what it can
    assert!(result.is_ok());
}

#[test]
#[ignore] // Requires test_binary_with_resources.exe fixture
fn test_extract_version_info_strings_from_fixture() {
    let fixture_path = get_fixture_path("test_binary_with_resources.exe");
    assert!(
        fixture_path.exists(),
        "Fixture test_binary_with_resources.exe not found. See other test comments for build instructions."
    );
    let pe_data = fs::read(&fixture_path).expect("Failed to read resource fixture");
    let strings = extract_version_info_strings(&pe_data);

    // Should extract at least some version strings
    assert!(!strings.is_empty(), "Should extract version info strings");
    for string in &strings {
        assert!(string.tags.contains(&Tag::Version));
        assert!(string.tags.contains(&Tag::Resource));
        assert_eq!(string.encoding, Encoding::Utf16Le);
        assert_eq!(string.source, StringSource::ResourceString);
    }
}

#[test]
#[ignore] // Requires test_binary_with_resources.exe fixture
fn test_extract_string_table_strings_from_fixture() {
    let fixture_path = get_fixture_path("test_binary_with_resources.exe");
    assert!(
        fixture_path.exists(),
        "Fixture test_binary_with_resources.exe not found. See other test comments for build instructions."
    );
    let pe_data = fs::read(&fixture_path).expect("Failed to read resource fixture");
    let strings = extract_string_table_strings(&pe_data);

    // Should extract at least some string table strings
    assert!(!strings.is_empty(), "Should extract string table strings");
    for string in &strings {
        assert!(string.tags.contains(&Tag::Resource));
        assert!(!string.tags.contains(&Tag::Version));
        assert_eq!(string.encoding, Encoding::Utf16Le);
        assert_eq!(string.source, StringSource::ResourceString);
    }
}

#[test]
fn test_detect_manifest_encoding_utf8() {
    // Test UTF-8 detection
    let bytes = [0xEF, 0xBB, 0xBF, b'<', b'?', b'x', b'm'];
    let encoding = detect_manifest_encoding(&bytes);
    assert_eq!(encoding, Encoding::Utf8);
}

#[test]
fn test_detect_manifest_encoding_utf16le() {
    // Test UTF-16LE detection
    let bytes = [0xFF, 0xFE, b'<', 0x00, b'?', 0x00];
    let encoding = detect_manifest_encoding(&bytes);
    assert_eq!(encoding, Encoding::Utf16Le);
}

#[test]
fn test_extract_manifest_strings_empty() {
    // Test with no manifest
    let invalid_data = b"NOT_A_PE_FILE";
    let strings = extract_manifest_strings(invalid_data);
    assert!(strings.is_empty());
}

#[test]
#[ignore] // Requires test_binary_with_resources.exe fixture
fn test_extract_resource_strings_integration() {
    // Test full orchestrator
    let fixture_path = get_fixture_path("test_binary_with_resources.exe");
    assert!(
        fixture_path.exists(),
        "Fixture test_binary_with_resources.exe not found. See other test comments for build instructions."
    );
    let pe_data = fs::read(&fixture_path).expect("Failed to read resource fixture");
    let strings = extract_resource_strings(&pe_data);

    // Should extract strings from at least one resource type
    assert!(!strings.is_empty(), "Should extract some resource strings");

    // Verify all strings have proper metadata
    for string in &strings {
        assert!(!string.text.is_empty());
        assert!(string.tags.contains(&Tag::Resource));
        assert_eq!(string.source, StringSource::ResourceString);
    }
}
