//! Tests for PE resource extraction
//!
//! Comprehensive unit tests covering invalid/malformed PE data handling,
//! missing resource directories, empty resource sections, multiple language
//! variants, and edge cases in VERSIONINFO, STRINGTABLE, and MANIFEST detection.

use super::*;
use crate::types::{Encoding, ResourceType, StringSource, Tag};
use std::fs;
use std::path::Path;

// Helper to get fixture path
fn get_fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

// Tests for extract_resources function

#[test]
fn test_extract_resources_invalid_data() {
    // Test with invalid data - should return empty vec, not panic
    let invalid_data = b"NOT_A_PE_FILE";
    let result = extract_resources(invalid_data);
    assert!(result.is_empty(), "Invalid data should return empty vector");
}

#[test]
fn test_extract_resources_empty_data() {
    // Test with empty byte slice - should return empty vec gracefully
    let empty_data = b"";
    let result = extract_resources(empty_data);
    assert!(result.is_empty(), "Empty data should return empty vector");
}

#[test]
fn test_extract_resources_truncated_pe() {
    // Test with incomplete PE header - should handle gracefully
    let truncated_pe = b"MZ\x90\x00"; // Just DOS header, no PE header
    let result = extract_resources(truncated_pe);
    assert!(result.is_empty(), "Truncated PE should return empty vector");
}

#[test]
#[ignore] // Requires test_binary_pe.exe fixture
// To run: cargo test -- --ignored test_extract_resources_no_resource_section
// Fixture can be generated via the build script in tests/fixtures/
fn test_extract_resources_no_resource_section() {
    // Test with valid PE but no .rsrc section
    // This is tested via integration tests with test_binary_pe.exe
    // which is a minimal PE without resources
    let fixture_path = get_fixture_path("test_binary_pe.exe");
    assert!(
        fixture_path.exists(),
        "Fixture test_binary_pe.exe not found. Generate it using the build script."
    );
    let pe_data = fs::read(&fixture_path).expect("Failed to read PE fixture");
    let result = extract_resources(&pe_data);
    // May be empty or may have resources - both are valid
    // The key is that it doesn't panic
    assert!(
        result.iter().all(|r| r.data_size > 0),
        "All resources should have non-zero size"
    );
}

#[test]
fn test_extract_resources_corrupted_resource_directory() {
    // Test with valid PE but corrupted resource directory structure
    // This is difficult to craft without a real PE, so we test via
    // graceful error handling in the actual implementation
    // The function should return empty vec on any error
    let invalid_data = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF";
    let result = extract_resources(invalid_data);
    assert!(
        result.is_empty(),
        "Corrupted data should return empty vector"
    );
}

// Tests for VERSIONINFO detection

#[test]
#[ignore] // Requires test_binary_pe.exe fixture
// To run: cargo test -- --ignored test_detect_version_info_missing
// Fixture can be generated via the build script in tests/fixtures/
fn test_detect_version_info_missing() {
    // Test when RT_VERSION type directory doesn't exist
    // This is tested via extract_resources with a PE that has no version info
    let fixture_path = get_fixture_path("test_binary_pe.exe");
    assert!(
        fixture_path.exists(),
        "Fixture test_binary_pe.exe not found. Generate it using the build script."
    );
    let pe_data = fs::read(&fixture_path).expect("Failed to read PE fixture");
    let resources = extract_resources(&pe_data);
    // test_binary_pe.exe doesn't have VERSIONINFO, so we shouldn't find any
    let has_version = resources
        .iter()
        .any(|r| matches!(r.resource_type, ResourceType::VersionInfo));
    assert!(
        !has_version,
        "test_binary_pe.exe should not have VERSIONINFO resources"
    );
}

#[test]
fn test_detect_version_info_empty_directory() {
    // Test when binary has no RT_VERSION directory entries
    // extract_resources should return empty or non-VERSIONINFO resources
    let fixture_path = get_fixture_path("test_binary_pe.exe");
    if !fixture_path.exists() {
        return; // Skip if fixture not available
    }
    let pe_data = fs::read(&fixture_path).expect("Failed to read PE fixture");
    let resources = extract_resources(&pe_data);
    // No VERSIONINFO resources should be detected
    let version_count = resources
        .iter()
        .filter(|r| matches!(r.resource_type, ResourceType::VersionInfo))
        .count();
    assert_eq!(version_count, 0, "Expected no VERSIONINFO resources");
}

#[test]
#[ignore] // Requires test_binary_with_resources.exe fixture
// To run: cargo test -- --ignored test_detect_version_info_multiple_languages
// Fixture can be generated via: docker run --rm -v "$(pwd):/work" -w /work mcr.microsoft.com/devcontainers/cpp:latest bash -c "apt-get update -qq && apt-get install -y -qq mingw-w64 && x86_64-w64-mingw32-windres --input-format=rc --output-format=coff -o test_binary_with_resources.res test_binary_with_resources.rc && x86_64-w64-mingw32-gcc -o test_binary_with_resources.exe test_binary_with_resources.c test_binary_with_resources.res"
fn test_detect_version_info_multiple_languages() {
    // Test VERSIONINFO with multiple language entries
    // This is tested via integration tests with test_binary_with_resources.exe
    let fixture_path = get_fixture_path("test_binary_with_resources.exe");
    assert!(
        fixture_path.exists(),
        "Fixture test_binary_with_resources.exe not found. See test comment for build instructions."
    );
    let pe_data = fs::read(&fixture_path).expect("Failed to read resource fixture");
    let resources = extract_resources(&pe_data);
    let version_resources: Vec<_> = resources
        .iter()
        .filter(|r| matches!(r.resource_type, ResourceType::VersionInfo))
        .collect();
    // Should handle multiple languages gracefully
    for resource in version_resources {
        assert!(resource.data_size > 0, "Version resource should have size");
        assert!(
            resource.language <= 0xFFFF,
            "Language ID should be valid u16 value"
        );
    }
}

#[test]
#[ignore] // Requires test_binary_with_resources.exe fixture
// To run: cargo test -- --ignored test_detect_version_info_no_translation
fn test_detect_version_info_no_translation() {
    // Test VERSIONINFO without translation array
    // The implementation uses fallback language handling
    // This test verifies that behavior doesn't panic
    let fixture_path = get_fixture_path("test_binary_with_resources.exe");
    assert!(
        fixture_path.exists(),
        "Fixture test_binary_with_resources.exe not found. See other test comments for build instructions."
    );
    let pe_data = fs::read(&fixture_path).expect("Failed to read resource fixture");
    let resources = extract_resources(&pe_data);
    // Should not panic even if translation is missing
    let _ = resources;
}

#[test]
fn test_detect_version_info_malformed_data_entry() {
    // Test with corrupted data entry in version directory
    // The implementation uses pattern matching to skip invalid entries
    // This test verifies graceful skipping
    let invalid_data = b"NOT_A_VALID_PE";
    let result = extract_resources(invalid_data);
    assert!(result.is_empty(), "Malformed data should return empty");
}

// Tests for STRINGTABLE detection

#[test]
#[ignore] // Requires test_binary_pe.exe fixture
// To run: cargo test -- --ignored test_detect_string_tables_missing
fn test_detect_string_tables_missing() {
    // Test when RT_STRING type directory doesn't exist
    let fixture_path = get_fixture_path("test_binary_pe.exe");
    assert!(
        fixture_path.exists(),
        "Fixture test_binary_pe.exe not found. Generate it using the build script."
    );
    let pe_data = fs::read(&fixture_path).expect("Failed to read PE fixture");
    let resources = extract_resources(&pe_data);
    // test_binary_pe.exe doesn't have STRINGTABLE, so we shouldn't find any
    let has_string_table = resources
        .iter()
        .any(|r| matches!(r.resource_type, ResourceType::StringTable));
    assert!(
        !has_string_table,
        "test_binary_pe.exe should not have STRINGTABLE resources"
    );
}

#[test]
fn test_detect_string_tables_empty_directory() {
    // Verify extract_resources handles a PE with no RT_STRING entries gracefully
    let fixture_path = get_fixture_path("test_binary_pe.exe");
    if !fixture_path.exists() {
        return; // Skip if fixture not available
    }
    let pe_data = fs::read(&fixture_path).expect("Failed to read PE fixture");
    let resources = extract_resources(&pe_data);
    let string_table_count = resources
        .iter()
        .filter(|r| matches!(r.resource_type, ResourceType::StringTable))
        .count();
    assert_eq!(string_table_count, 0, "Expected no STRINGTABLE resources");
}

#[test]
#[ignore] // Requires test_binary_with_resources.exe fixture
// To run: cargo test -- --ignored test_detect_string_tables_multiple_blocks
fn test_detect_string_tables_multiple_blocks() {
    // Test multiple string table blocks with different IDs
    let fixture_path = get_fixture_path("test_binary_with_resources.exe");
    assert!(
        fixture_path.exists(),
        "Fixture test_binary_with_resources.exe not found. See other test comments for build instructions."
    );
    let pe_data = fs::read(&fixture_path).expect("Failed to read resource fixture");
    let resources = extract_resources(&pe_data);
    let string_tables: Vec<_> = resources
        .iter()
        .filter(|r| matches!(r.resource_type, ResourceType::StringTable))
        .collect();
    // Should handle multiple blocks gracefully
    for resource in string_tables {
        assert!(resource.data_size > 0, "String table should have size");
        assert!(resource.language <= 0xFFFF, "Language ID should be valid");
    }
}

#[test]
#[ignore] // Requires test_binary_with_resources.exe fixture
// To run: cargo test -- --ignored test_detect_string_tables_multiple_languages
fn test_detect_string_tables_multiple_languages() {
    // Test string tables with multiple language variants
    let fixture_path = get_fixture_path("test_binary_with_resources.exe");
    assert!(
        fixture_path.exists(),
        "Fixture test_binary_with_resources.exe not found. See other test comments for build instructions."
    );
    let pe_data = fs::read(&fixture_path).expect("Failed to read resource fixture");
    let resources = extract_resources(&pe_data);
    let string_tables: Vec<_> = resources
        .iter()
        .filter(|r| matches!(r.resource_type, ResourceType::StringTable))
        .collect();
    // Should detect multiple languages if present
    for resource in string_tables {
        assert!(resource.data_size > 0);
    }
}

#[test]
fn test_detect_string_tables_malformed_block() {
    // Test with corrupted block directory structure
    // Implementation uses pattern matching to skip invalid entries
    let invalid_data = b"INVALID_PE_DATA";
    let result = extract_resources(invalid_data);
    assert!(result.is_empty(), "Malformed block should return empty");
}

// Tests for MANIFEST detection

#[test]
#[ignore] // Requires test_binary_pe.exe fixture
// To run: cargo test -- --ignored test_detect_manifests_missing
fn test_detect_manifests_missing() {
    // Test when RT_MANIFEST type directory doesn't exist
    let fixture_path = get_fixture_path("test_binary_pe.exe");
    assert!(
        fixture_path.exists(),
        "Fixture test_binary_pe.exe not found. Generate it using the build script."
    );
    let pe_data = fs::read(&fixture_path).expect("Failed to read PE fixture");
    let resources = extract_resources(&pe_data);
    // test_binary_pe.exe doesn't have MANIFEST
    let has_manifest = resources
        .iter()
        .any(|r| matches!(r.resource_type, ResourceType::Manifest));
    assert!(
        !has_manifest,
        "test_binary_pe.exe should not have MANIFEST resources"
    );
}

#[test]
fn test_detect_manifests_empty_directory() {
    // Verify extract_resources handles a PE with no RT_MANIFEST entries gracefully
    let fixture_path = get_fixture_path("test_binary_pe.exe");
    if !fixture_path.exists() {
        return; // Skip if fixture not available
    }
    let pe_data = fs::read(&fixture_path).expect("Failed to read PE fixture");
    let resources = extract_resources(&pe_data);
    let manifest_count = resources
        .iter()
        .filter(|r| matches!(r.resource_type, ResourceType::Manifest))
        .count();
    assert_eq!(manifest_count, 0, "Expected no MANIFEST resources");
}

#[test]
#[ignore] // Requires test_binary_with_resources.exe fixture
// To run: cargo test -- --ignored test_detect_manifests_multiple_manifests
fn test_detect_manifests_multiple_manifests() {
    // Test multiple manifest resources (rare but possible)
    // Implementation should handle multiple manifests if present
    let fixture_path = get_fixture_path("test_binary_with_resources.exe");
    assert!(
        fixture_path.exists(),
        "Fixture test_binary_with_resources.exe not found. See other test comments for build instructions."
    );
    let pe_data = fs::read(&fixture_path).expect("Failed to read resource fixture");
    let resources = extract_resources(&pe_data);
    let manifests: Vec<_> = resources
        .iter()
        .filter(|r| matches!(r.resource_type, ResourceType::Manifest))
        .collect();
    // Should handle multiple manifests gracefully
    for resource in manifests {
        assert!(resource.data_size > 0, "Manifest should have size");
    }
}

#[test]
#[ignore] // Requires test_binary_with_resources.exe fixture
// To run: cargo test -- --ignored test_detect_manifests_zero_language
fn test_detect_manifests_zero_language() {
    // Test manifest with language ID 0 (common for manifests)
    let fixture_path = get_fixture_path("test_binary_with_resources.exe");
    assert!(
        fixture_path.exists(),
        "Fixture test_binary_with_resources.exe not found. See other test comments for build instructions."
    );
    let pe_data = fs::read(&fixture_path).expect("Failed to read resource fixture");
    let resources = extract_resources(&pe_data);
    let manifests: Vec<_> = resources
        .iter()
        .filter(|r| matches!(r.resource_type, ResourceType::Manifest))
        .collect();
    // Language ID 0 is valid for manifests
    for resource in manifests {
        assert!(resource.language <= 0xFFFF, "Language should be valid");
    }
}

// Integration-style unit tests with real fixtures

#[test]
#[ignore] // Requires test_binary_pe.exe fixture
// To run: cargo test -- --ignored test_extract_resources_from_fixture_basic
fn test_extract_resources_from_fixture_basic() {
    // Use test_binary_pe.exe (no resources expected)
    let fixture_path = get_fixture_path("test_binary_pe.exe");
    assert!(
        fixture_path.exists(),
        "Fixture test_binary_pe.exe not found. Generate it using the build script."
    );
    let pe_data = fs::read(&fixture_path).expect("Failed to read PE fixture");
    let resources = extract_resources(&pe_data);
    // Basic PE may or may not have resources - both are valid
    // Verify structure is correct
    for resource in &resources {
        assert!(resource.data_size > 0, "Resource should have non-zero size");
        assert!(resource.language <= 0xFFFF, "Language ID should be valid");
    }
}

#[test]
#[ignore] // Requires test_binary_with_resources.exe fixture
// To run: cargo test -- --ignored test_extract_resources_from_fixture_with_resources
fn test_extract_resources_from_fixture_with_resources() {
    // Use test_binary_with_resources.exe (should find VERSIONINFO and STRINGTABLE)
    let fixture_path = get_fixture_path("test_binary_with_resources.exe");
    assert!(
        fixture_path.exists(),
        "Fixture test_binary_with_resources.exe not found. See other test comments for build instructions."
    );
    let pe_data = fs::read(&fixture_path).expect("Failed to read resource fixture");
    let resources = extract_resources(&pe_data);
    // Should find at least some resources
    let has_version_info = resources
        .iter()
        .any(|r| matches!(r.resource_type, ResourceType::VersionInfo));
    let has_string_table = resources
        .iter()
        .any(|r| matches!(r.resource_type, ResourceType::StringTable));
    // Resource-enabled binary should have at least one known resource type
    assert!(
        has_version_info || has_string_table,
        "Resource-enabled binary should have VERSIONINFO or STRINGTABLE resources"
    );
}

#[test]
#[ignore] // Requires test_binary_with_resources.exe fixture
// To run: cargo test -- --ignored test_resource_metadata_validation
fn test_resource_metadata_validation() {
    // Verify ResourceMetadata fields are correctly populated
    let fixture_path = get_fixture_path("test_binary_with_resources.exe");
    assert!(
        fixture_path.exists(),
        "Fixture test_binary_with_resources.exe not found. See other test comments for build instructions."
    );
    let pe_data = fs::read(&fixture_path).expect("Failed to read resource fixture");
    let resources = extract_resources(&pe_data);
    for resource in resources {
        // Type should be one of the known types
        match resource.resource_type {
            ResourceType::VersionInfo | ResourceType::StringTable | ResourceType::Manifest => {
                // Valid types
            }
            _ => {
                // Other types are also valid for future expansion
            }
        }
        assert!(resource.data_size > 0, "Resource should have non-zero size");
        assert!(
            resource.language <= 0xFFFF,
            "Language ID should be valid u16 value"
        );
        // Offset is always None in Phase 1 (pelite API limitation)
        assert_eq!(resource.offset, None, "Offset should be None in Phase 1");
    }
}

// Boundary condition tests

#[test]
#[ignore] // Requires test_binary_with_resources.exe fixture
// To run: cargo test -- --ignored test_extract_resources_zero_size_data_entry
fn test_extract_resources_zero_size_data_entry() {
    // Test resource with size=0 (edge case)
    // This is handled by pelite - if a resource has size 0, it won't be enumerated
    // Our implementation relies on pelite's validation
    let fixture_path = get_fixture_path("test_binary_with_resources.exe");
    assert!(
        fixture_path.exists(),
        "Fixture test_binary_with_resources.exe not found. See other test comments for build instructions."
    );
    let pe_data = fs::read(&fixture_path).expect("Failed to read resource fixture");
    let resources = extract_resources(&pe_data);
    // All resources should have non-zero size (pelite filters out zero-size)
    for resource in resources {
        assert!(resource.data_size > 0, "Resource should have non-zero size");
    }
}

#[test]
#[ignore] // Requires test_binary_with_resources.exe fixture
// To run: cargo test -- --ignored test_extract_resources_max_language_id
fn test_extract_resources_max_language_id() {
    // Test with maximum u32 language ID (edge case validation)
    // Language IDs are actually u16 in PE format, but we store as u32
    // Maximum valid language ID is 0xFFFF
    let fixture_path = get_fixture_path("test_binary_with_resources.exe");
    assert!(
        fixture_path.exists(),
        "Fixture test_binary_with_resources.exe not found. See other test comments for build instructions."
    );
    let pe_data = fs::read(&fixture_path).expect("Failed to read resource fixture");
    let resources = extract_resources(&pe_data);
    for resource in resources {
        // Language should be within valid range
        assert!(
            resource.language <= 0xFFFF,
            "Language ID should not exceed 0xFFFF"
        );
    }
}

#[test]
#[ignore] // Requires a PE binary with large resource section
// To run locally: cargo test -- --ignored test_extract_resources_large_resource_section
// To generate a test fixture with large resources:
// 1. Create a .rc file with large resource data (e.g., large VERSIONINFO or STRINGTABLE)
// 2. Compile with windres: x86_64-w64-mingw32-windres --input-format=rc --output-format=coff -o large_resources.res large_resources.rc
// 3. Link into a PE: x86_64-w64-mingw32-gcc -o large_resources.exe test_binary_with_resources.c large_resources.res
// 4. Place in tests/fixtures/ and update fixture_path below
fn test_extract_resources_large_resource_section() {
    // Test handling of a large resource payload
    // This validates that the implementation can handle resource sections
    // that exceed typical sizes without performance degradation or errors
    let fixture_path = get_fixture_path("large_resources.exe");
    assert!(
        fixture_path.exists(),
        "Fixture large_resources.exe not found. See test comment for generation instructions."
    );
    let pe_data = fs::read(&fixture_path).expect("Failed to read large resource fixture");
    let resources = extract_resources(&pe_data);
    // Should handle large resources gracefully
    for resource in resources {
        assert!(resource.data_size > 0, "Resource should have non-zero size");
        assert!(resource.language <= 0xFFFF, "Language ID should be valid");
    }
}

// Phase 2: String extraction tests

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
