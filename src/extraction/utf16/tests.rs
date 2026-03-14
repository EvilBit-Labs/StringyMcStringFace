//! Tests for the UTF-16 extraction module

use crate::extraction::utf16::{
    ByteOrder, Utf16ExtractionConfig, extract_from_section, extract_utf16_strings,
};
use crate::types::{Encoding, SectionInfo, SectionType};

// Helper to create UTF-16LE test data
fn create_utf16le_string(text: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for ch in text.chars() {
        let code_point = ch as u32;
        if code_point <= 0xFFFF {
            let u16_val = code_point as u16;
            bytes.extend_from_slice(&u16_val.to_le_bytes());
        } else {
            // Surrogate pair
            let code_point = code_point - 0x10000;
            let high = 0xD800 + ((code_point >> 10) as u16);
            let low = 0xDC00 + ((code_point & 0x3FF) as u16);
            bytes.extend_from_slice(&high.to_le_bytes());
            bytes.extend_from_slice(&low.to_le_bytes());
        }
    }
    bytes
}

// Helper to create UTF-16BE test data
fn create_utf16be_string(text: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for ch in text.chars() {
        let code_point = ch as u32;
        if code_point <= 0xFFFF {
            let u16_val = code_point as u16;
            bytes.extend_from_slice(&u16_val.to_be_bytes());
        } else {
            // Surrogate pair
            let code_point = code_point - 0x10000;
            let high = 0xD800 + ((code_point >> 10) as u16);
            let low = 0xDC00 + ((code_point & 0x3FF) as u16);
            bytes.extend_from_slice(&high.to_be_bytes());
            bytes.extend_from_slice(&low.to_be_bytes());
        }
    }
    bytes
}

// Helper to create test section
fn create_test_section(name: &str, offset: u64, size: u64, rva: Option<u64>) -> SectionInfo {
    let section = SectionInfo::new(name.to_string(), offset, size, SectionType::StringData, 1.0);
    match rva {
        Some(rva) => section.with_rva(rva),
        None => section,
    }
}

#[test]
fn test_extract_utf16le_basic() {
    let mut data = create_utf16le_string("Hello");
    data.extend_from_slice(&[0x00, 0x00]);
    let world = create_utf16le_string("World");
    data.extend_from_slice(&world);
    data.extend_from_slice(&[0x00, 0x00]);

    let config = Utf16ExtractionConfig {
        byte_order: ByteOrder::LE,
        ..Default::default()
    };
    let strings = extract_utf16_strings(&data, &config);

    assert_eq!(strings.len(), 2);
    assert_eq!(strings[0].text, "Hello");
    assert_eq!(strings[0].encoding, Encoding::Utf16Le);
    assert_eq!(strings[1].text, "World");
}

#[test]
fn test_extract_utf16be_basic() {
    let mut data = create_utf16be_string("Hello");
    data.extend_from_slice(&[0x00, 0x00]);
    let world = create_utf16be_string("World");
    data.extend_from_slice(&world);
    data.extend_from_slice(&[0x00, 0x00]);

    let config = Utf16ExtractionConfig {
        byte_order: ByteOrder::BE,
        ..Default::default()
    };
    let strings = extract_utf16_strings(&data, &config);

    assert_eq!(strings.len(), 2);
    assert_eq!(strings[0].text, "Hello");
    assert_eq!(strings[0].encoding, Encoding::Utf16Be);
    assert_eq!(strings[1].text, "World");
}

#[test]
fn test_extract_utf16_auto_detects_le() {
    let mut data = create_utf16le_string("Hello");
    data.extend_from_slice(&[0x00, 0x00]);

    let config = Utf16ExtractionConfig {
        byte_order: ByteOrder::Auto,
        ..Default::default()
    };
    let strings = extract_utf16_strings(&data, &config);

    assert!(!strings.is_empty());
    assert_eq!(strings[0].text, "Hello");
    assert_eq!(strings[0].encoding, Encoding::Utf16Le);
}

#[test]
fn test_extract_utf16_auto_detects_be() {
    let mut data = create_utf16be_string("Hello");
    data.extend_from_slice(&[0x00, 0x00]);

    let config = Utf16ExtractionConfig {
        byte_order: ByteOrder::Auto,
        scan_both_alignments: false, // Ensure we're not scanning odd offsets
        ..Default::default()
    };
    let strings = extract_utf16_strings(&data, &config);

    assert!(!strings.is_empty());
    // Find the BE string (should be the correct one)
    let be_string = strings
        .iter()
        .find(|s| s.encoding == Encoding::Utf16Be && s.text == "Hello");
    assert!(be_string.is_some(), "Should find BE string 'Hello'");
    if let Some(s) = be_string {
        assert_eq!(s.text, "Hello");
        assert_eq!(s.encoding, Encoding::Utf16Be);
    }
}

#[test]
fn test_extract_utf16_mixed_ascii_unicode() {
    let mut data = create_utf16le_string("Hello \u{4e16}\u{754c}");
    data.extend_from_slice(&[0x00, 0x00]);

    let config = Utf16ExtractionConfig {
        byte_order: ByteOrder::LE,
        ..Default::default()
    };
    let strings = extract_utf16_strings(&data, &config);

    assert!(!strings.is_empty());
    assert_eq!(strings[0].text, "Hello \u{4e16}\u{754c}");
}

#[test]
fn test_utf16_min_length_filtering() {
    let mut data = create_utf16le_string("Hi");
    data.extend_from_slice(&[0x00, 0x00]);
    let test = create_utf16le_string("Test");
    data.extend_from_slice(&test);
    data.extend_from_slice(&[0x00, 0x00]);

    let config = Utf16ExtractionConfig {
        min_length: 3,
        byte_order: ByteOrder::LE,
        ..Default::default()
    };
    let strings = extract_utf16_strings(&data, &config);

    assert_eq!(strings.len(), 1);
    assert_eq!(strings[0].text, "Test");
}

#[test]
fn test_utf16_confidence_legitimate_string() {
    let data = create_utf16le_string("Microsoft Corporation");
    let config = Utf16ExtractionConfig {
        byte_order: ByteOrder::LE,
        confidence_threshold: 0.5,
        ..Default::default()
    };
    let strings = extract_utf16_strings(&data, &config);

    assert!(!strings.is_empty());
    assert!(strings[0].confidence >= 0.5);
}

#[test]
fn test_utf16_confidence_null_pattern_penalty() {
    // Create data with null-interleaved pattern (false positive)
    let data = vec![
        0x41, 0x00, 0x00, 0x00, 0x42, 0x00, 0x00, 0x00, 0x43, 0x00, 0x00, 0x00,
    ]; // "A\0B\0C\0" pattern

    let config = Utf16ExtractionConfig {
        byte_order: ByteOrder::LE,
        confidence_threshold: 0.3, // Lower threshold to see if it gets filtered
        ..Default::default()
    };
    let strings = extract_utf16_strings(&data, &config);

    // Should have low confidence or be filtered out
    if !strings.is_empty() {
        assert!(strings[0].confidence < 0.7);
    }
}

#[test]
fn test_utf16_empty_data() {
    let data = &[];
    let config = Utf16ExtractionConfig::default();
    let strings = extract_utf16_strings(data, &config);
    assert!(strings.is_empty());
}

#[test]
fn test_utf16_odd_length_data() {
    let data = &[0x48, 0x00, 0x65, 0x00, 0x6C];
    let config = Utf16ExtractionConfig::default();
    let _strings = extract_utf16_strings(data, &config);
    // Should not panic
}

#[test]
fn test_extract_from_section_metadata() {
    let section = create_test_section(".rdata", 0, 30, Some(0x1000));
    let mut data = create_utf16le_string("Hello World");
    data.extend_from_slice(&[0x00, 0x00]);

    let config = Utf16ExtractionConfig::default();
    let strings = extract_from_section(&section, &data, &config, None, false, 0.5);

    assert!(!strings.is_empty());
    assert_eq!(strings[0].section, Some(".rdata".to_string()));
    assert_eq!(strings[0].rva, Some(0x1000));
}
