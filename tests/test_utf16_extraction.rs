//! Unit tests for UTF-16LE string extraction

use stringy::extraction::utf16::{
    Utf16ExtractionConfig, extract_from_section, extract_utf16le_strings,
};
use stringy::types::{Encoding, SectionInfo, SectionType, StringSource};

// Helper to create UTF-16LE test data
fn create_utf16le_string(text: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for ch in text.chars() {
        let code_point = ch as u32;
        if code_point <= 0xFFFF {
            let u16_val = code_point as u16;
            bytes.extend_from_slice(&u16_val.to_le_bytes());
        }
    }
    bytes
}

// Helper to create test section
fn create_test_section(name: &str, offset: u64, size: u64, rva: Option<u64>) -> SectionInfo {
    SectionInfo {
        name: name.to_string(),
        offset,
        size,
        rva,
        section_type: SectionType::StringData,
        is_executable: false,
        is_writable: false,
        weight: 1.0,
    }
}

#[test]
fn test_basic_utf16le_extraction() {
    // "Hello\0World\0Test123\0" in UTF-16LE
    let mut data = create_utf16le_string("Hello");
    data.extend_from_slice(&[0x00, 0x00]);
    let world = create_utf16le_string("World");
    data.extend_from_slice(&world);
    data.extend_from_slice(&[0x00, 0x00]);
    let test123 = create_utf16le_string("Test123");
    data.extend_from_slice(&test123);
    data.extend_from_slice(&[0x00, 0x00]);

    let config = Utf16ExtractionConfig::default();
    let strings = extract_utf16le_strings(&data, &config);

    assert_eq!(strings.len(), 3);
    assert_eq!(strings[0].text, "Hello");
    assert_eq!(strings[0].offset, 0);
    assert_eq!(strings[0].encoding, Encoding::Utf16Le);
    assert_eq!(strings[0].source, StringSource::SectionData);
    assert_eq!(strings[1].text, "World");
    assert_eq!(strings[2].text, "Test123");
}

#[test]
fn test_minimum_character_length() {
    // "Hi\0Test\0AB\0LongString\0" in UTF-16LE
    let mut data = create_utf16le_string("Hi");
    data.extend_from_slice(&[0x00, 0x00]);
    let test = create_utf16le_string("Test");
    data.extend_from_slice(&test);
    data.extend_from_slice(&[0x00, 0x00]);
    let ab = create_utf16le_string("AB");
    data.extend_from_slice(&ab);
    data.extend_from_slice(&[0x00, 0x00]);
    let long = create_utf16le_string("LongString");
    data.extend_from_slice(&long);
    data.extend_from_slice(&[0x00, 0x00]);

    let config = Utf16ExtractionConfig::default(); // min_char_len = 3
    let strings = extract_utf16le_strings(&data, &config);

    // "Hi" (2 chars) and "AB" (2 chars) should be filtered out
    assert_eq!(strings.len(), 2);
    assert_eq!(strings[0].text, "Test");
    assert_eq!(strings[1].text, "LongString");
}

#[test]
fn test_custom_minimum_length() {
    // "Test\0Hello\0AB" in UTF-16LE
    let mut data = create_utf16le_string("Test");
    data.extend_from_slice(&[0x00, 0x00]);
    let hello = create_utf16le_string("Hello");
    data.extend_from_slice(&hello);
    data.extend_from_slice(&[0x00, 0x00]);
    let ab = create_utf16le_string("AB");
    data.extend_from_slice(&ab);

    let config = Utf16ExtractionConfig::new(5); // min_char_len = 5
    let strings = extract_utf16le_strings(&data, &config);

    assert_eq!(strings.len(), 1);
    assert_eq!(strings[0].text, "Hello");
}

#[test]
fn test_null_terminated_strings() {
    // Test proper null termination detection
    let mut data = create_utf16le_string("First");
    data.extend_from_slice(&[0x00, 0x00]);
    let second = create_utf16le_string("Second");
    data.extend_from_slice(&second);
    data.extend_from_slice(&[0x00, 0x00]);
    let third = create_utf16le_string("Third");
    data.extend_from_slice(&third);
    data.extend_from_slice(&[0x00, 0x00]);

    let config = Utf16ExtractionConfig::default();
    let strings = extract_utf16le_strings(&data, &config);

    assert_eq!(strings.len(), 3);
    assert_eq!(strings[0].text, "First");
    assert_eq!(strings[1].text, "Second");
    assert_eq!(strings[2].text, "Third");
}

#[test]
fn test_high_confidence_strings() {
    // High confidence: all printable with null terminator
    let mut data = create_utf16le_string("Microsoft Corporation");
    data.extend_from_slice(&[0x00, 0x00]);

    let config = Utf16ExtractionConfig {
        min_confidence: 0.9,
        ..Default::default()
    };
    let strings = extract_utf16le_strings(&data, &config);

    assert_eq!(strings.len(), 1);
    assert!(strings[0].confidence > 0.9);
}

#[test]
fn test_medium_confidence_strings() {
    // Medium confidence: mostly printable
    let mut data = create_utf16le_string("Test123");
    data.extend_from_slice(&[0x00, 0x00]);

    let config = Utf16ExtractionConfig {
        min_confidence: 0.7,
        ..Default::default()
    };
    let strings = extract_utf16le_strings(&data, &config);

    assert_eq!(strings.len(), 1);
    assert!(strings[0].confidence >= 0.7);
}

#[test]
fn test_low_confidence_strings() {
    // Low confidence: mixed printable/non-printable (using control character 0x7F DEL)
    let mut data = create_utf16le_string("Te");
    data.extend_from_slice(&[0x7F, 0x00, 0x73, 0x00, 0x74, 0x00]); // "Te[non-printable]st"
    data.extend_from_slice(&[0x00, 0x00]);

    let config = Utf16ExtractionConfig {
        min_confidence: 0.5,
        ..Default::default()
    };
    let strings = extract_utf16le_strings(&data, &config);

    // May or may not extract depending on confidence calculation
    if !strings.is_empty() {
        assert!(strings[0].confidence < 0.7);
    }
}

#[test]
fn test_confidence_threshold_filtering() {
    // Create a string with medium confidence
    let mut data = create_utf16le_string("Test");
    data.extend_from_slice(&[0x00, 0x00]);

    // High threshold should filter it out
    let config = Utf16ExtractionConfig {
        min_confidence: 0.95,
        ..Default::default()
    };
    let strings = extract_utf16le_strings(&data, &config);

    // May be filtered out if confidence is below 0.95
    assert!(strings.is_empty() || strings[0].confidence >= 0.95);
}

#[test]
fn test_empty_input() {
    let data = &[];
    let config = Utf16ExtractionConfig::default();
    let strings = extract_utf16le_strings(data, &config);
    assert!(strings.is_empty());
}

#[test]
fn test_no_valid_strings() {
    // Binary data with no valid UTF-16LE sequences
    let data = &[0xFF, 0xFF, 0x01, 0x02, 0x03, 0x04];
    let config = Utf16ExtractionConfig::default();
    let strings = extract_utf16le_strings(data, &config);
    assert!(strings.is_empty());
}

#[test]
fn test_string_at_start() {
    // String at buffer start
    let mut data = create_utf16le_string("Start");
    data.extend_from_slice(&[0x00, 0x00]);
    let middle = create_utf16le_string("Middle");
    data.extend_from_slice(&middle);
    data.extend_from_slice(&[0x00, 0x00]);

    let config = Utf16ExtractionConfig::default();
    let strings = extract_utf16le_strings(&data, &config);

    assert_eq!(strings.len(), 2);
    assert_eq!(strings[0].text, "Start");
    assert_eq!(strings[0].offset, 0);
}

#[test]
fn test_string_at_end() {
    // String at buffer end without null terminator
    let mut data = create_utf16le_string("Start");
    data.extend_from_slice(&[0x00, 0x00]);
    let end = create_utf16le_string("EndTest");
    data.extend_from_slice(&end);

    let config = Utf16ExtractionConfig::default();
    let strings = extract_utf16le_strings(&data, &config);

    assert_eq!(strings.len(), 2);
    assert_eq!(strings[1].text, "EndTest");
}

#[test]
fn test_odd_length_data() {
    // Odd-length data should be handled gracefully
    let data = &[0x48, 0x00, 0x65, 0x00, 0x6C]; // Odd length
    let config = Utf16ExtractionConfig::default();
    let _strings = extract_utf16le_strings(data, &config);
    // Should not panic, may or may not find strings depending on alignment
}

#[test]
fn test_partial_string_at_boundary() {
    // Test partial UTF-16LE character at section boundary
    let section = create_test_section(".rdata", 0, 5, None);
    let data = &[0x48, 0x00, 0x65, 0x00, 0x6C]; // Odd length, partial character
    let config = Utf16ExtractionConfig::default();
    let strings = extract_from_section(&section, data, &config, None, false, 0.5);

    // Should handle gracefully without panicking
    assert!(strings.len() <= 1);
}

#[test]
fn test_interleaved_binary_data() {
    // UTF-16LE strings mixed with binary data
    let mut data = vec![0xFF, 0xFF, 0x01, 0x02];
    let hello = create_utf16le_string("Hello");
    data.extend_from_slice(&hello);
    data.extend_from_slice(&[0x00, 0x00]);
    data.extend_from_slice(&[0x03, 0x04, 0x05, 0x06]);
    let world = create_utf16le_string("World");
    data.extend_from_slice(&world);
    data.extend_from_slice(&[0x00, 0x00]);

    let config = Utf16ExtractionConfig::default();
    let strings = extract_utf16le_strings(&data, &config);

    assert_eq!(strings.len(), 2);
    assert_eq!(strings[0].text, "Hello");
    assert_eq!(strings[1].text, "World");
}

#[test]
fn test_section_metadata_attachment() {
    let section = create_test_section(".rdata", 0, 30, Some(0x1000));
    let mut data = create_utf16le_string("Test String");
    data.extend_from_slice(&[0x00, 0x00]);
    let another = create_utf16le_string("Another");
    data.extend_from_slice(&another);
    data.extend_from_slice(&[0x00, 0x00]);

    let config = Utf16ExtractionConfig::default();
    let strings = extract_from_section(&section, &data, &config, None, false, 0.5);

    assert_eq!(strings.len(), 2);
    for string in &strings {
        assert_eq!(string.section, Some(".rdata".to_string()));
        assert!(string.rva.is_some());
        assert!(string.rva.unwrap() >= 0x1000);
    }
}

#[test]
fn test_section_boundary_handling() {
    // Test that extraction respects section boundaries
    let section = create_test_section(".rdata", 10, 12, Some(0x2000));
    let mut prefix = vec![0x00; 10];
    let hello = create_utf16le_string("Hello");
    prefix.extend_from_slice(&hello);
    prefix.extend_from_slice(&[0x00, 0x00]);
    prefix.extend_from_slice(&[0xFF, 0xFF]); // Binary data after section

    let config = Utf16ExtractionConfig::default();
    let strings = extract_from_section(&section, &prefix, &config, None, false, 0.5);

    assert_eq!(strings.len(), 1);
    assert_eq!(strings[0].text, "Hello");
    assert_eq!(strings[0].offset, 10);
    assert_eq!(strings[0].rva, Some(0x2000));
}

#[test]
fn test_section_out_of_bounds() {
    let section = create_test_section(".data", 1000, 100, None);
    let data = create_utf16le_string("Short data");
    let config = Utf16ExtractionConfig::default();
    let strings = extract_from_section(&section, &data, &config, None, false, 0.5);

    // Should return empty vector, not panic
    assert!(strings.is_empty());
}

#[test]
fn test_different_section_types() {
    let rdata_section = SectionInfo {
        name: ".rdata".to_string(),
        offset: 0,
        size: 30,
        rva: Some(0x1000),
        section_type: SectionType::StringData,
        is_executable: false,
        is_writable: false,
        weight: 1.0,
    };

    let data_section = SectionInfo {
        name: ".data".to_string(),
        offset: 0,
        size: 30,
        rva: Some(0x2000),
        section_type: SectionType::WritableData,
        is_executable: false,
        is_writable: true,
        weight: 0.5,
    };

    let mut data = create_utf16le_string("Hello World");
    data.extend_from_slice(&[0x00, 0x00]);
    let test = create_utf16le_string("Test");
    data.extend_from_slice(&test);
    data.extend_from_slice(&[0x00, 0x00]);

    let config = Utf16ExtractionConfig::default();

    let rdata_strings = extract_from_section(&rdata_section, &data, &config, None, false, 0.5);
    let data_strings = extract_from_section(&data_section, &data, &config, None, false, 0.5);

    assert_eq!(rdata_strings.len(), 2);
    assert_eq!(data_strings.len(), 2);

    for string in &rdata_strings {
        assert_eq!(string.section, Some(".rdata".to_string()));
    }

    for string in &data_strings {
        assert_eq!(string.section, Some(".data".to_string()));
    }
}

#[test]
fn test_windows_pe_versioninfo() {
    // Simulate VERSIONINFO resource strings
    let mut data = create_utf16le_string("Microsoft Corporation");
    data.extend_from_slice(&[0x00, 0x00]);
    let copyright = create_utf16le_string("Copyright © 2024");
    data.extend_from_slice(&copyright);
    data.extend_from_slice(&[0x00, 0x00]);

    let config = Utf16ExtractionConfig::default();
    let strings = extract_utf16le_strings(&data, &config);

    assert_eq!(strings.len(), 2);
    assert_eq!(strings[0].text, "Microsoft Corporation");
    assert_eq!(strings[1].text, "Copyright © 2024");
}

#[test]
fn test_dotnet_string_literals() {
    // Simulate .NET assembly string literals
    let mut data = create_utf16le_string("System.String");
    data.extend_from_slice(&[0x00, 0x00]);
    let namespace = create_utf16le_string("System.Collections.Generic");
    data.extend_from_slice(&namespace);
    data.extend_from_slice(&[0x00, 0x00]);

    let config = Utf16ExtractionConfig::default();
    let strings = extract_utf16le_strings(&data, &config);

    assert_eq!(strings.len(), 2);
    assert_eq!(strings[0].text, "System.String");
    assert_eq!(strings[1].text, "System.Collections.Generic");
}

#[test]
fn test_registry_paths() {
    // Test Windows registry path extraction
    let mut data = create_utf16le_string("HKEY_LOCAL_MACHINE\\SOFTWARE");
    data.extend_from_slice(&[0x00, 0x00]);
    let path = create_utf16le_string("C:\\Windows\\System32");
    data.extend_from_slice(&path);
    data.extend_from_slice(&[0x00, 0x00]);

    let config = Utf16ExtractionConfig::default();
    let strings = extract_utf16le_strings(&data, &config);

    assert_eq!(strings.len(), 2);
    assert_eq!(strings[0].text, "HKEY_LOCAL_MACHINE\\SOFTWARE");
    assert_eq!(strings[1].text, "C:\\Windows\\System32");
}

#[test]
fn test_noise_filtering_enabled() {
    // Test with noise filtering enabled
    let mut data = create_utf16le_string("Hello");
    data.extend_from_slice(&[0x00, 0x00]);
    // Add some noisy data
    let noisy = create_utf16le_string("AAAA");
    data.extend_from_slice(&noisy);
    data.extend_from_slice(&[0x00, 0x00]);

    let section = create_test_section(".rdata", 0, data.len() as u64, None);
    let config = Utf16ExtractionConfig::default();
    let noise_config = Some(stringy::extraction::config::NoiseFilterConfig::default());

    let strings = extract_from_section(&section, &data, &config, noise_config.as_ref(), true, 0.5);

    // Should extract strings, but noisy ones may have lower confidence
    assert!(!strings.is_empty());
    for string in &strings {
        assert!(string.confidence >= 0.5);
    }
}

#[test]
fn test_noise_filtering_disabled() {
    // Test with noise filtering disabled
    let mut data = create_utf16le_string("Hello");
    data.extend_from_slice(&[0x00, 0x00]);
    let world = create_utf16le_string("World");
    data.extend_from_slice(&world);
    data.extend_from_slice(&[0x00, 0x00]);

    let section = create_test_section(".rdata", 0, data.len() as u64, None);
    let config = Utf16ExtractionConfig::default();

    let strings = extract_from_section(&section, &data, &config, None, false, 0.5);

    // Should extract all strings
    assert_eq!(strings.len(), 2);
}

#[test]
fn test_confidence_threshold_application() {
    // Test various confidence thresholds
    let mut data = create_utf16le_string("Test");
    data.extend_from_slice(&[0x00, 0x00]);

    let section = create_test_section(".rdata", 0, data.len() as u64, None);
    let config = Utf16ExtractionConfig::default();

    // Low threshold should include more strings
    let strings_low = extract_from_section(&section, &data, &config, None, false, 0.3);
    // High threshold should filter more strings
    let strings_high = extract_from_section(&section, &data, &config, None, false, 0.95);

    assert!(strings_low.len() >= strings_high.len());
}

#[test]
fn test_config_defaults() {
    let config = Utf16ExtractionConfig::default();
    assert_eq!(config.min_char_len, 3);
    assert_eq!(config.max_char_len, None);
    assert_eq!(config.min_confidence, 0.7);
}

#[test]
fn test_config_customization() {
    let config = Utf16ExtractionConfig {
        min_char_len: 5,
        max_char_len: Some(100),
        min_confidence: 0.8,
    };

    assert_eq!(config.min_char_len, 5);
    assert_eq!(config.max_char_len, Some(100));
    assert_eq!(config.min_confidence, 0.8);
}

#[test]
fn test_max_length_filtering() {
    // Test maximum length filtering
    let mut data = create_utf16le_string("Short");
    data.extend_from_slice(&[0x00, 0x00]);
    let long_string = "A".repeat(200);
    let long = create_utf16le_string(&long_string);
    data.extend_from_slice(&long);
    data.extend_from_slice(&[0x00, 0x00]);

    let config = Utf16ExtractionConfig {
        max_char_len: Some(10),
        ..Default::default()
    };
    let strings = extract_utf16le_strings(&data, &config);

    assert_eq!(strings.len(), 1);
    assert_eq!(strings[0].text, "Short");
}

#[test]
fn test_surrogate_pairs() {
    // Test surrogate pairs (non-BMP characters)
    // U+1F600 (😀) is encoded as surrogate pair: 0xD83D 0xDE00
    let mut data = vec![0x3D, 0xD8, 0x00, 0xDE]; // 😀 in UTF-16LE
    data.extend_from_slice(&[0x00, 0x00]); // null terminator

    let config = Utf16ExtractionConfig::default();
    let strings = extract_utf16le_strings(&data, &config);

    assert_eq!(strings.len(), 1);
    assert_eq!(strings[0].text, "😀");
    assert_eq!(strings[0].offset, 0);
}

#[test]
fn test_lone_surrogate_rejection() {
    // Test that lone surrogates are rejected
    // High surrogate without low surrogate
    let data = &[0x3D, 0xD8, 0x48, 0x00]; // High surrogate + 'H'
    let config = Utf16ExtractionConfig::default();
    let strings = extract_utf16le_strings(data, &config);

    // Should not extract string starting with lone high surrogate
    assert!(strings.is_empty() || strings[0].text != "H");
}

#[test]
fn test_surrogate_pair_confidence() {
    // Test confidence calculation with surrogate pairs
    use stringy::extraction::utf16::calculate_confidence;

    // String with surrogate pair (😀) and regular characters
    let mut data = vec![0x48, 0x00]; // 'H'
    data.extend_from_slice(&[0x3D, 0xD8, 0x00, 0xDE]); // 😀
    data.extend_from_slice(&[0x65, 0x00]); // 'e'

    let confidence = calculate_confidence(&data, 3, false);
    // Should have high confidence since all characters are printable
    assert!(confidence >= 0.7);
}

#[test]
fn test_alignment_handling() {
    // Test that extraction handles both even and odd section offsets
    // Section starting at odd offset should still find strings
    let section = create_test_section(".rdata", 1, 20, Some(0x1001));

    // Create data with prefix byte, then UTF-16LE string
    let mut data = vec![0xFF]; // Prefix byte (odd offset)
    let hello = create_utf16le_string("Hello");
    data.extend_from_slice(&hello);
    data.extend_from_slice(&[0x00, 0x00]);

    let config = Utf16ExtractionConfig::default();
    let strings = extract_from_section(&section, &data, &config, None, false, 0.5);

    // Should find the string even though section starts at odd offset
    assert_eq!(strings.len(), 1);
    assert_eq!(strings[0].text, "Hello");
    assert_eq!(strings[0].offset, 1);
}
