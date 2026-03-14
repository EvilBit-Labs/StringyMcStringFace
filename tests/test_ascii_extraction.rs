//! Unit tests for ASCII string extraction

use stringy::extraction::ascii::{
    AsciiExtractionConfig, extract_ascii_strings, extract_from_section,
};
use stringy::types::{Encoding, SectionInfo, SectionType, StringSource};

#[test]
fn test_basic_extraction() {
    let data = b"Hello\0World\0Test123";
    let config = AsciiExtractionConfig::default();
    let strings = extract_ascii_strings(data, &config);

    assert_eq!(strings.len(), 3);
    assert_eq!(strings[0].text, "Hello");
    assert_eq!(strings[0].offset, 0);
    assert_eq!(strings[0].encoding, Encoding::Ascii);
    assert_eq!(strings[0].source, StringSource::SectionData);
    assert_eq!(strings[0].confidence, 1.0);
}

#[test]
fn test_minimum_length_threshold() {
    let data = b"Hi\0Test\0AB\0LongString";
    let config = AsciiExtractionConfig::new(4);
    let strings = extract_ascii_strings(data, &config);

    assert_eq!(strings.len(), 2);
    assert_eq!(strings[0].text, "Test");
    assert_eq!(strings[1].text, "LongString");
}

#[test]
fn test_null_terminated_strings() {
    let data = b"First\0Second\0Third";
    let config = AsciiExtractionConfig::default();
    let strings = extract_ascii_strings(data, &config);

    assert_eq!(strings.len(), 3);
    assert_eq!(strings[0].text, "First");
    assert_eq!(strings[1].text, "Second");
    assert_eq!(strings[2].text, "Third");
}

#[test]
fn test_mixed_printable_nonprintable() {
    let data = b"Hello\x00World\x01Test";
    let config = AsciiExtractionConfig::default();
    let strings = extract_ascii_strings(data, &config);

    assert_eq!(strings.len(), 3);
    assert_eq!(strings[0].text, "Hello");
    assert_eq!(strings[1].text, "World");
    assert_eq!(strings[2].text, "Test");
}

#[test]
fn test_empty_input() {
    let data = b"";
    let config = AsciiExtractionConfig::default();
    let strings = extract_ascii_strings(data, &config);

    assert!(strings.is_empty());
}

#[test]
fn test_no_valid_strings() {
    let data = &[0x00, 0xFF, 0x01, 0x02, 0x03];
    let config = AsciiExtractionConfig::default();
    let strings = extract_ascii_strings(data, &config);

    assert!(strings.is_empty());
}

#[test]
fn test_string_at_section_boundary() {
    let section = SectionInfo::new(".rodata".to_string(), 7, 12, SectionType::StringData, 1.0)
        .with_rva(0x2000);

    let data = b"prefix\0Hello World\0suffix";
    let config = AsciiExtractionConfig::default();
    let strings = extract_from_section(&section, data, &config, None, false, 0.5);

    assert!(!strings.is_empty());
    let hello_world = strings.iter().find(|s| s.text == "Hello World");
    assert!(hello_world.is_some());
    if let Some(s) = hello_world {
        assert_eq!(s.offset, 7);
        assert_eq!(s.rva, Some(0x2000));
        assert_eq!(s.section, Some(".rodata".to_string()));
    }
}

#[test]
fn test_very_long_string() {
    let long_string = "A".repeat(500);
    let data = format!("{}\0Short", long_string).into_bytes();
    let config = AsciiExtractionConfig {
        max_length: Some(200),
        ..Default::default()
    };
    let strings = extract_ascii_strings(&data, &config);

    assert_eq!(strings.len(), 1);
    assert_eq!(strings[0].text, "Short");
}

#[test]
fn test_single_character_sequences() {
    let data = b"A\0Test\0B\0C";
    let config = AsciiExtractionConfig::default();
    let strings = extract_ascii_strings(data, &config);

    assert_eq!(strings.len(), 1);
    assert_eq!(strings[0].text, "Test");
}

#[test]
fn test_different_section_types() {
    let rodata_section =
        SectionInfo::new(".rodata".to_string(), 0, 20, SectionType::StringData, 1.0)
            .with_rva(0x1000);

    let data_section = SectionInfo::new(".data".to_string(), 0, 20, SectionType::WritableData, 0.5)
        .with_rva(0x2000)
        .with_writable(true);

    let data = b"Hello World\0Test";
    let config = AsciiExtractionConfig::default();

    let rodata_strings = extract_from_section(&rodata_section, data, &config, None, false, 0.5);
    let data_strings = extract_from_section(&data_section, data, &config, None, false, 0.5);

    assert_eq!(rodata_strings.len(), 2);
    assert_eq!(data_strings.len(), 2);

    for string in &rodata_strings {
        assert_eq!(string.section, Some(".rodata".to_string()));
    }

    for string in &data_strings {
        assert_eq!(string.section, Some(".data".to_string()));
    }
}

#[test]
fn test_section_metadata_attachment() {
    let section = SectionInfo::new(".custom".to_string(), 0, 20, SectionType::ReadOnlyData, 0.8)
        .with_rva(0x3000);

    let data = b"Test String\0Another";
    let config = AsciiExtractionConfig::default();
    let strings = extract_from_section(&section, data, &config, None, false, 0.5);

    for string in &strings {
        assert_eq!(string.section, Some(".custom".to_string()));
        assert!(string.rva.is_some());
        assert!(string.rva.unwrap() >= 0x3000);
    }
}

#[test]
fn test_custom_minimum_length() {
    let data = b"Test\0Hello\0AB";
    let config = AsciiExtractionConfig::new(5);
    let strings = extract_ascii_strings(data, &config);

    assert_eq!(strings.len(), 1);
    assert_eq!(strings[0].text, "Hello");
}

#[test]
fn test_noise_filtering_disabled() {
    // This test verifies that extraction works even when noise filtering is conceptually disabled
    // (by setting confidence to 1.0 for all extracted strings)
    let data = b"Hello\0AAAA\0World";
    let config = AsciiExtractionConfig::default();
    let strings = extract_ascii_strings(data, &config);

    // All strings should be extracted with confidence 1.0
    assert_eq!(strings.len(), 3);
    for string in &strings {
        assert_eq!(string.confidence, 1.0);
    }
}

#[test]
fn test_configuration_customization() {
    let config = AsciiExtractionConfig {
        min_length: 8,
        max_length: Some(50),
    };

    let data = b"Short\0VeryLongStringHere\0MediumLength";
    let strings = extract_ascii_strings(data, &config);

    // "VeryLongStringHere" (18 chars) and "MediumLength" (12 chars) should pass (length >= 8 and <= 50)
    // "Short" (5 chars) should be filtered out (length < 8)
    assert_eq!(strings.len(), 2);
    assert!(strings.iter().any(|s| s.text == "VeryLongStringHere"));
    assert!(strings.iter().any(|s| s.text == "MediumLength"));
}
