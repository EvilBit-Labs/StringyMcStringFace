use super::*;
use crate::types::{Encoding, SectionInfo, SectionType, StringSource};

// Helper to create test section
fn create_test_section(name: &str, offset: u64, size: u64, rva: Option<u64>) -> SectionInfo {
    let section = SectionInfo::new(name.to_string(), offset, size, SectionType::StringData, 1.0);
    match rva {
        Some(rva) => section.with_rva(rva),
        None => section,
    }
}

#[test]
fn test_is_printable_ascii() {
    // Printable ASCII range (0x20-0x7E)
    assert!(is_printable_ascii(0x20)); // space
    assert!(is_printable_ascii(0x21)); // !
    assert!(is_printable_ascii(0x41)); // A
    assert!(is_printable_ascii(0x5A)); // Z
    assert!(is_printable_ascii(0x61)); // a
    assert!(is_printable_ascii(0x7A)); // z
    assert!(is_printable_ascii(0x30)); // 0
    assert!(is_printable_ascii(0x39)); // 9
    assert!(is_printable_ascii(0x7E)); // ~

    // Non-printable
    assert!(!is_printable_ascii(0x00));
    assert!(!is_printable_ascii(0x1F));
    assert!(!is_printable_ascii(0x7F));
    assert!(!is_printable_ascii(0xFF));
}

#[test]
fn test_extract_ascii_strings_basic() {
    // Basic extraction with default minimum length (4)
    let data = b"Hello\0World\0Test";
    let config = AsciiExtractionConfig::default();
    let strings = extract_ascii_strings(data, &config);

    assert_eq!(strings.len(), 3);
    assert_eq!(strings[0].text, "Hello");
    assert_eq!(strings[0].offset, 0);
    assert_eq!(strings[0].encoding, Encoding::Ascii);
    assert_eq!(strings[0].source, StringSource::SectionData);
    assert_eq!(strings[1].text, "World");
    assert_eq!(strings[1].offset, 6);
    assert_eq!(strings[2].text, "Test");
    assert_eq!(strings[2].offset, 12);
}

#[test]
fn test_extract_ascii_strings_custom_min_length() {
    // Custom minimum length filtering
    let data = b"Hi\0Test\0AB\0LongString";
    let config = AsciiExtractionConfig::new(3);
    let strings = extract_ascii_strings(data, &config);

    assert_eq!(strings.len(), 2);
    assert_eq!(strings[0].text, "Test");
    assert_eq!(strings[1].text, "LongString");
    // "Hi" and "AB" should be filtered out (length < 3)
}

#[test]
fn test_extract_ascii_strings_min_length_5() {
    let data = b"Test\0Hello\0World";
    let config = AsciiExtractionConfig::new(5);
    let strings = extract_ascii_strings(data, &config);

    assert_eq!(strings.len(), 2);
    assert_eq!(strings[0].text, "Hello");
    assert_eq!(strings[1].text, "World");
    // "Test" should be filtered out (length < 5)
}

#[test]
fn test_extract_ascii_strings_min_length_10() {
    let data = b"Short\0VeryLongStringHere";
    let config = AsciiExtractionConfig::new(10);
    let strings = extract_ascii_strings(data, &config);

    assert_eq!(strings.len(), 1);
    assert_eq!(strings[0].text, "VeryLongStringHere");
}

#[test]
fn test_extract_ascii_strings_empty_input() {
    // Empty input edge case
    let data = b"";
    let config = AsciiExtractionConfig::default();
    let strings = extract_ascii_strings(data, &config);

    assert!(strings.is_empty());
}

#[test]
fn test_extract_ascii_strings_no_strings_found() {
    // No strings found (all binary data)
    let data = &[0x00, 0xFF, 0x01, 0x02, 0x03];
    let config = AsciiExtractionConfig::default();
    let strings = extract_ascii_strings(data, &config);

    assert!(strings.is_empty());
}

#[test]
fn test_extract_ascii_strings_string_at_start() {
    // String at buffer start
    let data = b"Start\0Middle\0End";
    let config = AsciiExtractionConfig::default();
    let strings = extract_ascii_strings(data, &config);

    // "End" is only 3 characters, below min_length=4, so filtered out
    assert_eq!(strings.len(), 2);
    assert_eq!(strings[0].text, "Start");
    assert_eq!(strings[0].offset, 0);
    assert_eq!(strings[1].text, "Middle");
}

#[test]
fn test_extract_ascii_strings_string_at_end() {
    // String at buffer end
    let data = b"Start\0Middle\0EndTest";
    let config = AsciiExtractionConfig::default();
    let strings = extract_ascii_strings(data, &config);

    assert_eq!(strings.len(), 3);
    assert_eq!(strings[2].text, "EndTest");
    assert_eq!(strings[2].offset, 13);
}

#[test]
fn test_extract_ascii_strings_single_char_below_minimum() {
    // Single character below minimum
    let data = b"A\0Test\0B\0C";
    let config = AsciiExtractionConfig::default();
    let strings = extract_ascii_strings(data, &config);

    assert_eq!(strings.len(), 1);
    assert_eq!(strings[0].text, "Test");
    // Single characters should be filtered out
}

#[test]
fn test_extract_ascii_strings_exact_minimum_length() {
    // Exact minimum length string
    let data = b"Test\0Hello";
    let config = AsciiExtractionConfig::default(); // min_length = 4
    let strings = extract_ascii_strings(data, &config);

    assert_eq!(strings.len(), 2);
    assert_eq!(strings[0].text, "Test");
    assert_eq!(strings[0].length, 4);
    assert_eq!(strings[1].text, "Hello");
}

#[test]
fn test_extract_ascii_strings_offset_calculation() {
    // Offset calculation correctness
    let data = b"prefix\0Hello\0World\0suffix";
    let config = AsciiExtractionConfig::default();
    let strings = extract_ascii_strings(data, &config);

    // All strings are >= 4 characters, so all should be extracted
    assert_eq!(strings.len(), 4);
    assert_eq!(strings[0].text, "prefix");
    assert_eq!(strings[0].offset, 0);
    assert_eq!(strings[1].text, "Hello");
    assert_eq!(strings[1].offset, 7); // "prefix\0" = 7 bytes
    assert_eq!(strings[2].text, "World");
    assert_eq!(strings[2].offset, 13); // "prefix\0Hello\0" = 13 bytes
    assert_eq!(strings[3].text, "suffix");
    assert_eq!(strings[3].offset, 19); // "prefix\0Hello\0World\0" = 19 bytes
}

#[test]
fn test_extract_ascii_strings_multiple_strings_sequence() {
    // Multiple strings in sequence
    let data = b"First\0Second\0Third\0Fourth";
    let config = AsciiExtractionConfig::default();
    let strings = extract_ascii_strings(data, &config);

    assert_eq!(strings.len(), 4);
    assert_eq!(strings[0].text, "First");
    assert_eq!(strings[1].text, "Second");
    assert_eq!(strings[2].text, "Third");
    assert_eq!(strings[3].text, "Fourth");
}

#[test]
fn test_extract_ascii_strings_separated_by_single_byte() {
    // Strings separated by single non-printable byte
    let data = b"Hello\x00World\x01Test";
    let config = AsciiExtractionConfig::default();
    let strings = extract_ascii_strings(data, &config);

    assert_eq!(strings.len(), 3);
    assert_eq!(strings[0].text, "Hello");
    assert_eq!(strings[1].text, "World");
    assert_eq!(strings[2].text, "Test");
}

#[test]
fn test_extract_ascii_strings_max_length_filtering() {
    // Max length filtering if configured
    let data = b"Short\0VeryLongStringHere";
    let config = AsciiExtractionConfig {
        max_length: Some(10),
        ..Default::default()
    };
    let strings = extract_ascii_strings(data, &config);

    assert_eq!(strings.len(), 1);
    assert_eq!(strings[0].text, "Short");
    // "VeryLongStringHere" should be filtered out (length > 10)
}

#[test]
fn test_extract_ascii_strings_very_long_string() {
    // Very long strings (test max_length enforcement)
    let long_string = "A".repeat(1000);
    let data = format!("{}\0Short", long_string).into_bytes();
    let config = AsciiExtractionConfig {
        max_length: Some(100),
        ..Default::default()
    };
    let strings = extract_ascii_strings(&data, &config);

    assert_eq!(strings.len(), 1);
    assert_eq!(strings[0].text, "Short");
    // Very long string should be filtered out
}

#[test]
fn test_extract_from_section_basic() {
    // Basic section extraction
    let section = create_test_section(".rodata", 0, 20, Some(0x1000));
    let data = b"Hello World\0Test";
    let config = AsciiExtractionConfig::default();
    let strings = extract_from_section(&section, data, &config, None, false, 0.5);

    assert_eq!(strings.len(), 2);
    assert_eq!(strings[0].text, "Hello World");
    assert_eq!(strings[0].offset, 0);
    assert_eq!(strings[0].rva, Some(0x1000));
    assert_eq!(strings[0].section, Some(".rodata".to_string()));
    assert_eq!(strings[1].text, "Test");
    assert_eq!(strings[1].offset, 12);
    assert_eq!(strings[1].rva, Some(0x100C));
}

#[test]
fn test_extract_from_section_offset_adjustment() {
    // Section metadata population (verify section name and RVA)
    // data = b"prefix\0Hello World\0suffix"
    //        "prefix\0" = 7 bytes, so "Hello World" starts at offset 7
    // Section should start at 7 to include "Hello World"
    let section = create_test_section(".data", 7, 12, Some(0x2000));
    let data = b"prefix\0Hello World\0suffix";
    let config = AsciiExtractionConfig::default();
    let strings = extract_from_section(&section, data, &config, None, false, 0.5);

    assert_eq!(strings.len(), 1);
    assert_eq!(strings[0].text, "Hello World");
    // Section starts at 7, "Hello World" is at relative offset 0 within section
    // Absolute offset = section.offset (7) + relative_offset (0) = 7
    assert_eq!(strings[0].offset, 7);
    assert_eq!(strings[0].rva, Some(0x2000));
    assert_eq!(strings[0].section, Some(".data".to_string()));
}

#[test]
fn test_extract_from_section_rva_calculation() {
    // RVA calculation with section offset
    let section = create_test_section(".text", 5, 10, Some(0x1000));
    let data = b"pre\0Hello\0suf";
    let config = AsciiExtractionConfig::default();
    let strings = extract_from_section(&section, data, &config, None, false, 0.5);

    assert!(
        !strings.is_empty(),
        "Should extract at least one string from section"
    );
    // Section data is data[5..15] = "Hello\0suf"
    // "Hello" is at relative offset 0
    // Absolute offset = 5 + 0 = 5
    // RVA = 0x1000 + 0 = 0x1000
    assert_eq!(strings[0].offset, 5);
    assert_eq!(strings[0].rva, Some(0x1000));
}

#[test]
fn test_extract_from_section_no_rva() {
    // Section without RVA
    let section = create_test_section(".data", 0, 20, None);
    let data = b"Hello World\0Test";
    let config = AsciiExtractionConfig::default();
    let strings = extract_from_section(&section, data, &config, None, false, 0.5);

    assert_eq!(strings.len(), 2);
    assert_eq!(strings[0].rva, None);
    assert_eq!(strings[1].rva, None);
}

#[test]
fn test_extract_from_section_section_name() {
    // Verify section name is populated
    let section = create_test_section(".custom", 0, 20, Some(0x3000));
    let data = b"Test String\0Another";
    let config = AsciiExtractionConfig::default();
    let strings = extract_from_section(&section, data, &config, None, false, 0.5);

    for string in &strings {
        assert_eq!(string.section, Some(".custom".to_string()));
    }
}

#[test]
fn test_extract_from_section_bounds_checking() {
    // Section boundaries (ensure slice doesn't exceed data.len())
    let section = create_test_section(".data", 0, 1000, None);
    let data = b"Short data";
    let config = AsciiExtractionConfig::default();
    let strings = extract_from_section(&section, data, &config, None, false, 0.5);

    // Should only extract from available data, not panic
    assert!(strings.len() <= 1);
}

#[test]
fn test_extract_from_section_out_of_bounds() {
    // Section offset + size overflow (use checked arithmetic)
    let section = create_test_section(".data", 1000, 100, None);
    let data = b"Short data";
    let config = AsciiExtractionConfig::default();
    let strings = extract_from_section(&section, data, &config, None, false, 0.5);

    // Should return empty vector, not panic
    assert!(strings.is_empty());
}

#[test]
fn test_extract_from_section_empty_section() {
    // Empty section
    let section = create_test_section(".empty", 0, 0, None);
    let data = b"Some data";
    let config = AsciiExtractionConfig::default();
    let strings = extract_from_section(&section, data, &config, None, false, 0.5);

    assert!(strings.is_empty());
}

#[test]
fn test_extraction_config_default() {
    let config = AsciiExtractionConfig::default();
    assert_eq!(config.min_length, 4);
    assert_eq!(config.max_length, None);
}

#[test]
fn test_extraction_config_new() {
    let config = AsciiExtractionConfig::new(8);
    assert_eq!(config.min_length, 8);
    assert_eq!(config.max_length, None);
}

#[test]
fn test_extraction_config_custom_max_length() {
    let config = AsciiExtractionConfig {
        max_length: Some(256),
        ..Default::default()
    };
    assert_eq!(config.min_length, 4);
    assert_eq!(config.max_length, Some(256));
}
