//! Tests for the non-null-termination confidence cap (ADR-0003).
//!
//! Kept in a sibling module to `tests.rs` so neither file exceeds the project's
//! 500-line limit.

use super::*;
use crate::extraction::config::NoiseFilterConfig;
use crate::extraction::filters::{CompositeNoiseFilter, FilterContext};
use crate::types::{SectionInfo, SectionType};

// Helper to create test section (mirrors the one in `tests.rs`).
fn create_test_section(name: &str, offset: u64, size: u64, rva: Option<u64>) -> SectionInfo {
    let section = SectionInfo::new(name.to_string(), offset, size, SectionType::StringData, 1.0);
    match rva {
        Some(rva) => section.with_rva(rva),
        None => section,
    }
}

#[test]
fn test_null_terminated_string_keeps_full_confidence() {
    // Arrange: "HelloWorld" is null-terminated; filtering disabled gives base 1.0
    let section = create_test_section(".rodata", 0, 32, None);
    let data = b"HelloWorld\0trailing";
    let config = AsciiExtractionConfig::default();

    // Act
    let strings = extract_from_section(&section, data, &config, None, false, 0.5);

    // Assert
    let hello = strings
        .iter()
        .find(|s| s.text == "HelloWorld")
        .expect("HelloWorld should be extracted");
    assert_eq!(hello.confidence, 1.0);
}

#[test]
fn test_non_null_cutoff_caps_confidence_even_without_filtering() {
    // Arrange: "HelloWorld" is cut off by 0x01, not a null terminator. The
    // termination cap must apply even when noise filtering is disabled.
    let section = create_test_section(".rodata", 0, 32, None);
    let data = b"HelloWorld\x01trailing";
    let config = AsciiExtractionConfig::default();

    // Act
    let strings = extract_from_section(&section, data, &config, None, false, 0.5);

    // Assert
    let hello = strings
        .iter()
        .find(|s| s.text == "HelloWorld")
        .expect("HelloWorld should be extracted");
    assert_eq!(hello.confidence, 0.9);
}

#[test]
fn test_newline_terminated_string_keeps_full_confidence() {
    // Arrange: a line of text terminated by a newline is cleanly delimited, not
    // cut off by binary garbage, so it must not be capped (regression for the
    // multi-line-text case: license headers, embedded scripts).
    let section = create_test_section(".rodata", 0, 32, None);
    let data = b"HelloWorld\ntrailing";
    let config = AsciiExtractionConfig::default();

    // Act
    let strings = extract_from_section(&section, data, &config, None, false, 0.5);

    // Assert
    let hello = strings
        .iter()
        .find(|s| s.text == "HelloWorld")
        .expect("HelloWorld should be extracted");
    assert_eq!(hello.confidence, 1.0);
}

#[test]
fn test_tab_terminated_string_keeps_full_confidence() {
    // Arrange: tab is ASCII whitespace, a legitimate field separator, not a cutoff.
    let section = create_test_section(".rodata", 0, 32, None);
    let data = b"HelloWorld\ttrailing";
    let config = AsciiExtractionConfig::default();

    // Act
    let strings = extract_from_section(&section, data, &config, None, false, 0.5);

    // Assert
    let hello = strings
        .iter()
        .find(|s| s.text == "HelloWorld")
        .expect("HelloWorld should be extracted");
    assert_eq!(hello.confidence, 1.0);
}

#[test]
fn test_termination_cap_uses_section_relative_offset() {
    // Arrange: a non-null-terminated string in a section that does NOT start at
    // file offset 0. Regression guard for KTD3's ordering constraint: the cap
    // must read the terminator via the section-relative offset, not the
    // post-adjustment absolute offset. Section starts at 8, and section_data is
    // exactly "CappedText\x01" (11 bytes). Correct behavior reads the relative
    // terminator section_data[10] = 0x01 -> 0.9 cap. A bug using the absolute
    // offset would read section_data[8 + 10] = out of bounds -> buffer-end ->
    // wrongly 1.0, so the assertion below fails under that regression.
    let section = create_test_section(".rodata", 8, 11, None);
    let data = b"PADDINGXCappedText\x01";
    let config = AsciiExtractionConfig::default();

    // Act
    let strings = extract_from_section(&section, data, &config, None, false, 0.5);

    // Assert
    let capped = strings
        .iter()
        .find(|s| s.text == "CappedText")
        .expect("CappedText should be extracted from the offset-8 section");
    assert_eq!(capped.offset, 8);
    assert_eq!(capped.confidence, 0.9);
}

#[test]
fn test_buffer_end_string_keeps_full_confidence() {
    // Arrange: "EndString" runs to the end of the section slice; termination
    // is unknown there, and unknown is not evidence of noise.
    let section = create_test_section(".rodata", 0, 13, None);
    let data = b"pad\0EndString";
    let config = AsciiExtractionConfig::default();

    // Act
    let strings = extract_from_section(&section, data, &config, None, false, 0.5);

    // Assert
    let end = strings
        .iter()
        .find(|s| s.text == "EndString")
        .expect("EndString should be extracted");
    assert_eq!(end.confidence, 1.0);
}

#[test]
fn test_null_terminated_outranks_identical_cutoff_twin() {
    // Arrange: two identical printable runs, one null-terminated, one cut off
    // by 0x01 (extractor level, pre-dedup)
    let section = create_test_section(".rodata", 0, 32, None);
    let data = b"SameText\0SameText\x01";
    let config = AsciiExtractionConfig::default();

    // Act
    let strings = extract_from_section(&section, data, &config, None, false, 0.5);

    // Assert
    assert_eq!(strings.len(), 2);
    assert_eq!(strings[0].text, "SameText");
    assert_eq!(strings[1].text, "SameText");
    assert!(strings[0].confidence > strings[1].confidence);
    assert_eq!(strings[1].confidence, 0.9);
}

#[test]
fn test_termination_cap_applies_with_noise_filtering_enabled() {
    // Arrange: identical twins so both get the same noise-filter confidence;
    // only the 0x01-cut twin should additionally be capped
    let section = create_test_section(".rodata", 0, 64, None);
    let data = b"Hello World Text\0Hello World Text\x01";
    let config = AsciiExtractionConfig::default();
    let noise_config = NoiseFilterConfig::default();

    // Act
    let strings = extract_from_section(&section, data, &config, Some(&noise_config), true, 0.0);

    // Assert
    assert_eq!(strings.len(), 2);
    assert!(strings[1].confidence <= 0.9);
    assert!(strings[0].confidence >= strings[1].confidence);
}

#[test]
fn test_null_termination_does_not_raise_low_noise_confidence() {
    // Arrange: null termination must never raise confidence above the
    // noise-filter verdict for junk-looking text
    let section = create_test_section(".rodata", 0, 64, None);
    let junk = "qZx9vB2kQpLmWnRt";
    let data = format!("{junk}\0").into_bytes();
    let config = AsciiExtractionConfig::default();
    let noise_config = NoiseFilterConfig::default();
    let filter = CompositeNoiseFilter::new(&noise_config);
    let filter_context = FilterContext::from_section(&section);
    let noise_only = filter.calculate_confidence(junk, &filter_context);

    // Act
    let strings = extract_from_section(&section, &data, &config, Some(&noise_config), true, 0.0);

    // Assert
    let extracted = strings
        .iter()
        .find(|s| s.text == junk)
        .expect("junk string should be extracted at threshold 0.0");
    assert!(extracted.confidence <= noise_only);
}
