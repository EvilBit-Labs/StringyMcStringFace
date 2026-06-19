use super::*;
use crate::types::{
    BinaryFormat, ContainerInfo, Encoding, ExportInfo, ImportInfo, SectionInfo, SectionType,
    StringSource,
};

#[test]
fn test_extraction_config_default() {
    let config = ExtractionConfig::default();
    assert_eq!(config.min_length, 1);
    assert_eq!(config.max_length, 4096);
    assert_eq!(config.enabled_encodings.len(), 2);
    assert!(config.enabled_encodings.contains(&Encoding::Ascii));
    assert!(config.enabled_encodings.contains(&Encoding::Utf8));
    assert!(config.scan_code_sections);
    assert!(!config.include_debug);
    assert_eq!(config.section_priority.len(), 3);
    assert!(config.include_symbols);
}

#[test]
fn test_basic_extractor_extract_from_section() {
    let extractor = BasicExtractor::new();
    let config = ExtractionConfig::default();

    let section = SectionInfo::new(".rodata".to_string(), 0, 20, SectionType::StringData, 1.0)
        .with_rva(0x1000);

    let data = b"Hello World\0Test";
    let strings = extractor
        .extract_from_section(data, &section, &config)
        .unwrap();

    assert_eq!(strings.len(), 2);
    assert_eq!(strings[0].text, "Hello World");
    assert_eq!(strings[0].offset, 0);
    assert_eq!(strings[0].rva, Some(0x1000));
    assert_eq!(strings[0].section, Some(".rodata".to_string()));
    // ASCII content is now labeled UTF-8 (KTD7); the variant is no longer emitted.
    assert_eq!(strings[0].encoding, Encoding::Utf8);
    assert_eq!(strings[1].text, "Test");
    assert_eq!(strings[1].offset, 12);
    assert_eq!(strings[1].rva, Some(0x100C));
}

#[test]
fn test_basic_extractor_max_length_filtering() {
    let extractor = BasicExtractor::new();
    let config = ExtractionConfig::default().with_max_length(10);

    let section = SectionInfo::new(".data".to_string(), 0, 30, SectionType::WritableData, 0.5)
        .with_writable(true);

    let data = b"Short\0VeryLongStringHere";
    let strings = extractor
        .extract_from_section(data, &section, &config)
        .unwrap();

    // Only "Short" should pass max_length filter
    assert_eq!(strings.len(), 1);
    assert_eq!(strings[0].text, "Short");
}

#[test]
fn test_basic_extractor_section_bounds() {
    let extractor = BasicExtractor::new();
    let config = ExtractionConfig::default();

    let section = SectionInfo::new(
        ".text".to_string(),
        7,  // Start after "prefix\0"
        12, // "Hello World" is 11 bytes + null terminator
        SectionType::Code,
        0.1,
    )
    .with_rva(0x2000)
    .with_executable(true);

    let data = b"prefix\0Hello World\0suffix";
    let strings = extractor
        .extract_from_section(data, &section, &config)
        .unwrap();

    // Should find "Hello World" in the section
    assert!(!strings.is_empty());
    let hello_world = strings.iter().find(|s| s.text == "Hello World");
    assert!(hello_world.is_some(), "Should find 'Hello World' string");
    if let Some(s) = hello_world {
        assert_eq!(s.offset, 7);
        assert_eq!(s.rva, Some(0x2000));
    }
}

#[test]
fn test_basic_extractor_empty_section() {
    let extractor = BasicExtractor::new();
    let config = ExtractionConfig::default();

    let section = SectionInfo::new(".empty".to_string(), 0, 0, SectionType::Other, 0.0);

    let data = b"";
    let strings = extractor
        .extract_from_section(data, &section, &config)
        .unwrap();

    assert!(strings.is_empty());
}

#[test]
fn test_basic_extractor_section_out_of_bounds() {
    let extractor = BasicExtractor::new();
    let config = ExtractionConfig::default();

    let section = SectionInfo::new(".invalid".to_string(), 1000, 100, SectionType::Other, 0.0);

    let data = b"small data";
    let strings = extractor
        .extract_from_section(data, &section, &config)
        .unwrap();

    assert!(strings.is_empty());
}

#[test]
fn test_basic_extractor_utf8_encoding() {
    let extractor = BasicExtractor::new();
    let config = ExtractionConfig::default();

    let section = SectionInfo::new(".rodata".to_string(), 0, 20, SectionType::StringData, 1.0);

    let data = "Hello \u{4e16}\u{754c}".as_bytes();
    let strings = extractor
        .extract_from_section(data, &section, &config)
        .unwrap();

    // Should extract UTF-8 string with CJK characters
    // Note: ASCII extractor may also extract "Hello " as a prefix, but UTF-8 extractor
    // will extract the full string. We check for the UTF-8 string.
    let utf8_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.encoding == Encoding::Utf8 && s.text == "Hello \u{4e16}\u{754c}")
        .collect();
    assert_eq!(
        utf8_strings.len(),
        1,
        "Should find UTF-8 string with CJK chars, found {} strings total",
        strings.len()
    );
    assert_eq!(utf8_strings[0].text, "Hello \u{4e16}\u{754c}");
    assert_eq!(utf8_strings[0].encoding, Encoding::Utf8);
}

#[test]
fn test_basic_extractor_encoding_filtering() {
    let extractor = BasicExtractor::new();
    // Only allow ASCII, exclude UTF-8
    let config = ExtractionConfig::default().with_enabled_encodings(vec![Encoding::Ascii]);

    let section = SectionInfo::new(".rodata".to_string(), 0, 30, SectionType::StringData, 1.0);

    let data = "Hello\0\u{4e16}\u{754c}\0Test".as_bytes();
    let strings = extractor
        .extract_from_section(data, &section, &config)
        .unwrap();

    // Should only find narrow strings, not the wide UTF-8 content.
    // "Hello" and "Test" are ASCII (emitted as UTF-8 per KTD7); the multibyte
    // "\u{4e16}\u{754c}" is not scanned because only ASCII scanning is enabled.
    let ascii_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.encoding == Encoding::Utf8)
        .collect();
    assert_eq!(ascii_strings.len(), 2, "Should find 2 narrow strings");
    assert!(ascii_strings.iter().any(|s| s.text == "Hello"));
    assert!(ascii_strings.iter().any(|s| s.text == "Test"));
    // UTF-8 string "\u{4e16}\u{754c}" should be filtered out
    assert!(!strings.iter().any(|s| s.text.contains("\u{4e16}\u{754c}")));
}

#[test]
fn test_basic_extractor_ascii_disabled() {
    let extractor = BasicExtractor::new();
    // Exclude ASCII, only allow UTF-8
    let config = ExtractionConfig::default().with_enabled_encodings(vec![Encoding::Utf8]);

    let section = SectionInfo::new(".rodata".to_string(), 0, 30, SectionType::StringData, 1.0);

    let data = b"Hello\0World\0Test";
    let strings = extractor
        .extract_from_section(data, &section, &config)
        .unwrap();

    // Should not find ASCII strings when ASCII is disabled
    // Note: "Hello", "World", and "Test" are ASCII-only, so they should be extracted as UTF-8
    // but ASCII extractor should not run
    let ascii_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.encoding == Encoding::Ascii)
        .collect();
    assert_eq!(
        ascii_strings.len(),
        0,
        "Should not find any ASCII strings when ASCII is disabled"
    );

    // UTF-8 extractor may still find these strings since they're valid UTF-8
    let utf8_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.encoding == Encoding::Utf8)
        .collect();
    // UTF-8 extractor should find the strings
    assert!(!utf8_strings.is_empty(), "Should find UTF-8 strings");
}

#[test]
fn test_basic_extractor_include_symbols() {
    let extractor = BasicExtractor::new();
    let config = ExtractionConfig::default().with_include_symbols(true);

    let section =
        SectionInfo::new(".text".to_string(), 0, 10, SectionType::Code, 0.1).with_executable(true);

    let container_info = ContainerInfo::new(
        BinaryFormat::Elf,
        vec![section],
        vec![
            ImportInfo {
                name: "printf".to_string(),
                library: Some("libc.so.6".to_string()),
                address: Some(0x1000),
                ordinal: None,
            },
            ImportInfo {
                name: "malloc".to_string(),
                library: Some("libc.so.6".to_string()),
                address: Some(0x2000),
                ordinal: None,
            },
        ],
        vec![
            ExportInfo {
                name: "main".to_string(),
                address: 0x3000,
                ordinal: None,
            },
            ExportInfo {
                name: "exported_function".to_string(),
                address: 0x4000,
                ordinal: None,
            },
        ],
        None,
    );

    let data = b"test data";
    let strings = extractor.extract(data, &container_info, &config).unwrap();

    // Should include import and export names
    let import_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.source == StringSource::ImportName)
        .collect();
    let export_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.source == StringSource::ExportName)
        .collect();

    assert_eq!(import_strings.len(), 2);
    assert!(import_strings.iter().any(|s| s.text == "printf"));
    assert!(import_strings.iter().any(|s| s.text == "malloc"));

    assert_eq!(export_strings.len(), 2);
    assert!(export_strings.iter().any(|s| s.text == "main"));
    assert!(export_strings.iter().any(|s| s.text == "exported_function"));

    // Verify import string properties
    let printf_str = import_strings.iter().find(|s| s.text == "printf").unwrap();
    assert_eq!(printf_str.encoding, Encoding::Utf8);
    assert_eq!(printf_str.offset, 0);
    assert_eq!(printf_str.rva, None);
    assert_eq!(printf_str.section, None);
    assert_eq!(printf_str.length, 6);

    // Verify export string properties
    let main_str = export_strings.iter().find(|s| s.text == "main").unwrap();
    assert_eq!(main_str.encoding, Encoding::Utf8);
    assert_eq!(main_str.offset, 0);
    assert_eq!(main_str.rva, None);
    assert_eq!(main_str.section, None);
    assert_eq!(main_str.length, 4);
}

#[test]
fn test_basic_extractor_exclude_symbols() {
    let extractor = BasicExtractor::new();
    let config = ExtractionConfig::default().with_include_symbols(false);

    let section =
        SectionInfo::new(".text".to_string(), 0, 10, SectionType::Code, 0.1).with_executable(true);

    let container_info = ContainerInfo::new(
        BinaryFormat::Elf,
        vec![section],
        vec![ImportInfo {
            name: "printf".to_string(),
            library: Some("libc.so.6".to_string()),
            address: Some(0x1000),
            ordinal: None,
        }],
        vec![ExportInfo {
            name: "main".to_string(),
            address: 0x3000,
            ordinal: None,
        }],
        None,
    );

    let data = b"test data";
    let strings = extractor.extract(data, &container_info, &config).unwrap();

    // Should not include import/export names
    assert!(!strings.iter().any(|s| s.source == StringSource::ImportName));
    assert!(!strings.iter().any(|s| s.source == StringSource::ExportName));
}

#[test]
fn test_basic_extractor_section_filtering() {
    let extractor = BasicExtractor::new();
    let config = ExtractionConfig::default()
        .with_scan_code_sections(false)
        .with_include_debug(false);

    let code_section =
        SectionInfo::new(".text".to_string(), 0, 9, SectionType::Code, 0.1).with_executable(true);

    let debug_section = SectionInfo::new(".debug_info".to_string(), 9, 10, SectionType::Debug, 0.0);

    let data_section =
        SectionInfo::new(".rodata".to_string(), 19, 11, SectionType::StringData, 1.0);

    let data = b"CodeData\0DebugData\0RoDataTest";
    let container_info = ContainerInfo::new(
        BinaryFormat::Elf,
        vec![code_section, debug_section, data_section],
        vec![],
        vec![],
        None,
    );

    let strings = extractor.extract(data, &container_info, &config).unwrap();

    // Should only extract from data section, not code or debug
    assert_eq!(strings.len(), 1);
    assert_eq!(strings[0].text, "RoDataTest");
}
