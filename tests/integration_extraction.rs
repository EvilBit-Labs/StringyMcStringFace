use std::fs;
use stringy::container::{ContainerParser, ElfParser, PeParser};
use stringy::extraction::{BasicExtractor, ExtractionConfig, StringExtractor};
use stringy::types::{Encoding, SectionType, StringSource};

fn get_fixture_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

#[test]
fn test_basic_extractor_ascii_strings() {
    let extractor = BasicExtractor::new();
    let config = ExtractionConfig::default();

    // Create test data with embedded ASCII strings
    let data = b"prefix\0Hello\0World\0Test123\0suffix";
    let section = stringy::types::SectionInfo {
        name: ".rodata".to_string(),
        offset: 7, // Start after "prefix\0"
        size: 20,
        rva: Some(0x1000),
        section_type: SectionType::StringData,
        is_executable: false,
        is_writable: false,
        weight: 1.0,
    };

    let strings = extractor
        .extract_from_section(data, &section, &config)
        .unwrap();

    assert_eq!(strings.len(), 3);
    assert_eq!(strings[0].text, "Hello");
    assert_eq!(strings[0].encoding, Encoding::Ascii);
    assert_eq!(strings[0].source, StringSource::SectionData);
    assert_eq!(strings[1].text, "World");
    assert_eq!(strings[2].text, "Test123");
}

#[test]
fn test_basic_extractor_utf8_strings() {
    let extractor = BasicExtractor::new();
    let config = ExtractionConfig::default();

    // Create test data with UTF-8 strings
    let data = "prefix\0Hello 世界\0Test 测试\0suffix".as_bytes();
    let section = stringy::types::SectionInfo {
        name: ".rodata".to_string(),
        offset: 7,
        size: 30,
        rva: Some(0x1000),
        section_type: SectionType::StringData,
        is_executable: false,
        is_writable: false,
        weight: 1.0,
    };

    let strings = extractor
        .extract_from_section(data, &section, &config)
        .unwrap();

    // Should extract UTF-8 strings "Hello 世界" and "Test 测试"
    // Note: ASCII extractor may also extract ASCII prefixes, but UTF-8 extractor
    // will extract the full UTF-8 strings. We check for the UTF-8 strings.
    let utf8_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.encoding == Encoding::Utf8)
        .collect();
    assert!(
        utf8_strings.len() >= 2,
        "Should find at least 2 UTF-8 strings, found {} UTF-8 strings ({} total)",
        utf8_strings.len(),
        strings.len()
    );
    assert!(utf8_strings.iter().any(|s| s.text == "Hello 世界"));
    assert!(utf8_strings.iter().any(|s| s.text == "Test 测试"));
}

#[test]
fn test_basic_extractor_min_length_filtering() {
    let extractor = BasicExtractor::new();
    let config = ExtractionConfig {
        min_length: 4,
        ..Default::default()
    };

    let data = b"Hi\0Test\0AB\0LongString\0OK";
    let section = stringy::types::SectionInfo {
        name: ".data".to_string(),
        offset: 0,
        size: data.len() as u64,
        rva: None,
        section_type: SectionType::WritableData,
        is_executable: false,
        is_writable: true,
        weight: 0.5,
    };

    let strings = extractor
        .extract_from_section(data, &section, &config)
        .unwrap();

    // Should only find strings >= 4 characters
    assert!(strings.iter().all(|s| s.text.len() >= 4));
    assert!(strings.iter().any(|s| s.text == "Test"));
    assert!(strings.iter().any(|s| s.text == "LongString"));
    // "Hi" and "AB" should be filtered out
    assert!(!strings.iter().any(|s| s.text == "Hi"));
    assert!(!strings.iter().any(|s| s.text == "AB"));
}

#[test]
fn test_basic_extractor_max_length_filtering() {
    let extractor = BasicExtractor::new();
    let config = ExtractionConfig::default(); // max_length = 4096 by default

    // Create a very long string
    let long_string = "A".repeat(5000);
    let data = format!("Short\0{}\0EndTest", long_string).into_bytes();
    let section = stringy::types::SectionInfo {
        name: ".data".to_string(),
        offset: 0,
        size: data.len() as u64,
        rva: None,
        section_type: SectionType::WritableData,
        is_executable: false,
        is_writable: true,
        weight: 0.5,
    };

    let strings = extractor
        .extract_from_section(&data, &section, &config)
        .unwrap();

    // The long string should be filtered out by max_length
    assert!(strings.iter().any(|s| s.text == "Short"));
    assert!(strings.iter().any(|s| s.text == "EndTest"));
    // The 5000-character string should not be present
    assert!(!strings.iter().any(|s| s.text.len() > 4096));
}

#[test]
fn test_basic_extractor_with_elf_fixture() {
    let fixture_path = get_fixture_path("test_binary_elf");
    let elf_data = fs::read(&fixture_path)
        .expect("Failed to read ELF fixture. Run the build script to generate fixtures.");

    // Parse with ElfParser to get ContainerInfo
    let parser = ElfParser::new();
    let container_info = parser.parse(&elf_data).expect("Failed to parse ELF");

    // Use BasicExtractor with config that excludes symbols to focus on section data
    let extractor = BasicExtractor::new();
    let config = ExtractionConfig {
        include_symbols: false,
        ..Default::default()
    };
    let strings = extractor
        .extract(&elf_data, &container_info, &config)
        .expect("Failed to extract strings");

    // Verify strings are found
    assert!(
        !strings.is_empty(),
        "Should find some strings in ELF binary"
    );

    // Verify strings are from appropriate sections
    for string in &strings {
        assert_eq!(string.source, StringSource::SectionData);
        assert!(string.section.is_some());
        assert!(string.length > 0);

        // Verify encoding is ASCII or UTF-8
        assert!(
            matches!(string.encoding, Encoding::Ascii | Encoding::Utf8),
            "Encoding should be ASCII or UTF-8"
        );

        // Verify RVA is calculated if section has RVA
        if let Some(section_name) = &string.section
            && let Some(section) = container_info
                .sections
                .iter()
                .find(|s| s.name == *section_name)
            && section.rva.is_some()
        {
            assert!(
                string.rva.is_some(),
                "RVA should be calculated if section has RVA"
            );
        }
    }

    // Check that we found strings in common string sections
    let section_names: Vec<&str> = strings
        .iter()
        .filter_map(|s| s.section.as_deref())
        .collect();
    println!("Found strings in sections: {:?}", section_names);
}

#[test]
fn test_basic_extractor_with_pe_fixture() {
    let fixture_path = get_fixture_path("test_binary_pe.exe");
    let pe_data = fs::read(&fixture_path)
        .expect("Failed to read PE fixture. Run the build script to generate fixtures.");

    // Parse with PeParser to get ContainerInfo
    let parser = PeParser::new();
    let container_info = parser.parse(&pe_data).expect("Failed to parse PE");

    // Extract strings using BasicExtractor with config that excludes symbols
    let extractor = BasicExtractor::new();
    let config = ExtractionConfig {
        include_symbols: false,
        ..Default::default()
    };
    let strings = extractor
        .extract(&pe_data, &container_info, &config)
        .expect("Failed to extract strings");

    // Verify strings are found
    assert!(!strings.is_empty(), "Should find some strings in PE binary");

    // Verify all FoundString fields are properly populated
    for string in &strings {
        assert!(!string.text.is_empty());
        assert_eq!(string.source, StringSource::SectionData);
        assert!(string.section.is_some());
        assert!(string.length > 0);
        assert!(matches!(string.encoding, Encoding::Ascii | Encoding::Utf8));

        // Verify offset is within data bounds
        assert!(
            string.offset < pe_data.len() as u64,
            "Offset should be within data bounds"
        );
    }

    // Check for strings in common PE sections
    let has_rdata = strings.iter().any(|s| {
        s.section
            .as_ref()
            .map(|name| name.contains(".rdata") || name.contains(".data"))
            .unwrap_or(false)
    });
    println!("Found strings in .rdata/.data sections: {}", has_rdata);
}

#[test]
fn test_basic_extractor_section_filtering() {
    let fixture_path = get_fixture_path("test_binary_elf");
    let elf_data = fs::read(&fixture_path)
        .expect("Failed to read ELF fixture. Run the build script to generate fixtures.");

    let parser = ElfParser::new();
    let container_info = parser.parse(&elf_data).expect("Failed to parse ELF");

    // Create config that excludes code and debug sections
    let config = ExtractionConfig {
        scan_code_sections: false,
        include_debug: false,
        ..Default::default()
    };

    let extractor = BasicExtractor::new();
    let strings = extractor
        .extract(&elf_data, &container_info, &config)
        .expect("Failed to extract strings");

    // Verify no strings from code or debug sections
    for string in &strings {
        if let Some(section_name) = &string.section
            && let Some(section) = container_info
                .sections
                .iter()
                .find(|s| s.name == *section_name)
        {
            assert_ne!(
                section.section_type,
                SectionType::Code,
                "Should not extract from code sections"
            );
            assert_ne!(
                section.section_type,
                SectionType::Debug,
                "Should not extract from debug sections"
            );
        }
    }
}

#[test]
fn test_basic_extractor_empty_data() {
    let extractor = BasicExtractor::new();
    let config = ExtractionConfig::default();

    let section = stringy::types::SectionInfo {
        name: ".empty".to_string(),
        offset: 0,
        size: 0,
        rva: None,
        section_type: SectionType::Other,
        is_executable: false,
        is_writable: false,
        weight: 0.0,
    };

    let data = b"";
    let strings = extractor
        .extract_from_section(data, &section, &config)
        .unwrap();

    // Should return empty result, not panic
    assert!(strings.is_empty());
}

#[test]
fn test_basic_extractor_boundary_conditions() {
    let extractor = BasicExtractor::new();
    let config = ExtractionConfig::default();

    // Test string at start of section
    let data1 = b"Start\0middle\0end";
    let section1 = stringy::types::SectionInfo {
        name: ".test1".to_string(),
        offset: 0,
        size: data1.len() as u64,
        rva: Some(0x1000),
        section_type: SectionType::StringData,
        is_executable: false,
        is_writable: false,
        weight: 1.0,
    };
    let strings1 = extractor
        .extract_from_section(data1, &section1, &config)
        .unwrap();
    assert!(strings1.iter().any(|s| s.text == "Start" && s.offset == 0));

    // Test string at end of section
    let data2 = b"prefix\0middle\0EndTest";
    let section2 = stringy::types::SectionInfo {
        name: ".test2".to_string(),
        offset: 0,
        size: data2.len() as u64,
        rva: Some(0x2000),
        section_type: SectionType::StringData,
        is_executable: false,
        is_writable: false,
        weight: 1.0,
    };
    let strings2 = extractor
        .extract_from_section(data2, &section2, &config)
        .unwrap();
    assert!(strings2.iter().any(|s| s.text == "EndTest"));

    // Test string spanning entire section
    let data3 = b"FullSectionString";
    let section3 = stringy::types::SectionInfo {
        name: ".test3".to_string(),
        offset: 0,
        size: data3.len() as u64,
        rva: Some(0x3000),
        section_type: SectionType::StringData,
        is_executable: false,
        is_writable: false,
        weight: 1.0,
    };
    let strings3 = extractor
        .extract_from_section(data3, &section3, &config)
        .unwrap();
    assert_eq!(strings3.len(), 1);
    assert_eq!(strings3[0].text, "FullSectionString");
    assert_eq!(strings3[0].offset, 0);
    assert_eq!(strings3[0].rva, Some(0x3000));
}

#[test]
fn test_extraction_config_defaults() {
    let config = ExtractionConfig::default();

    // Verify all default values match specification
    assert_eq!(config.min_length, 4);
    assert_eq!(config.max_length, 4096);
    assert_eq!(config.encodings.len(), 2);
    assert!(config.encodings.contains(&Encoding::Ascii));
    assert!(config.encodings.contains(&Encoding::Utf8));
    assert!(config.scan_code_sections);
    assert!(!config.include_debug);
    assert_eq!(config.section_priority.len(), 3);
    assert!(config.section_priority.contains(&SectionType::StringData));
    assert!(config.section_priority.contains(&SectionType::ReadOnlyData));
    assert!(config.section_priority.contains(&SectionType::Resources));
    assert!(config.include_symbols);
}

#[test]
fn test_basic_extractor_encoding_filtering() {
    let extractor = BasicExtractor::new();
    // Only allow ASCII, exclude UTF-8
    let config = ExtractionConfig {
        encodings: vec![Encoding::Ascii],
        enabled_encodings: vec![Encoding::Ascii],
        ..Default::default()
    };

    let section = stringy::types::SectionInfo {
        name: ".rodata".to_string(),
        offset: 0,
        size: 30,
        rva: None,
        section_type: SectionType::StringData,
        is_executable: false,
        is_writable: false,
        weight: 1.0,
    };

    let data = "Hello\0世界\0Test".as_bytes();
    let strings = extractor
        .extract_from_section(data, &section, &config)
        .unwrap();

    // Should only find ASCII strings, not UTF-8
    assert_eq!(strings.len(), 2);
    assert_eq!(strings[0].text, "Hello");
    assert_eq!(strings[0].encoding, Encoding::Ascii);
    assert_eq!(strings[1].text, "Test");
    assert_eq!(strings[1].encoding, Encoding::Ascii);
    // UTF-8 string "世界" should be filtered out
    assert!(!strings.iter().any(|s| s.text.contains("世界")));
}

#[test]
fn test_basic_extractor_include_symbols() {
    let fixture_path = get_fixture_path("test_binary_elf");
    let elf_data = fs::read(&fixture_path)
        .expect("Failed to read ELF fixture. Run the build script to generate fixtures.");

    let parser = ElfParser::new();
    let container_info = parser.parse(&elf_data).expect("Failed to parse ELF");

    // Extract with symbols included
    let extractor = BasicExtractor::new();
    let config = ExtractionConfig {
        include_symbols: true,
        ..Default::default()
    };
    let strings = extractor
        .extract(&elf_data, &container_info, &config)
        .expect("Failed to extract strings");

    // Should include import and export names
    let import_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.source == StringSource::ImportName)
        .collect();
    let export_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.source == StringSource::ExportName)
        .collect();

    // Verify we found some imports/exports
    assert!(!import_strings.is_empty() || !export_strings.is_empty());

    // Verify import string properties
    for import_str in &import_strings {
        assert_eq!(import_str.encoding, Encoding::Utf8);
        assert_eq!(import_str.offset, 0);
        assert_eq!(import_str.rva, None);
        assert_eq!(import_str.section, None);
        assert!(import_str.length > 0);
    }

    // Verify export string properties
    for export_str in &export_strings {
        assert_eq!(export_str.encoding, Encoding::Utf8);
        assert_eq!(export_str.offset, 0);
        assert_eq!(export_str.rva, None);
        assert_eq!(export_str.section, None);
        assert!(export_str.length > 0);
    }
}

#[test]
fn test_basic_extractor_exclude_symbols() {
    let fixture_path = get_fixture_path("test_binary_elf");
    let elf_data = fs::read(&fixture_path)
        .expect("Failed to read ELF fixture. Run the build script to generate fixtures.");

    let parser = ElfParser::new();
    let container_info = parser.parse(&elf_data).expect("Failed to parse ELF");

    // Extract with symbols excluded
    let extractor = BasicExtractor::new();
    let config = ExtractionConfig {
        include_symbols: false,
        ..Default::default()
    };
    let strings = extractor
        .extract(&elf_data, &container_info, &config)
        .expect("Failed to extract strings");

    // Should not include import/export names
    assert!(!strings.iter().any(|s| s.source == StringSource::ImportName));
    assert!(!strings.iter().any(|s| s.source == StringSource::ExportName));
}

#[test]
fn test_utf16le_extraction_with_basic_extractor() {
    // Create mock binary with UTF-16LE strings in a .rdata section
    let mut data = vec![0x00; 100]; // Padding
    let hello = vec![
        0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00, 0x00, 0x00,
    ]; // "Hello\0"
    let world = vec![
        0x57, 0x00, 0x6F, 0x00, 0x72, 0x00, 0x6C, 0x00, 0x64, 0x00, 0x00, 0x00,
    ]; // "World\0"
    data.extend_from_slice(&hello);
    data.extend_from_slice(&world);

    let section = stringy::types::SectionInfo {
        name: ".rdata".to_string(),
        offset: 100,
        size: (hello.len() + world.len()) as u64,
        rva: Some(0x1000),
        section_type: SectionType::StringData,
        is_executable: false,
        is_writable: false,
        weight: 1.0,
    };

    let container_info = stringy::ContainerInfo::new(
        stringy::BinaryFormat::Pe,
        vec![section],
        vec![],
        vec![],
        None,
    );

    let extractor = BasicExtractor::new();
    let mut config = ExtractionConfig::default();
    config.enabled_encodings.push(Encoding::Utf16Le);

    let strings = extractor
        .extract(&data, &container_info, &config)
        .expect("Failed to extract strings");

    // Should find UTF-16LE strings
    let utf16le_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.encoding == Encoding::Utf16Le)
        .collect();
    assert!(!utf16le_strings.is_empty(), "Should find UTF-16LE strings");
    assert!(utf16le_strings.iter().any(|s| s.text == "Hello"));
    assert!(utf16le_strings.iter().any(|s| s.text == "World"));

    // Verify metadata
    for string in &utf16le_strings {
        assert_eq!(string.source, StringSource::SectionData);
        assert_eq!(string.section, Some(".rdata".to_string()));
        assert!(string.confidence >= config.utf16_min_confidence);
    }
}

#[test]
fn test_utf16le_encoding_filtering() {
    // Test that UTF-16LE strings are only extracted when Encoding::Utf16Le is enabled
    let mut data = vec![0x00; 50];
    let hello = vec![
        0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00, 0x00, 0x00,
    ];
    data.extend_from_slice(&hello);

    let section = stringy::types::SectionInfo {
        name: ".rdata".to_string(),
        offset: 50,
        size: hello.len() as u64,
        rva: Some(0x1000),
        section_type: SectionType::StringData,
        is_executable: false,
        is_writable: false,
        weight: 1.0,
    };

    let container_info = stringy::ContainerInfo::new(
        stringy::BinaryFormat::Pe,
        vec![section],
        vec![],
        vec![],
        None,
    );

    let extractor = BasicExtractor::new();

    // Test with UTF-16LE disabled
    let config_disabled = ExtractionConfig {
        enabled_encodings: vec![Encoding::Ascii, Encoding::Utf8],
        ..Default::default()
    };
    let strings_disabled = extractor
        .extract(&data, &container_info, &config_disabled)
        .expect("Failed to extract strings");
    let utf16le_disabled: Vec<_> = strings_disabled
        .iter()
        .filter(|s| s.encoding == Encoding::Utf16Le)
        .collect();
    assert!(
        utf16le_disabled.is_empty(),
        "Should not extract UTF-16LE when disabled"
    );

    // Test with UTF-16LE enabled
    let mut config_enabled = ExtractionConfig::default();
    config_enabled.enabled_encodings.push(Encoding::Utf16Le);
    let strings_enabled = extractor
        .extract(&data, &container_info, &config_enabled)
        .expect("Failed to extract strings");
    let utf16le_enabled: Vec<_> = strings_enabled
        .iter()
        .filter(|s| s.encoding == Encoding::Utf16Le)
        .collect();
    assert!(
        !utf16le_enabled.is_empty(),
        "Should extract UTF-16LE when enabled"
    );
}

#[test]
fn test_utf16le_with_noise_filtering() {
    // Create test data with both high-quality and noisy UTF-16LE strings
    let mut data = vec![0x00; 50];
    let hello = vec![
        0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00, 0x00, 0x00,
    ];
    data.extend_from_slice(&hello);
    // Add noisy string (repeated characters)
    let noisy = vec![
        0x41, 0x00, 0x41, 0x00, 0x41, 0x00, 0x41, 0x00, 0x41, 0x00, 0x00, 0x00,
    ]; // "AAAAA\0"
    data.extend_from_slice(&noisy);

    let section = stringy::types::SectionInfo {
        name: ".rdata".to_string(),
        offset: 50,
        size: (hello.len() + noisy.len()) as u64,
        rva: Some(0x1000),
        section_type: SectionType::StringData,
        is_executable: false,
        is_writable: false,
        weight: 1.0,
    };

    let container_info = stringy::ContainerInfo::new(
        stringy::BinaryFormat::Pe,
        vec![section],
        vec![],
        vec![],
        None,
    );

    let extractor = BasicExtractor::new();
    let mut config = ExtractionConfig::default();
    config.enabled_encodings.push(Encoding::Utf16Le);
    config.noise_filtering_enabled = true;
    config.min_confidence_threshold = 0.6;

    let strings = extractor
        .extract(&data, &container_info, &config)
        .expect("Failed to extract strings");

    // Should extract strings, but noisy ones may be filtered out
    let utf16le_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.encoding == Encoding::Utf16Le)
        .collect();
    assert!(!utf16le_strings.is_empty());
    // High-quality string should be present
    assert!(utf16le_strings.iter().any(|s| s.text == "Hello"));
    // All extracted strings should meet confidence threshold
    for string in &utf16le_strings {
        assert!(string.confidence >= config.min_confidence_threshold);
    }
}

#[test]
fn test_utf16le_min_wide_length_config() {
    // Test that min_wide_length configuration is respected
    let mut data = vec![0x00; 50];
    let hi = vec![0x48, 0x00, 0x69, 0x00, 0x00, 0x00]; // "Hi\0" (2 chars)
    let test = vec![0x54, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00, 0x00, 0x00]; // "Test\0" (4 chars)
    data.extend_from_slice(&hi);
    data.extend_from_slice(&test);

    let section = stringy::types::SectionInfo {
        name: ".rdata".to_string(),
        offset: 50,
        size: (hi.len() + test.len()) as u64,
        rva: Some(0x1000),
        section_type: SectionType::StringData,
        is_executable: false,
        is_writable: false,
        weight: 1.0,
    };

    let container_info = stringy::ContainerInfo::new(
        stringy::BinaryFormat::Pe,
        vec![section],
        vec![],
        vec![],
        None,
    );

    let extractor = BasicExtractor::new();
    let mut config = ExtractionConfig::default();
    config.enabled_encodings.push(Encoding::Utf16Le);
    config.min_wide_length = 3; // Minimum 3 characters

    let strings = extractor
        .extract(&data, &container_info, &config)
        .expect("Failed to extract strings");

    let utf16le_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.encoding == Encoding::Utf16Le)
        .collect();
    // "Hi" (2 chars) should be filtered out, "Test" (4 chars) should be extracted
    assert_eq!(utf16le_strings.len(), 1);
    assert_eq!(utf16le_strings[0].text, "Test");
}

#[test]
fn test_utf16le_confidence_threshold() {
    // Test various utf16_min_confidence threshold values
    let mut data = vec![0x00; 50];
    let hello = vec![
        0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00, 0x00, 0x00,
    ];
    data.extend_from_slice(&hello);

    let section = stringy::types::SectionInfo {
        name: ".rdata".to_string(),
        offset: 50,
        size: hello.len() as u64,
        rva: Some(0x1000),
        section_type: SectionType::StringData,
        is_executable: false,
        is_writable: false,
        weight: 1.0,
    };

    let container_info = stringy::ContainerInfo::new(
        stringy::BinaryFormat::Pe,
        vec![section],
        vec![],
        vec![],
        None,
    );

    let extractor = BasicExtractor::new();

    // Low threshold should include more strings
    let mut config_low = ExtractionConfig::default();
    config_low.enabled_encodings.push(Encoding::Utf16Le);
    config_low.utf16_min_confidence = 0.5;
    let strings_low = extractor
        .extract(&data, &container_info, &config_low)
        .expect("Failed to extract strings");

    // High threshold may filter more strings
    let mut config_high = ExtractionConfig::default();
    config_high.enabled_encodings.push(Encoding::Utf16Le);
    config_high.utf16_min_confidence = 0.95;
    let strings_high = extractor
        .extract(&data, &container_info, &config_high)
        .expect("Failed to extract strings");

    let utf16le_low: Vec<_> = strings_low
        .iter()
        .filter(|s| s.encoding == Encoding::Utf16Le)
        .collect();
    let utf16le_high: Vec<_> = strings_high
        .iter()
        .filter(|s| s.encoding == Encoding::Utf16Le)
        .collect();

    assert!(utf16le_low.len() >= utf16le_high.len());
    // All extracted strings should meet their respective thresholds
    for string in &utf16le_high {
        assert!(string.confidence >= config_high.utf16_min_confidence);
    }
}
