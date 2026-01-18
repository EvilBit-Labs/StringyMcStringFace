//! Integration tests for string deduplication

use stringy::container::{create_parser, detect_format};
use stringy::extraction::{BasicExtractor, ExtractionConfig, StringExtractor, deduplicate};
use stringy::types::{BinaryFormat, Encoding, SectionInfo, SectionType, StringSource};

fn get_fixture_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

#[test]
fn test_deduplication_with_basic_extractor() {
    let extractor = BasicExtractor::new();
    let config = ExtractionConfig::default();

    // Create test data with duplicate strings in multiple sections
    let data = b"Hello\0World\0Hello\0Test\0World\0Hello\0";
    let section1 = SectionInfo {
        name: ".rodata".to_string(),
        offset: 0,
        size: 12, // "Hello\0World\0"
        rva: Some(0x1000),
        section_type: SectionType::StringData,
        is_executable: false,
        is_writable: false,
        weight: 1.0,
    };
    let section2 = SectionInfo {
        name: ".data".to_string(),
        offset: 12,
        size: 10, // "Hello\0Test\0"
        rva: Some(0x2000),
        section_type: SectionType::ReadOnlyData,
        is_executable: false,
        is_writable: false,
        weight: 0.7,
    };
    let section3 = SectionInfo {
        name: ".text".to_string(),
        offset: 22,
        size: 6, // "World\0"
        rva: Some(0x3000),
        section_type: SectionType::Code,
        is_executable: true,
        is_writable: false,
        weight: 0.1,
    };

    let container_info = stringy::types::ContainerInfo::new(
        BinaryFormat::Elf,
        vec![section1, section2, section3],
        vec![],
        vec![],
        None,
    );

    // Disable deduplication in extractor to test manual deduplication
    let config_no_dedup = ExtractionConfig {
        enable_deduplication: false,
        ..config.clone()
    };

    let strings = extractor
        .extract(data, &container_info, &config_no_dedup)
        .unwrap();

    // Verify we have duplicates before deduplication
    assert!(strings.len() >= 3);
    let hello_count = strings.iter().filter(|s| s.text == "Hello").count();
    assert!(hello_count >= 2, "Should have at least 2 'Hello' strings");

    // Apply deduplication
    let canonical = deduplicate(strings, None, true);

    // Verify deduplication reduced count
    assert!(
        canonical.len() < 6,
        "Deduplication should reduce string count"
    );

    // Find "Hello" canonical string
    let hello_canonical = canonical.iter().find(|c| c.text == "Hello");
    assert!(
        hello_canonical.is_some(),
        "Should find 'Hello' in canonical strings"
    );

    if let Some(hello) = hello_canonical {
        // Verify it has multiple occurrences
        assert!(
            hello.occurrences.len() >= 2,
            "Hello should appear multiple times"
        );

        // Verify metadata preservation
        let offsets: Vec<u64> = hello.occurrences.iter().map(|o| o.offset).collect();
        assert!(offsets.contains(&0), "Should preserve offset 0");

        // Verify cross-section bonus (if applicable)
        let sections: Vec<Option<String>> = hello
            .occurrences
            .iter()
            .map(|o| o.section.clone())
            .collect();
        let unique_sections: std::collections::HashSet<_> = sections.into_iter().collect();
        if unique_sections.len() > 1 {
            // Cross-section bonus should be applied
            assert!(
                hello.combined_score >= 10,
                "Should have cross-section bonus"
            );
        }
    }
}

#[test]
fn test_deduplication_metadata_preservation() {
    let extractor = BasicExtractor::new();
    let config = ExtractionConfig::default();

    // Create test data with same string in different sections
    let data = b"TestString\0TestString\0";
    let section1 = SectionInfo {
        name: ".rodata".to_string(),
        offset: 0,
        size: 11,
        rva: Some(0x1000),
        section_type: SectionType::StringData,
        is_executable: false,
        is_writable: false,
        weight: 1.0,
    };
    let section2 = SectionInfo {
        name: ".data".to_string(),
        offset: 11,
        size: 11,
        rva: Some(0x2000),
        section_type: SectionType::ReadOnlyData,
        is_executable: false,
        is_writable: false,
        weight: 0.7,
    };

    let container_info = stringy::types::ContainerInfo::new(
        BinaryFormat::Elf,
        vec![section1, section2],
        vec![],
        vec![],
        None,
    );

    // Disable deduplication in extractor to test manual deduplication
    let config_no_dedup = ExtractionConfig {
        enable_deduplication: false,
        ..config.clone()
    };

    let strings = extractor
        .extract(data, &container_info, &config_no_dedup)
        .unwrap();
    let canonical = deduplicate(strings, None, true);

    // Find "TestString"
    let test_string = canonical.iter().find(|c| c.text == "TestString");
    assert!(test_string.is_some());

    if let Some(ts) = test_string {
        assert_eq!(ts.occurrences.len(), 2);

        // Verify all offsets are preserved
        let offsets: Vec<u64> = ts.occurrences.iter().map(|o| o.offset).collect();
        assert!(offsets.contains(&0));
        assert!(offsets.contains(&11));

        // Verify sections are preserved
        let sections: Vec<Option<String>> =
            ts.occurrences.iter().map(|o| o.section.clone()).collect();
        assert!(sections.contains(&Some(".rodata".to_string())));
        assert!(sections.contains(&Some(".data".to_string())));
    }
}

#[test]
fn test_deduplication_with_real_fixture() {
    // Try to use a real fixture if available
    let fixture_path = get_fixture_path("test_elf");
    if !fixture_path.exists() {
        // Skip if fixture doesn't exist
        return;
    }

    let data = std::fs::read(&fixture_path).unwrap();
    let format = detect_format(&data);
    if format == BinaryFormat::Unknown {
        // Skip if format not supported
        return;
    }

    let parser = create_parser(format).unwrap();
    let container_info = parser.parse(&data).unwrap();

    let extractor = BasicExtractor::new();

    // Test with deduplication disabled to get baseline count
    let config_no_dedup = ExtractionConfig {
        enable_deduplication: false,
        ..Default::default()
    };
    let strings_no_dedup = extractor
        .extract(&data, &container_info, &config_no_dedup)
        .unwrap();
    let strings_len = strings_no_dedup.len();

    // Test with deduplication enabled
    let config = ExtractionConfig::default();
    let strings = extractor.extract(&data, &container_info, &config).unwrap();

    // For comparison, also test manual deduplication
    let canonical = deduplicate(strings_no_dedup, None, true);

    // Verify deduplication worked (both integrated and manual)
    assert!(
        strings.len() <= strings_len,
        "Integrated deduplication should reduce count"
    );
    assert!(
        canonical.len() <= strings_len,
        "Manual deduplication should reduce count"
    );

    // Verify no data loss - all original strings should be represented
    let mut original_texts: Vec<(String, Encoding)> = strings
        .iter()
        .map(|s| (s.text.clone(), s.encoding))
        .collect();
    original_texts.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| format!("{:?}", a.1).cmp(&format!("{:?}", b.1)))
    });
    original_texts.dedup();

    let mut canonical_texts: Vec<(String, Encoding)> = canonical
        .iter()
        .map(|c| (c.text.clone(), c.encoding))
        .collect();
    canonical_texts.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| format!("{:?}", a.1).cmp(&format!("{:?}", b.1)))
    });

    assert_eq!(
        original_texts.len(),
        canonical_texts.len(),
        "All unique (text, encoding) pairs should be preserved"
    );
    for (orig, canon) in original_texts.iter().zip(canonical_texts.iter()) {
        assert_eq!(orig.0, canon.0);
        assert_eq!(format!("{:?}", orig.1), format!("{:?}", canon.1));
    }

    // Verify sorting by score
    for i in 1..canonical.len() {
        assert!(
            canonical[i - 1].combined_score >= canonical[i].combined_score,
            "Canonical strings should be sorted by combined_score descending"
        );
    }
}

#[test]
fn test_deduplication_score_bonuses() {
    use stringy::types::FoundString;

    // Create strings with different sources to test multi-source bonus
    let strings = vec![
        FoundString {
            text: "TestString".to_string(),
            original_text: None,
            encoding: Encoding::Utf8,
            offset: 0x100,
            rva: Some(0x1000),
            section: Some(".rodata".to_string()),
            length: 10,
            tags: vec![],
            score: 10,
            section_weight: None,
            semantic_boost: None,
            noise_penalty: None,
            source: StringSource::SectionData,
            confidence: 0.8,
        },
        FoundString {
            text: "TestString".to_string(),
            original_text: None,
            encoding: Encoding::Utf8,
            offset: 0x200,
            rva: Some(0x2000),
            section: Some(".data".to_string()),
            length: 10,
            tags: vec![],
            score: 15,
            section_weight: None,
            semantic_boost: None,
            noise_penalty: None,
            source: StringSource::ImportName,
            confidence: 0.9,
        },
    ];

    let canonical = deduplicate(strings, None, true);
    assert_eq!(canonical.len(), 1);

    let cs = &canonical[0];
    // Base: 15 (max), Occurrence: 5, Cross-section: 10, Multi-source: 15, Confidence: 9
    let expected_score = 15 + 5 + 10 + 15 + 9;
    assert_eq!(cs.combined_score, expected_score);
}

#[test]
fn test_extract_canonical_preserves_occurrences() {
    use stringy::extraction::{BasicExtractor, ExtractionConfig, StringExtractor};

    let extractor = BasicExtractor::new();
    let config = ExtractionConfig::default(); // enable_deduplication is true by default

    // Create test data with duplicate strings in multiple sections
    let data = b"Hello\0World\0Hello\0Test\0";
    let section1 = SectionInfo {
        name: ".rodata".to_string(),
        offset: 0,
        size: 12, // "Hello\0World\0"
        rva: Some(0x1000),
        section_type: SectionType::StringData,
        is_executable: false,
        is_writable: false,
        weight: 1.0,
    };
    let section2 = SectionInfo {
        name: ".data".to_string(),
        offset: 12,
        size: 10, // "Hello\0Test\0"
        rva: Some(0x2000),
        section_type: SectionType::ReadOnlyData,
        is_executable: false,
        is_writable: false,
        weight: 0.7,
    };

    let container_info = stringy::types::ContainerInfo::new(
        BinaryFormat::Elf,
        vec![section1, section2],
        vec![],
        vec![],
        None,
    );

    // Test extract_canonical() - should preserve all occurrences
    let canonical = extractor
        .extract_canonical(data, &container_info, &config)
        .unwrap();

    // Find "Hello" - should have multiple occurrences
    let hello = canonical.iter().find(|c| c.text == "Hello");
    assert!(hello.is_some(), "Should find 'Hello' in canonical strings");
    if let Some(h) = hello {
        assert!(
            h.occurrences.len() >= 2,
            "Hello should have multiple occurrences, got {}",
            h.occurrences.len()
        );
        // Verify we can see all offsets
        let offsets: Vec<u64> = h.occurrences.iter().map(|o| o.offset).collect();
        assert!(offsets.len() >= 2, "Should preserve multiple offsets");
    }

    // Compare with extract() - should lose occurrence information
    let strings = extractor.extract(data, &container_info, &config).unwrap();
    let hello_strings: Vec<_> = strings.iter().filter(|s| s.text == "Hello").collect();
    // With deduplication enabled, extract() should return only one "Hello"
    assert_eq!(
        hello_strings.len(),
        1,
        "extract() should deduplicate and return only one 'Hello'"
    );
    // But extract_canonical() should preserve all occurrences
    assert!(
        canonical
            .iter()
            .find(|c| c.text == "Hello")
            .unwrap()
            .occurrences
            .len()
            >= 2,
        "extract_canonical() should preserve all occurrences"
    );
}
