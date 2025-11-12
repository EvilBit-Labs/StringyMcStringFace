//! Integration tests for ASCII extraction with noise filtering

use insta::assert_snapshot;
use std::fs;
use stringy::container::{ContainerParser, PeParser};
use stringy::extraction::ascii::{
    AsciiExtractionConfig, extract_ascii_strings, extract_from_section,
};
use stringy::extraction::config::NoiseFilterConfig;
use stringy::extraction::filters::{CompositeNoiseFilter, FilterContext};
use stringy::extraction::{BasicExtractor, ExtractionConfig, StringExtractor};
use stringy::types::{BinaryFormat, ContainerInfo, SectionInfo, SectionType};

fn get_fixture_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

#[test]
#[ignore] // Requires test_binary_pe.exe fixture
fn test_ascii_extraction_from_binary() {
    let fixture_path = get_fixture_path("test_binary_pe.exe");
    if !fixture_path.exists() {
        return;
    }

    let pe_data = fs::read(&fixture_path).expect("Failed to read PE fixture");
    let parser = PeParser::new();
    let container_info = parser.parse(&pe_data).expect("Failed to parse PE");

    // Extract ASCII strings from each section
    let config = AsciiExtractionConfig::default();
    let mut all_strings = Vec::new();

    for section in &container_info.sections {
        if section.size > 0 {
            let section_data = &pe_data[section.offset as usize..]
                .get(..section.size as usize)
                .unwrap_or(&[]);
            let strings = extract_ascii_strings(section_data, &config);
            all_strings.extend(strings);
        }
    }

    // Verify that legitimate strings are extracted
    assert!(
        !all_strings.is_empty(),
        "Should extract some strings from binary"
    );

    // Verify all strings have confidence set
    for string in &all_strings {
        assert!(string.confidence >= 0.0 && string.confidence <= 1.0);
    }
}

#[test]
fn test_false_positive_reduction() {
    // Create test data with known noise patterns
    let noise_data = b"AAAA\x00\x00\x00\x00!!!@@@###\0Hello World\0Test123";
    let config = AsciiExtractionConfig::default();
    let strings = extract_ascii_strings(noise_data, &config);

    // Apply noise filtering
    let filter_config = NoiseFilterConfig::default();
    let filter = CompositeNoiseFilter::new(&filter_config);
    let context = FilterContext::default();

    let mut filtered_strings = Vec::new();
    for string in &strings {
        let confidence = filter.calculate_confidence(&string.text, &context);
        if confidence >= 0.5 {
            filtered_strings.push((string.text.clone(), confidence));
        }
    }

    // Verify that noise is filtered out or marked with low confidence
    let noise_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.text == "AAAA" || s.text == "!!!@@@###")
        .collect();

    for noise_string in noise_strings {
        let confidence = filter.calculate_confidence(&noise_string.text, &context);
        assert!(
            confidence < 0.5,
            "Noise string '{}' should have low confidence: {}",
            noise_string.text,
            confidence
        );
    }
}

#[test]
fn test_true_positive_retention() {
    // Create test data with known legitimate strings
    let legitimate_data =
        b"Hello World\0Error: file not found\0C:\\Windows\\System32\0https://example.com";
    let config = AsciiExtractionConfig::default();
    let strings = extract_ascii_strings(legitimate_data, &config);

    // Apply noise filtering
    let filter_config = NoiseFilterConfig::default();
    let filter = CompositeNoiseFilter::new(&filter_config);
    let context = FilterContext::default();

    let mut retained_count = 0;
    for string in &strings {
        let confidence = filter.calculate_confidence(&string.text, &context);
        if confidence >= 0.5 {
            retained_count += 1;
        }
    }

    // Verify that legitimate strings are retained (target: >95%)
    let retention_rate = retained_count as f32 / strings.len() as f32;
    assert!(
        retention_rate > 0.95,
        "True positive retention rate should be >95%, got {}%",
        retention_rate * 100.0
    );
}

#[test]
fn test_performance_overhead() {
    // Measure extraction time with and without noise filtering
    let test_data = b"Hello World\0Test String\0Another String\0".repeat(1000);
    let config = AsciiExtractionConfig::default();

    // Time extraction without filtering
    let start = std::time::Instant::now();
    let strings = extract_ascii_strings(&test_data, &config);
    let extraction_time = start.elapsed();

    // Time filtering
    let filter_config = NoiseFilterConfig::default();
    let filter = CompositeNoiseFilter::new(&filter_config);
    let context = FilterContext::default();

    let start = std::time::Instant::now();
    for string in &strings {
        let _ = filter.calculate_confidence(&string.text, &context);
    }
    let filtering_time = start.elapsed();

    // Verify that overhead is reasonable
    // Note: In debug builds with small test data, filtering may appear slower
    // The <10% overhead target is for optimized release builds with realistic data sizes
    // For this test, we just verify that filtering completes in reasonable time
    let total_time = extraction_time + filtering_time;
    assert!(
        total_time.as_secs_f64() < 1.0,
        "Total extraction+filtering time should be <1s, got {:?} (extraction: {:?}, filtering: {:?})",
        total_time,
        extraction_time,
        filtering_time
    );

    // In release mode, verify the <10% overhead target
    #[cfg(not(debug_assertions))]
    {
        let overhead_ratio = if extraction_time.as_secs_f64() > 0.0 {
            filtering_time.as_secs_f64() / extraction_time.as_secs_f64()
        } else {
            0.0
        };
        assert!(
            overhead_ratio < 0.1,
            "Filtering overhead should be <10% of extraction time in release mode, got {}%",
            overhead_ratio * 100.0
        );
    }
}

#[test]
#[ignore] // Requires test_binary_pe.exe fixture
fn test_snapshot_extraction() {
    let fixture_path = get_fixture_path("test_binary_pe.exe");
    if !fixture_path.exists() {
        return;
    }

    let pe_data = fs::read(&fixture_path).expect("Failed to read PE fixture");
    let parser = PeParser::new();
    let container_info = parser.parse(&pe_data).expect("Failed to parse PE");

    let config = AsciiExtractionConfig::default();
    let mut all_strings = Vec::new();

    for section in &container_info.sections {
        if section.size > 0 && section.section_type == SectionType::StringData {
            let section_data = &pe_data[section.offset as usize..]
                .get(..section.size as usize)
                .unwrap_or(&[]);
            let strings = extract_ascii_strings(section_data, &config);
            all_strings.extend(strings);
        }
    }

    // Create snapshot of extracted strings
    let mut output = String::new();
    for string in &all_strings {
        output.push_str(&format!(
            "{}:{}:{}\n",
            string.text, string.offset, string.confidence
        ));
    }

    assert_snapshot!("ascii_extraction_snapshot", output);
}

#[test]
fn test_section_context_awareness() {
    // Test that section context affects filtering
    let high_weight_section = SectionInfo {
        name: ".rodata".to_string(),
        offset: 0,
        size: 20,
        rva: Some(0x1000),
        section_type: SectionType::StringData,
        is_executable: false,
        is_writable: false,
        weight: 1.0,
    };

    let low_weight_section = SectionInfo {
        name: ".text".to_string(),
        offset: 0,
        size: 20,
        rva: Some(0x2000),
        section_type: SectionType::Code,
        is_executable: true,
        is_writable: false,
        weight: 0.1,
    };

    let data = b"Hello World\0Test";
    let config = AsciiExtractionConfig::default();

    let filter_config = NoiseFilterConfig::default();
    let filter = CompositeNoiseFilter::new(&filter_config);

    let high_weight_context = FilterContext::from_section(&high_weight_section);
    let low_weight_context = FilterContext::from_section(&low_weight_section);

    let strings = extract_ascii_strings(data, &config);

    for string in &strings {
        let high_score = filter.calculate_confidence(&string.text, &high_weight_context);
        let low_score = filter.calculate_confidence(&string.text, &low_weight_context);

        // Strings in high-weight sections should generally have higher confidence
        assert!(
            high_score >= low_score,
            "High-weight section should have equal or higher confidence"
        );
    }
}

#[test]
fn test_full_extraction_path_with_filtering() {
    // Test the full extraction path with filtering enabled using BasicExtractor
    let section = SectionInfo {
        name: ".rodata".to_string(),
        offset: 0,
        size: 50,
        rva: Some(0x1000),
        section_type: SectionType::StringData,
        is_executable: false,
        is_writable: false,
        weight: 1.0,
    };

    // Mix of legitimate strings and noise
    let data = b"Hello World\0AAAA\0Error: file not found\0!!!@@@###\0Test123";

    let extractor = BasicExtractor::new();
    let config = ExtractionConfig {
        noise_filtering_enabled: true,
        min_confidence_threshold: 0.5,
        ..Default::default()
    };

    let container_info = ContainerInfo::new(
        BinaryFormat::Elf,
        vec![section.clone()],
        vec![],
        vec![],
        None,
    );

    let strings = extractor.extract(data, &container_info, &config).unwrap();

    // Verify that filtering is applied (confidence scores are computed)
    assert!(!strings.is_empty(), "Should extract some strings");

    // Verify all strings have confidence scores in valid range
    for string in &strings {
        assert!(
            string.confidence >= 0.0 && string.confidence <= 1.0,
            "String '{}' should have confidence in [0.0, 1.0], got {}",
            string.text,
            string.confidence
        );
    }

    // Verify that strings with confidence >= threshold are retained
    let retained_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.confidence >= config.min_confidence_threshold)
        .collect();

    assert!(
        !retained_strings.is_empty(),
        "Should retain at least some strings with confidence >= threshold"
    );

    // Verify that legitimate strings are likely to be retained
    let legitimate_strings: Vec<_> = strings
        .iter()
        .filter(|s| {
            s.text == "Hello World" || s.text == "Error: file not found" || s.text == "Test123"
        })
        .collect();

    // At least some legitimate strings should be retained
    let retained_legitimate: Vec<_> = legitimate_strings
        .iter()
        .filter(|s| s.confidence >= config.min_confidence_threshold)
        .collect();

    assert!(
        !retained_legitimate.is_empty(),
        "At least one legitimate string should be retained, found {}",
        retained_legitimate.len()
    );
}

#[test]
fn test_extraction_with_filtering_disabled() {
    // Test that filtering can be disabled
    let section = SectionInfo {
        name: ".rodata".to_string(),
        offset: 0,
        size: 30,
        rva: Some(0x1000),
        section_type: SectionType::StringData,
        is_executable: false,
        is_writable: false,
        weight: 1.0,
    };

    let data = b"Hello World\0AAAA\0Test123";

    let extractor = BasicExtractor::new();
    let config = ExtractionConfig {
        noise_filtering_enabled: false,
        ..Default::default()
    };

    let container_info = ContainerInfo::new(BinaryFormat::Elf, vec![section], vec![], vec![], None);

    let strings = extractor.extract(data, &container_info, &config).unwrap();

    // When filtering is disabled, all strings should be included
    assert!(
        strings.len() >= 3,
        "All strings should be included when filtering is disabled, found {}",
        strings.len()
    );

    // All strings should have confidence 1.0 when filtering is disabled
    for string in &strings {
        assert_eq!(
            string.confidence, 1.0,
            "String '{}' should have confidence 1.0 when filtering is disabled, got {}",
            string.text, string.confidence
        );
    }
}

#[test]
fn test_extract_from_section_with_filtering() {
    // Test extract_from_section with filtering enabled
    let section = SectionInfo {
        name: ".rodata".to_string(),
        offset: 0,
        size: 40,
        rva: Some(0x1000),
        section_type: SectionType::StringData,
        is_executable: false,
        is_writable: false,
        weight: 1.0,
    };

    let data = b"Hello World\0AAAA\0Test123";
    let config = AsciiExtractionConfig::default();
    let noise_config = Some(NoiseFilterConfig::default());

    let strings = extract_from_section(
        &section,
        data,
        &config,
        noise_config.as_ref(),
        true, // filtering enabled
        0.5,  // threshold
    );

    // Verify noise is filtered
    let has_noise = strings.iter().any(|s| s.text == "AAAA");
    assert!(!has_noise, "Noise string 'AAAA' should be filtered out");

    // Verify legitimate strings are retained
    let has_legitimate = strings
        .iter()
        .any(|s| s.text == "Hello World" || s.text == "Test123");
    assert!(has_legitimate, "Legitimate strings should be retained");

    // Verify confidence scores are set
    for string in &strings {
        assert!(
            string.confidence >= 0.5,
            "String '{}' should have confidence >= 0.5, got {}",
            string.text,
            string.confidence
        );
    }
}
