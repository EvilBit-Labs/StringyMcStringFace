//! Tests for string deduplication

use super::*;
use crate::types::{Encoding, StringSource, Tag};

// Test helper needs many parameters to construct FoundString with full metadata
#[allow(clippy::too_many_arguments)]
fn create_test_string(
    text: &str,
    encoding: Encoding,
    offset: u64,
    section: Option<String>,
    source: StringSource,
    tags: Vec<Tag>,
    score: i32,
    confidence: f32,
) -> FoundString {
    // Calculate byte length based on encoding
    let length = match encoding {
        Encoding::Utf16Le | Encoding::Utf16Be => {
            // UTF-16: 2 bytes per character
            text.chars().count() * 2
        }
        _ => {
            // ASCII/UTF-8: 1 byte per character (approximation for tests)
            text.len()
        }
    } as u32;

    FoundString {
        text: text.to_string(),
        original_text: None,
        encoding,
        offset,
        rva: Some(offset + 0x1000),
        section,
        length,
        tags,
        score,
        section_weight: None,
        semantic_boost: None,
        noise_penalty: None,
        source,
        confidence,
    }
}

#[test]
fn test_basic_deduplication() {
    let strings = vec![
        create_test_string(
            "Hello",
            Encoding::Utf8,
            0x100,
            Some(".rodata".to_string()),
            StringSource::SectionData,
            vec![],
            10,
            0.8,
        ),
        create_test_string(
            "Hello",
            Encoding::Utf8,
            0x200,
            Some(".rodata".to_string()),
            StringSource::SectionData,
            vec![],
            15,
            0.9,
        ),
        create_test_string(
            "Hello",
            Encoding::Utf8,
            0x300,
            Some(".data".to_string()),
            StringSource::SectionData,
            vec![],
            12,
            0.7,
        ),
    ];

    let canonical = deduplicate(strings, None, true);
    assert_eq!(canonical.len(), 1);
    assert_eq!(canonical[0].text, "Hello");
    assert_eq!(canonical[0].occurrences.len(), 3);
}

#[test]
fn test_encoding_separation() {
    let strings = vec![
        create_test_string(
            "Test",
            Encoding::Utf8,
            0x100,
            None,
            StringSource::SectionData,
            vec![],
            10,
            0.8,
        ),
        create_test_string(
            "Test",
            Encoding::Utf16Le,
            0x200,
            None,
            StringSource::SectionData,
            vec![],
            10,
            0.8,
        ),
    ];

    let canonical = deduplicate(strings, None, true);
    assert_eq!(canonical.len(), 2);
    assert!(canonical.iter().any(|c| c.encoding == Encoding::Utf8));
    assert!(canonical.iter().any(|c| c.encoding == Encoding::Utf16Le));
}

#[test]
fn test_metadata_preservation() {
    let strings = vec![
        create_test_string(
            "Test",
            Encoding::Utf8,
            0x100,
            Some(".rodata".to_string()),
            StringSource::SectionData,
            vec![],
            10,
            0.8,
        ),
        create_test_string(
            "Test",
            Encoding::Utf8,
            0x200,
            Some(".data".to_string()),
            StringSource::ImportName,
            vec![],
            15,
            0.9,
        ),
    ];

    let canonical = deduplicate(strings, None, true);
    assert_eq!(canonical.len(), 1);
    let occ = &canonical[0].occurrences;
    assert_eq!(occ.len(), 2);
    assert_eq!(occ[0].offset, 0x100);
    assert_eq!(occ[1].offset, 0x200);
    assert_eq!(occ[0].section, Some(".rodata".to_string()));
    assert_eq!(occ[1].section, Some(".data".to_string()));
    assert_eq!(occ[0].source, StringSource::SectionData);
    assert_eq!(occ[1].source, StringSource::ImportName);
}

#[test]
fn test_tag_merging() {
    let strings = vec![
        create_test_string(
            "Test",
            Encoding::Utf8,
            0x100,
            None,
            StringSource::SectionData,
            vec![Tag::Url, Tag::Domain],
            10,
            0.8,
        ),
        create_test_string(
            "Test",
            Encoding::Utf8,
            0x200,
            None,
            StringSource::SectionData,
            vec![Tag::Domain, Tag::Email],
            10,
            0.8,
        ),
    ];

    let canonical = deduplicate(strings, None, true);
    assert_eq!(canonical.len(), 1);
    let merged = &canonical[0].merged_tags;
    assert_eq!(merged.len(), 3);
    assert!(merged.contains(&Tag::Url));
    assert!(merged.contains(&Tag::Domain));
    assert!(merged.contains(&Tag::Email));
}

#[test]
fn test_score_calculation() {
    // Test base score (max)
    let strings = vec![
        create_test_string(
            "Test",
            Encoding::Utf8,
            0x100,
            None,
            StringSource::SectionData,
            vec![],
            10,
            0.8,
        ),
        create_test_string(
            "Test",
            Encoding::Utf8,
            0x200,
            None,
            StringSource::SectionData,
            vec![],
            15,
            0.9,
        ),
    ];

    let canonical = deduplicate(strings, None, true);
    assert_eq!(canonical.len(), 1);
    // Base: 15 (max), Occurrence bonus: 5, Confidence: 9 (0.9 * 10)
    assert_eq!(canonical[0].combined_score, 15 + 5 + 9);
}

#[test]
fn test_cross_section_bonus() {
    let strings = vec![
        create_test_string(
            "Test",
            Encoding::Utf8,
            0x100,
            Some(".rodata".to_string()),
            StringSource::SectionData,
            vec![],
            10,
            0.8,
        ),
        create_test_string(
            "Test",
            Encoding::Utf8,
            0x200,
            Some(".data".to_string()),
            StringSource::SectionData,
            vec![],
            10,
            0.8,
        ),
    ];

    let canonical = deduplicate(strings, None, true);
    assert_eq!(canonical.len(), 1);
    // Base: 10, Occurrence bonus: 5, Cross-section: 10, Confidence: 8
    assert_eq!(canonical[0].combined_score, 10 + 5 + 10 + 8);
}

#[test]
fn test_multi_source_bonus() {
    let strings = vec![
        create_test_string(
            "Test",
            Encoding::Utf8,
            0x100,
            None,
            StringSource::SectionData,
            vec![],
            10,
            0.8,
        ),
        create_test_string(
            "Test",
            Encoding::Utf8,
            0x200,
            None,
            StringSource::ImportName,
            vec![],
            10,
            0.8,
        ),
    ];

    let canonical = deduplicate(strings, None, true);
    assert_eq!(canonical.len(), 1);
    // Base: 10, Occurrence bonus: 5, Multi-source: 15, Confidence: 8
    assert_eq!(canonical[0].combined_score, 10 + 5 + 15 + 8);
}

#[test]
fn test_empty_input() {
    let strings = Vec::new();
    let canonical = deduplicate(strings, None, true);
    assert!(canonical.is_empty());
}

#[test]
fn test_single_occurrence() {
    let strings = vec![create_test_string(
        "Test",
        Encoding::Utf8,
        0x100,
        None,
        StringSource::SectionData,
        vec![],
        10,
        0.8,
    )];

    let canonical = deduplicate(strings, None, true);
    assert_eq!(canonical.len(), 1);
    assert_eq!(canonical[0].occurrences.len(), 1);
    // Base: 10, Confidence: 8, no bonuses
    assert_eq!(canonical[0].combined_score, 10 + 8);
}

#[test]
fn test_sorting() {
    let strings = vec![
        create_test_string(
            "Low",
            Encoding::Utf8,
            0x100,
            None,
            StringSource::SectionData,
            vec![],
            5,
            0.5,
        ),
        create_test_string(
            "High",
            Encoding::Utf8,
            0x200,
            None,
            StringSource::SectionData,
            vec![],
            20,
            0.9,
        ),
        create_test_string(
            "Medium",
            Encoding::Utf8,
            0x300,
            None,
            StringSource::SectionData,
            vec![],
            15,
            0.7,
        ),
    ];

    let canonical = deduplicate(strings, None, true);
    assert_eq!(canonical.len(), 3);
    // Should be sorted by combined_score descending
    assert_eq!(canonical[0].text, "High");
    assert_eq!(canonical[1].text, "Medium");
    assert_eq!(canonical[2].text, "Low");
}

#[test]
fn test_edge_case_empty_string() {
    let strings = vec![create_test_string(
        "",
        Encoding::Utf8,
        0x100,
        None,
        StringSource::SectionData,
        vec![],
        10,
        0.8,
    )];

    let canonical = deduplicate(strings, None, true);
    assert_eq!(canonical.len(), 1);
    assert_eq!(canonical[0].text, "");
}

#[test]
fn test_to_found_string() {
    let strings = vec![
        create_test_string(
            "Test",
            Encoding::Utf8,
            0x100,
            Some(".rodata".to_string()),
            StringSource::SectionData,
            vec![Tag::Url],
            10,
            0.8,
        ),
        create_test_string(
            "Test",
            Encoding::Utf8,
            0x200,
            Some(".data".to_string()),
            StringSource::ImportName,
            vec![Tag::Domain],
            15,
            0.9,
        ),
    ];

    let canonical = deduplicate(strings, None, true);
    let found = canonical[0]
        .to_found_string()
        .expect("canonical string with occurrences should convert");
    assert_eq!(found.text, "Test");
    assert_eq!(found.offset, 0x100); // First occurrence
    assert_eq!(found.score, canonical[0].combined_score);
    assert_eq!(found.confidence, 0.9); // Max confidence
    assert_eq!(found.tags.len(), 2); // Merged tags
}

#[test]
fn test_dedup_threshold() {
    let strings = vec![
        create_test_string(
            "Once",
            Encoding::Utf8,
            0x100,
            None,
            StringSource::SectionData,
            vec![],
            10,
            0.8,
        ),
        create_test_string(
            "Twice",
            Encoding::Utf8,
            0x200,
            None,
            StringSource::SectionData,
            vec![],
            10,
            0.8,
        ),
        create_test_string(
            "Twice",
            Encoding::Utf8,
            0x300,
            None,
            StringSource::SectionData,
            vec![],
            10,
            0.8,
        ),
        create_test_string(
            "Thrice",
            Encoding::Utf8,
            0x400,
            None,
            StringSource::SectionData,
            vec![],
            10,
            0.8,
        ),
        create_test_string(
            "Thrice",
            Encoding::Utf8,
            0x500,
            None,
            StringSource::SectionData,
            vec![],
            10,
            0.8,
        ),
        create_test_string(
            "Thrice",
            Encoding::Utf8,
            0x600,
            None,
            StringSource::SectionData,
            vec![],
            10,
            0.8,
        ),
    ];

    // No threshold - all should be deduplicated
    let canonical = deduplicate(strings.clone(), None, true);
    assert_eq!(canonical.len(), 3);

    // Threshold of 2 - strings appearing 2+ times get deduplication bonuses,
    // but strings below threshold are still preserved (just without bonuses)
    let canonical = deduplicate(strings.clone(), Some(2), true);
    assert_eq!(canonical.len(), 3); // All strings preserved: "Once", "Twice", "Thrice"
    assert!(canonical.iter().any(|c| c.text == "Once"));
    assert!(canonical.iter().any(|c| c.text == "Twice"));
    assert!(canonical.iter().any(|c| c.text == "Thrice"));

    // Verify "Once" is preserved but without bonuses (only base score)
    let once = canonical.iter().find(|c| c.text == "Once").unwrap();
    assert_eq!(once.occurrences.len(), 1);
    assert_eq!(once.combined_score, 10); // Base score only, no bonuses

    // Verify "Twice" and "Thrice" get bonuses
    let twice = canonical.iter().find(|c| c.text == "Twice").unwrap();
    assert_eq!(twice.occurrences.len(), 2);
    assert!(twice.combined_score > 10); // Should have bonuses

    let thrice = canonical.iter().find(|c| c.text == "Thrice").unwrap();
    assert_eq!(thrice.occurrences.len(), 3);
    assert!(thrice.combined_score > 10); // Should have bonuses

    // Threshold of 3 - strings appearing 3+ times get bonuses, others preserved without
    let canonical = deduplicate(strings, Some(3), true);
    assert_eq!(canonical.len(), 3); // All strings preserved
    let once = canonical.iter().find(|c| c.text == "Once").unwrap();
    assert_eq!(once.combined_score, 10); // No bonuses
    let twice = canonical.iter().find(|c| c.text == "Twice").unwrap();
    assert_eq!(twice.combined_score, 10); // No bonuses (below threshold)
    let thrice = canonical.iter().find(|c| c.text == "Thrice").unwrap();
    assert!(thrice.combined_score > 10); // Has bonuses (meets threshold)
}

#[test]
fn test_length_preservation() {
    // Test that length is preserved correctly for UTF-16 strings
    let strings = vec![
        FoundString {
            text: "Test".to_string(),
            original_text: None,
            encoding: Encoding::Utf16Le,
            offset: 0x100,
            rva: Some(0x1000),
            section: None,
            length: 8, // 4 characters * 2 bytes = 8 bytes
            tags: vec![],
            score: 10,
            section_weight: None,
            semantic_boost: None,
            noise_penalty: None,
            source: StringSource::SectionData,
            confidence: 0.8,
        },
        FoundString {
            text: "Test".to_string(),
            original_text: None,
            encoding: Encoding::Utf16Le,
            offset: 0x200,
            rva: Some(0x2000),
            section: None,
            length: 8,
            tags: vec![],
            score: 15,
            section_weight: None,
            semantic_boost: None,
            noise_penalty: None,
            source: StringSource::SectionData,
            confidence: 0.9,
        },
    ];

    let canonical = deduplicate(strings, None, true);
    assert_eq!(canonical.len(), 1);
    assert_eq!(canonical[0].occurrences[0].length, 8);
    assert_eq!(canonical[0].occurrences[1].length, 8);

    // Verify to_found_string() uses stored length, not text.len()
    let found = canonical[0]
        .to_found_string()
        .expect("canonical string with occurrences should convert");
    assert_eq!(found.length, 8); // Should be 8 bytes, not 4 (text.len())
    assert_eq!(found.text.len(), 4); // But text is still 4 characters
}
