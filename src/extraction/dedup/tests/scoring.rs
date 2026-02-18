//! Scoring, bonus, threshold, and length preservation tests

use super::*;

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

    let canonical = deduplicate(strings, None);
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

    let canonical = deduplicate(strings, None);
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

    let canonical = deduplicate(strings, None);
    assert_eq!(canonical.len(), 1);
    // Base: 10, Occurrence bonus: 5, Multi-source: 15, Confidence: 8
    assert_eq!(canonical[0].combined_score, 10 + 5 + 15 + 8);
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
    let canonical = deduplicate(strings.clone(), None);
    assert_eq!(canonical.len(), 3);

    // Threshold of 2 - strings appearing 2+ times get deduplication bonuses,
    // but strings below threshold are still preserved (just without bonuses)
    let canonical = deduplicate(strings.clone(), Some(2));
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
    let canonical = deduplicate(strings, Some(3));
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

    let canonical = deduplicate(strings, None);
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
