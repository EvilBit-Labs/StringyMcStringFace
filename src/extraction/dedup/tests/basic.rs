//! Basic deduplication tests: grouping, encoding separation, metadata, tags, edge cases

use super::*;

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

    let canonical = deduplicate(strings, None);
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

    let canonical = deduplicate(strings, None);
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

    let canonical = deduplicate(strings, None);
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

    let canonical = deduplicate(strings, None);
    assert_eq!(canonical.len(), 1);
    let merged = &canonical[0].merged_tags;
    assert_eq!(merged.len(), 3);
    assert!(merged.contains(&Tag::Url));
    assert!(merged.contains(&Tag::Domain));
    assert!(merged.contains(&Tag::Email));
}

#[test]
fn test_empty_input() {
    let strings = Vec::new();
    let canonical = deduplicate(strings, None);
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

    let canonical = deduplicate(strings, None);
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

    let canonical = deduplicate(strings, None);
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

    let canonical = deduplicate(strings, None);
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

    let canonical = deduplicate(strings, None);
    let found = canonical[0]
        .to_found_string()
        .expect("canonical string with occurrences should convert");
    assert_eq!(found.text, "Test");
    assert_eq!(found.offset, 0x100); // First occurrence
    assert_eq!(found.score, canonical[0].combined_score);
    assert_eq!(found.confidence, 0.9); // Max confidence
    assert_eq!(found.tags.len(), 2); // Merged tags
}
