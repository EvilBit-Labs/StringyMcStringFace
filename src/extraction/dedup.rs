//! String deduplication module
//!
//! This module provides functionality to deduplicate extracted strings while
//! preserving complete metadata about all occurrences. Strings are grouped by
//! (text, encoding) keys, and all occurrence information is preserved in a
//! `CanonicalString` structure.

use crate::types::{Encoding, FoundString, StringSource, Tag};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A canonical string with all its occurrences
///
/// Represents a deduplicated string that may appear multiple times in a binary.
/// All occurrence metadata is preserved, and tags are merged from all occurrences.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalString {
    /// The deduplicated string content
    pub text: String,
    /// Encoding type
    pub encoding: Encoding,
    /// All locations where this string appears
    pub occurrences: Vec<StringOccurrence>,
    /// Union of tags from all occurrences
    pub merged_tags: Vec<Tag>,
    /// Calculated score with occurrence-based bonuses
    pub combined_score: i32,
}

/// Metadata about a single occurrence of a string
///
/// Preserves all location and context information for each instance where
/// a string appears in the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringOccurrence {
    /// File offset where string was found
    pub offset: u64,
    /// Relative virtual address (if available)
    pub rva: Option<u64>,
    /// Section name where string was found
    pub section: Option<String>,
    /// Extraction source type
    pub source: StringSource,
    /// Tags from this specific occurrence
    pub original_tags: Vec<Tag>,
    /// Score from this specific occurrence
    pub original_score: i32,
    /// Confidence score from noise filtering
    pub confidence: f32,
    /// Length of the string in bytes
    pub length: u32,
}

/// Deduplicate a vector of found strings
///
/// Groups strings by (text, encoding) key and creates `CanonicalString` entries
/// with all occurrence metadata preserved. The result is sorted by combined_score
/// in descending order.
///
/// # Arguments
///
/// * `strings` - Vector of found strings to deduplicate
/// * `dedup_threshold` - Optional minimum occurrence count to deduplicate (None = deduplicate all)
/// * `preserve_all_occurrences` - If false, only store occurrence count instead of full metadata
///
/// # Returns
///
/// Vector of canonical strings sorted by combined_score (descending)
///
/// # Example
///
/// ```rust
/// use stringy::extraction::dedup::deduplicate;
/// use stringy::types::{FoundString, Encoding, StringSource};
///
/// let mut strings = Vec::new();
/// // ... populate strings ...
/// let canonical = deduplicate(strings, None, true);
/// ```
pub fn deduplicate(
    strings: Vec<FoundString>,
    dedup_threshold: Option<usize>,
    preserve_all_occurrences: bool,
) -> Vec<CanonicalString> {
    if strings.is_empty() {
        return Vec::new();
    }

    // Group strings by (text, encoding) key
    // Use string representation of encoding as HashMap key since Encoding doesn't implement Hash
    let mut groups: HashMap<(String, String), Vec<FoundString>> = HashMap::new();
    for string in strings {
        let encoding_str = format!("{:?}", string.encoding);
        let key = (string.text.clone(), encoding_str);
        groups.entry(key).or_default().push(string);
    }

    // Convert each group to a CanonicalString
    let mut canonical_strings: Vec<CanonicalString> = groups
        .into_iter()
        .map(|((text, _encoding_str), found_strings)| {
            // Check if group meets dedup_threshold
            let meets_threshold = if let Some(threshold) = dedup_threshold {
                found_strings.len() >= threshold
            } else {
                true // No threshold means all groups are eligible for deduplication
            };

            // All strings in group have same encoding, use first one
            let encoding = found_strings[0].encoding;

            let occurrences: Vec<StringOccurrence> = if preserve_all_occurrences {
                // Store full occurrence metadata
                found_strings
                    .into_iter()
                    .map(found_string_to_occurrence)
                    .collect()
            } else {
                // Store only the first occurrence as representative, but we still need
                // the count for scoring, so we'll keep all but mark them as "count only"
                // For now, we'll still store all occurrences but this could be optimized
                // to store just a count field in the future
                found_strings
                    .into_iter()
                    .map(found_string_to_occurrence)
                    .collect()
            };

            let merged_tags = merge_tags(&occurrences);

            // Only apply deduplication bonuses if threshold is met
            // For groups below threshold, use the base score without bonuses
            let combined_score = if meets_threshold {
                calculate_combined_score(&occurrences)
            } else {
                // For groups below threshold, use the maximum original score without bonuses
                occurrences
                    .iter()
                    .map(|occ| occ.original_score)
                    .max()
                    .unwrap_or(0)
            };

            CanonicalString {
                text,
                encoding,
                occurrences,
                merged_tags,
                combined_score,
            }
        })
        .collect();

    // Sort by combined_score descending
    canonical_strings.sort_by(|a, b| b.combined_score.cmp(&a.combined_score));

    canonical_strings
}

/// Calculate combined score for a group of occurrences
///
/// Combines individual scores with bonuses for multiple occurrences,
/// cross-section presence, multi-source presence, and confidence.
///
/// # Arguments
///
/// * `occurrences` - Slice of string occurrences
///
/// # Returns
///
/// Combined score as i32
fn calculate_combined_score(occurrences: &[StringOccurrence]) -> i32 {
    if occurrences.is_empty() {
        return 0;
    }

    // Base score: maximum original_score across all occurrences
    let base_score = occurrences
        .iter()
        .map(|occ| occ.original_score)
        .max()
        .unwrap_or(0);

    // Occurrence bonus: 5 points per additional occurrence
    let occurrence_bonus = if occurrences.len() > 1 {
        5 * (occurrences.len() - 1) as i32
    } else {
        0
    };

    // Cross-section bonus: 10 points if string appears in different sections
    let mut unique_sections = Vec::new();
    for occ in occurrences.iter() {
        if !unique_sections.contains(&occ.section) {
            unique_sections.push(occ.section.clone());
        }
    }
    let cross_section_bonus = if unique_sections.len() > 1 { 10 } else { 0 };

    // Multi-source bonus: 15 points if string appears from different sources
    let mut unique_sources = Vec::new();
    for occ in occurrences.iter() {
        if !unique_sources.contains(&occ.source) {
            unique_sources.push(occ.source);
        }
    }
    let multi_source_bonus = if unique_sources.len() > 1 { 15 } else { 0 };

    // Confidence boost: max_confidence * 10
    let max_confidence = occurrences
        .iter()
        .map(|occ| occ.confidence)
        .fold(0.0f32, f32::max);
    let confidence_boost = (max_confidence * 10.0) as i32;

    base_score + occurrence_bonus + cross_section_bonus + multi_source_bonus + confidence_boost
}

/// Merge tags from all occurrences
///
/// Creates a union of all tags from all occurrences, ensuring uniqueness
/// and returning a vector for consistent output.
///
/// # Arguments
///
/// * `occurrences` - Slice of string occurrences
///
/// # Returns
///
/// Vector of unique tags (order may vary since Tag doesn't implement Ord)
fn merge_tags(occurrences: &[StringOccurrence]) -> Vec<Tag> {
    let mut tags = Vec::new();
    for occurrence in occurrences {
        for tag in &occurrence.original_tags {
            if !tags.contains(tag) {
                tags.push(tag.clone());
            }
        }
    }
    tags
}

/// Convert a FoundString to a StringOccurrence
///
/// # Arguments
///
/// * `fs` - FoundString to convert
///
/// # Returns
///
/// StringOccurrence with all metadata preserved
pub fn found_string_to_occurrence(fs: FoundString) -> StringOccurrence {
    StringOccurrence {
        offset: fs.offset,
        rva: fs.rva,
        section: fs.section,
        source: fs.source,
        original_tags: fs.tags,
        original_score: fs.score,
        confidence: fs.confidence,
        length: fs.length,
    }
}

impl CanonicalString {
    /// Convert to a representative FoundString for backward compatibility
    ///
    /// Uses the first occurrence's metadata as the representative, with merged
    /// tags and combined score. The highest confidence from all occurrences
    /// is used.
    ///
    /// # Returns
    ///
    /// FoundString representing this canonical string
    pub fn to_found_string(&self) -> FoundString {
        let first_occurrence = &self.occurrences[0];
        let max_confidence = self
            .occurrences
            .iter()
            .map(|occ| occ.confidence)
            .fold(0.0f32, f32::max);

        FoundString {
            text: self.text.clone(),
            original_text: None,
            encoding: self.encoding,
            offset: first_occurrence.offset,
            rva: first_occurrence.rva,
            section: first_occurrence.section.clone(),
            length: first_occurrence.length,
            tags: self.merged_tags.clone(),
            score: self.combined_score,
            section_weight: None,
            semantic_boost: None,
            noise_penalty: None,
            source: first_occurrence.source,
            confidence: max_confidence,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Encoding, StringSource, Tag};

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
        let found = canonical[0].to_found_string();
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
        let found = canonical[0].to_found_string();
        assert_eq!(found.length, 8); // Should be 8 bytes, not 4 (text.len())
        assert_eq!(found.text.len(), 4); // But text is still 4 characters
    }
}
