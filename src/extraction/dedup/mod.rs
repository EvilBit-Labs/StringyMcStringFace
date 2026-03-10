//! String deduplication module
//!
//! This module provides functionality to deduplicate extracted strings while
//! preserving complete metadata about all occurrences. Strings are grouped by
//! (text, encoding) keys, and all occurrence information is preserved in a
//! `CanonicalString` structure.

mod scoring;
#[cfg(test)]
mod tests;

use crate::types::{Encoding, FoundString, StringSource, Tag};
use scoring::calculate_combined_score;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// A canonical string with all its occurrences
///
/// Represents a deduplicated string that may appear multiple times in a binary.
/// All occurrence metadata is preserved, and tags are merged from all occurrences.
#[non_exhaustive]
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
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringOccurrence {
    /// File offset where string was found
    pub offset: u64,
    /// Relative virtual address (if available)
    pub rva: Option<u64>,
    /// Section name where string was found
    pub section: Option<String>,
    /// Original text before demangling (if applicable)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub original_text: Option<String>,
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

impl CanonicalString {
    /// Create a new `CanonicalString` instance
    #[must_use]
    pub fn new(
        text: String,
        encoding: Encoding,
        occurrences: Vec<StringOccurrence>,
        merged_tags: Vec<Tag>,
        combined_score: i32,
    ) -> Self {
        Self {
            text,
            encoding,
            occurrences,
            merged_tags,
            combined_score,
        }
    }
}

impl StringOccurrence {
    /// Create a new `StringOccurrence` instance
    #[must_use]
    pub fn new(offset: u64, source: StringSource, length: u32) -> Self {
        Self {
            offset,
            rva: None,
            section: None,
            original_text: None,
            source,
            original_tags: Vec::new(),
            original_score: 0,
            confidence: 1.0,
            length,
        }
    }

    /// Set the relative virtual address
    #[must_use]
    pub fn with_rva(mut self, rva: u64) -> Self {
        self.rva = Some(rva);
        self
    }

    /// Set the section name
    #[must_use]
    pub fn with_section(mut self, section: String) -> Self {
        self.section = Some(section);
        self
    }

    /// Set the original text before demangling
    #[must_use]
    pub fn with_original_text(mut self, original_text: String) -> Self {
        self.original_text = Some(original_text);
        self
    }

    /// Set the tags from this occurrence
    #[must_use]
    pub fn with_original_tags(mut self, tags: Vec<Tag>) -> Self {
        self.original_tags = tags;
        self
    }

    /// Set the score from this occurrence
    #[must_use]
    pub fn with_original_score(mut self, score: i32) -> Self {
        self.original_score = score;
        self
    }

    /// Set the confidence score
    #[must_use]
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence;
        self
    }
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
/// let canonical = deduplicate(strings, None);
/// ```
pub fn deduplicate(
    strings: Vec<FoundString>,
    dedup_threshold: Option<usize>,
) -> Vec<CanonicalString> {
    if strings.is_empty() {
        return Vec::new();
    }

    // Group strings by (text, encoding) key
    let mut groups: HashMap<(String, Encoding), Vec<FoundString>> = HashMap::new();
    for string in strings {
        let key = (string.text.clone(), string.encoding);
        groups.entry(key).or_default().push(string);
    }

    // Convert each group to a CanonicalString
    let mut canonical_strings: Vec<CanonicalString> = groups
        .into_iter()
        .map(|((text, encoding), found_strings)| {
            // Check if group meets dedup_threshold
            let meets_threshold = if let Some(threshold) = dedup_threshold {
                found_strings.len() >= threshold
            } else {
                true // No threshold means all groups are eligible for deduplication
            };

            let occurrences: Vec<StringOccurrence> = found_strings
                .into_iter()
                .map(found_string_to_occurrence)
                .collect();

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

            CanonicalString::new(text, encoding, occurrences, merged_tags, combined_score)
        })
        .collect();

    // Sort by combined_score descending
    canonical_strings.sort_by(|a, b| b.combined_score.cmp(&a.combined_score));

    canonical_strings
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
    let mut seen = HashSet::new();
    let mut tags = Vec::new();
    for occurrence in occurrences {
        for tag in &occurrence.original_tags {
            if seen.insert(tag.clone()) {
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
    let mut occurrence = StringOccurrence::new(fs.offset, fs.source, fs.length)
        .with_original_tags(fs.tags)
        .with_original_score(fs.score)
        .with_confidence(fs.confidence);

    if let Some(rva) = fs.rva {
        occurrence = occurrence.with_rva(rva);
    }
    if let Some(section) = fs.section {
        occurrence = occurrence.with_section(section);
    }
    if let Some(original_text) = fs.original_text {
        occurrence = occurrence.with_original_text(original_text);
    }

    occurrence
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
    pub fn to_found_string(&self) -> Option<FoundString> {
        let first_occurrence = self.occurrences.first()?;
        let max_confidence = self
            .occurrences
            .iter()
            .map(|occ| occ.confidence)
            .fold(0.0f32, f32::max);

        let mut fs = FoundString::new(
            self.text.clone(),
            self.encoding,
            first_occurrence.offset,
            first_occurrence.length,
            first_occurrence.source,
        )
        .with_tags(self.merged_tags.clone())
        .with_score(self.combined_score)
        .with_confidence(max_confidence);

        if let Some(rva) = first_occurrence.rva {
            fs = fs.with_rva(rva);
        }
        if let Some(ref section) = first_occurrence.section {
            fs = fs.with_section(section.clone());
        }
        if let Some(ref original_text) = first_occurrence.original_text {
            fs = fs.with_original_text(original_text.clone());
        }

        Some(fs)
    }
}
