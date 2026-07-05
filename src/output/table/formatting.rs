//! String formatting utilities for table output.
//!
//! This module provides shared utilities for formatting strings, tags, and
//! text alignment used by both TTY and plain output modes.

use std::sync::LazyLock;

use crate::classification::RankingConfig;
use crate::types::Tag;

use super::TAGS_COLUMN_WIDTH;

/// Shared default ranking config to avoid per-call allocation.
static DEFAULT_RANKING_CONFIG: LazyLock<RankingConfig> = LazyLock::new(RankingConfig::default);

/// Text alignment for padding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alignment {
    /// Left-align text (pad on right).
    Left,
    /// Right-align text (pad on left).
    Right,
}

/// Format tags for display in the table.
///
/// Converts tags to their display format using serde rename values where applicable.
/// Shows only tags with the highest boost value to prioritize important tags.
///
/// # Arguments
///
/// * `tags` - Slice of tags to format
///
/// # Returns
///
/// Comma-separated string of tag names, or empty string if no tags.
///
/// # Examples
///
/// ```ignore
/// let tags = vec![Tag::IPv4, Tag::FilePath];
/// assert_eq!(format_tags(&tags), "ipv4");
/// ```
pub fn format_tags(tags: &[Tag]) -> String {
    if tags.is_empty() {
        return String::new();
    }

    let config = &*DEFAULT_RANKING_CONFIG;
    let max_boost = tags
        .iter()
        .map(|tag| tag_boost_value(tag, config))
        .max()
        .unwrap_or(0);

    let tag_strings: Vec<String> = tags
        .iter()
        .filter(|tag| tag_boost_value(tag, config) == max_boost)
        .map(|tag| tag.to_string())
        .collect();

    let result = tag_strings.join(", ");

    // Truncate if still too long
    if result.len() > TAGS_COLUMN_WIDTH {
        truncate_string(&result, TAGS_COLUMN_WIDTH)
    } else {
        result
    }
}

/// Get the ranking boost value for a tag using the provided config.
fn tag_boost_value(tag: &Tag, config: &RankingConfig) -> i32 {
    config.tag_boosts.get(tag).copied().unwrap_or(0)
}

/// Truncate a string to the specified maximum length.
///
/// If the string exceeds the maximum length, it is truncated and `...` is appended.
/// Handles Unicode correctly by truncating at character boundaries.
///
/// # Arguments
///
/// * `s` - The string to truncate
/// * `max_len` - Maximum length including the ellipsis
///
/// # Returns
///
/// The original string if it fits, or a truncated version with `...` appended.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(truncate_string("hello", 10), "hello");
/// assert_eq!(truncate_string("hello world", 8), "hello...");
/// ```
pub fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }

    if max_len <= 3 {
        return ".".repeat(max_len);
    }

    // Find a valid character boundary for truncation
    let truncate_at = max_len - 3;
    let mut end_index = 0;

    // Find the last char boundary that fits within truncate_at bytes
    for (idx, _) in s.char_indices() {
        if idx <= truncate_at {
            end_index = idx;
        } else {
            break;
        }
    }

    // If the first character is too wide to fit with "...", just return dots
    if end_index == 0 {
        return ".".repeat(max_len.min(3));
    }

    format!("{}...", &s[..end_index])
}

/// Pad a string to a fixed width with the specified alignment.
///
/// # Arguments
///
/// * `s` - The string to pad
/// * `width` - Target width
/// * `alignment` - Left or right alignment
///
/// # Returns
///
/// The padded string.
pub fn pad_string(s: &str, width: usize, alignment: Alignment) -> String {
    match alignment {
        Alignment::Left => format!("{:<width$}", s, width = width),
        Alignment::Right => format!("{:>width$}", s, width = width),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod format_tags_tests {
        use super::*;

        #[test]
        fn empty_tags() {
            assert_eq!(format_tags(&[]), "");
        }

        #[test]
        fn single_tag() {
            assert_eq!(format_tags(&[Tag::Url]), "url");
            assert_eq!(format_tags(&[Tag::IPv4]), "ipv4");
            assert_eq!(format_tags(&[Tag::FilePath]), "filepath");
        }

        #[test]
        fn two_tags() {
            assert_eq!(format_tags(&[Tag::Url, Tag::Domain]), "url");
            assert_eq!(format_tags(&[Tag::IPv4, Tag::FilePath]), "ipv4");
        }

        #[test]
        fn three_tags() {
            assert_eq!(format_tags(&[Tag::Url, Tag::Domain, Tag::IPv4]), "url");
        }

        #[test]
        fn more_than_max_tags_truncated() {
            let tags = vec![
                Tag::Url,
                Tag::Domain,
                Tag::IPv4,
                Tag::FilePath,
                Tag::RegistryPath,
            ];
            assert_eq!(format_tags(&tags), "url");
        }

        #[test]
        fn multiple_tags_same_priority() {
            assert_eq!(format_tags(&[Tag::Import, Tag::Export]), "import, export");
        }

        #[test]
        fn all_tag_variants_have_display() {
            // Ensure all tag variants produce valid output
            let all_tags = vec![
                Tag::Url,
                Tag::Domain,
                Tag::IPv4,
                Tag::IPv6,
                Tag::FilePath,
                Tag::RegistryPath,
                Tag::Guid,
                Tag::Email,
                Tag::Base64,
                Tag::FormatString,
                Tag::UserAgent,
                Tag::DemangledSymbol,
                Tag::Import,
                Tag::Export,
                Tag::Version,
                Tag::Manifest,
                Tag::Resource,
                Tag::DylibPath,
                Tag::Rpath,
                Tag::RpathVariable,
                Tag::FrameworkPath,
                Tag::Crypto,
                Tag::Network,
                Tag::FileIO,
                Tag::EntryPoint,
            ];

            for tag in all_tags {
                let display = tag.to_string();
                assert!(!display.is_empty(), "Tag {tag:?} should have display");
                assert!(display.is_ascii(), "Tag display should be ASCII");
            }
        }
    }

    mod truncate_string_tests {
        use super::*;

        #[test]
        fn short_string_unchanged() {
            assert_eq!(truncate_string("hello", 10), "hello");
            assert_eq!(truncate_string("", 10), "");
        }

        #[test]
        fn exact_length_unchanged() {
            assert_eq!(truncate_string("hello", 5), "hello");
        }

        #[test]
        fn long_string_truncated() {
            assert_eq!(truncate_string("hello world", 8), "hello...");
        }

        #[test]
        fn very_short_max_length() {
            assert_eq!(truncate_string("hello", 3), "...");
            assert_eq!(truncate_string("hello", 2), "..");
            assert_eq!(truncate_string("hello", 1), ".");
        }

        #[test]
        fn unicode_string_safe_truncation() {
            // Ensure we don't split multi-byte characters
            let unicode = "hello\u{1F600}world"; // emoji in the middle
            let truncated = truncate_string(unicode, 8);
            // Should truncate before the emoji to avoid splitting it
            assert!(truncated.ends_with("..."));
            assert!(truncated.len() <= 8);
        }

        #[test]
        fn unicode_at_boundary() {
            let text = "\u{4E2D}\u{6587}\u{6D4B}\u{8BD5}"; // Chinese characters
            let truncated = truncate_string(text, 6);
            assert!(truncated.is_char_boundary(truncated.len() - 3));
        }
    }

    mod pad_string_tests {
        use super::*;

        #[test]
        fn left_alignment() {
            assert_eq!(pad_string("hi", 5, Alignment::Left), "hi   ");
            assert_eq!(pad_string("hello", 5, Alignment::Left), "hello");
        }

        #[test]
        fn right_alignment() {
            assert_eq!(pad_string("hi", 5, Alignment::Right), "   hi");
            assert_eq!(pad_string("hello", 5, Alignment::Right), "hello");
        }

        #[test]
        fn exact_width() {
            assert_eq!(pad_string("exact", 5, Alignment::Left), "exact");
            assert_eq!(pad_string("exact", 5, Alignment::Right), "exact");
        }

        #[test]
        fn empty_string() {
            assert_eq!(pad_string("", 5, Alignment::Left), "     ");
            assert_eq!(pad_string("", 5, Alignment::Right), "     ");
        }
    }
}
