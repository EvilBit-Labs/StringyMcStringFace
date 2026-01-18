//! Table output formatter for Stringy.
//!
//! This module provides human-readable table output with automatic TTY detection.
//! When output is directed to a terminal (TTY), strings are displayed in an aligned
//! table with headers showing String, Tags, Score, and Section columns. When output
//! is piped or redirected (non-TTY), only the raw string text is emitted, one per line,
//! for seamless integration with other command-line tools.
//!
//! # TTY Mode Example
//!
//! ```text
//! String                                                       | Tags         | Score | Section
//! -------------------------------------------------------------|--------------|-------|--------
//! https://malware.example.com/beacon                           | url          |   150 | .rdata
//! C:\Windows\System32\cmd.exe                                  | filepath     |   120 | .data
//! GetProcAddress                                               | import       |    80 |
//! ```
//!
//! # Non-TTY Mode Example
//!
//! ```text
//! https://malware.example.com/beacon
//! C:\Windows\System32\cmd.exe
//! GetProcAddress
//! ```
//!
//! # Column Layout
//!
//! - **String**: Up to 60 characters, truncated with `...` if longer
//! - **Tags**: First 2-3 tags, comma-separated, max 20 characters
//! - **Score**: Right-aligned integer score
//! - **Section**: Section name where the string was found

use std::io::IsTerminal;

use crate::classification::ranking::RankingConfig;
use crate::types::{FoundString, Result, Tag};

use super::OutputMetadata;

/// Maximum width for the string column before truncation.
const STRING_COLUMN_WIDTH: usize = 60;

/// Maximum width for the tags column.
const TAGS_COLUMN_WIDTH: usize = 20;

/// Maximum width for the score column.
const SCORE_COLUMN_WIDTH: usize = 6;

/// Maximum width for the section column.
const SECTION_COLUMN_WIDTH: usize = 15;

/// Format strings in a human-readable table format.
///
/// Automatically detects whether output is going to a TTY (terminal) and adjusts
/// the format accordingly. In TTY mode, outputs an aligned table with headers.
/// In non-TTY mode (piped/redirected), outputs plain strings one per line.
///
/// # Arguments
///
/// * `strings` - The extracted strings to format
/// * `metadata` - Output context (currently unused but reserved for future features)
///
/// # Returns
///
/// A formatted string ready for output.
pub fn format_table(strings: &[FoundString], metadata: &OutputMetadata) -> Result<String> {
    let is_tty = std::io::stdout().is_terminal();
    format_table_with_mode(strings, metadata, is_tty)
}

/// Format table with explicit TTY mode specification.
///
/// This function allows explicit control over the output mode, useful for testing
/// and programmatic control over output format.
///
/// # Arguments
///
/// * `strings` - The extracted strings to format
/// * `metadata` - Output context
/// * `is_tty` - Whether to use TTY mode (true) or plain mode (false)
pub fn format_table_with_mode(
    strings: &[FoundString],
    metadata: &OutputMetadata,
    is_tty: bool,
) -> Result<String> {
    if is_tty {
        format_table_tty(strings, metadata)
    } else {
        format_table_plain(strings)
    }
}

/// Format strings as an aligned table for TTY output.
///
/// Creates a table with headers and aligned columns showing:
/// - String text (truncated if necessary)
/// - Tags (comma-separated, limited count)
/// - Score (right-aligned)
/// - Section name
fn format_table_tty(strings: &[FoundString], _metadata: &OutputMetadata) -> Result<String> {
    if strings.is_empty() {
        return Ok(String::new());
    }

    let mut output = String::new();

    // Calculate dynamic column widths based on content
    let section_width = calculate_section_width(strings);
    let tags_width = calculate_tags_width(strings);

    // Build header
    let header = format!(
        "{} | {} | {} | {}",
        pad_string("String", STRING_COLUMN_WIDTH, Alignment::Left),
        pad_string("Tags", tags_width, Alignment::Left),
        pad_string("Score", SCORE_COLUMN_WIDTH, Alignment::Right),
        pad_string("Section", section_width, Alignment::Left),
    );
    output.push_str(&header);
    output.push('\n');

    // Build separator line
    let separator = format!(
        "{}-|-{}-|-{}-|-{}",
        "-".repeat(STRING_COLUMN_WIDTH),
        "-".repeat(tags_width),
        "-".repeat(SCORE_COLUMN_WIDTH),
        "-".repeat(section_width),
    );
    output.push_str(&separator);
    output.push('\n');

    // Build rows
    for found_string in strings {
        let truncated_text = truncate_string(&found_string.text, STRING_COLUMN_WIDTH);
        let tags_display = format_tags(&found_string.tags);
        let section_display = found_string.section.as_deref().unwrap_or("");

        let row = format!(
            "{} | {} | {} | {}",
            pad_string(&truncated_text, STRING_COLUMN_WIDTH, Alignment::Left),
            pad_string(&tags_display, tags_width, Alignment::Left),
            pad_string(
                &found_string.score.to_string(),
                SCORE_COLUMN_WIDTH,
                Alignment::Right
            ),
            pad_string(section_display, section_width, Alignment::Left),
        );
        output.push_str(&row);
        output.push('\n');
    }

    // Remove trailing newline for consistency
    if output.ends_with('\n') {
        output.pop();
    }

    Ok(output)
}

/// Format strings as plain text for non-TTY output.
///
/// Outputs only the string text, one per line, suitable for piping to other tools.
fn format_table_plain(strings: &[FoundString]) -> Result<String> {
    let lines: Vec<String> = strings
        .iter()
        .map(|s| sanitize_plain_text(&s.text))
        .collect();
    Ok(lines.join("\n"))
}

/// Calculate the optimal width for the section column based on content.
fn calculate_section_width(strings: &[FoundString]) -> usize {
    let max_section_len = strings
        .iter()
        .filter_map(|s| s.section.as_ref())
        .map(|s| s.len())
        .max()
        .unwrap_or(0);

    // Minimum width is "Section" header length, maximum is SECTION_COLUMN_WIDTH
    max_section_len.clamp("Section".len(), SECTION_COLUMN_WIDTH)
}

/// Calculate the optimal width for the tags column based on content.
fn calculate_tags_width(strings: &[FoundString]) -> usize {
    let max_tags_len = strings
        .iter()
        .map(|s| format_tags(&s.tags).len())
        .max()
        .unwrap_or(0);

    // Minimum width is "Tags" header length, maximum is TAGS_COLUMN_WIDTH
    max_tags_len.clamp("Tags".len(), TAGS_COLUMN_WIDTH)
}

/// Format tags for display in the table.
///
/// Converts tags to their display format using serde rename values where applicable.
/// Limits output to `MAX_TAGS_DISPLAY` tags to prevent overflow.
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
/// assert_eq!(format_tags(&tags), "ipv4, filepath");
/// ```
pub fn format_tags(tags: &[Tag]) -> String {
    if tags.is_empty() {
        return String::new();
    }

    let config = RankingConfig::default();
    let max_boost = tags
        .iter()
        .map(|tag| tag_boost_value(tag, &config))
        .max()
        .unwrap_or(0);

    let tag_strings: Vec<String> = tags
        .iter()
        .filter(|tag| tag_boost_value(tag, &config) == max_boost)
        .map(tag_to_display_string)
        .collect();

    let result = tag_strings.join(", ");

    // Truncate if still too long
    if result.len() > TAGS_COLUMN_WIDTH {
        truncate_string(&result, TAGS_COLUMN_WIDTH)
    } else {
        result
    }
}

/// Sanitize plain text output so each string renders as a single line.
///
/// Replaces CRLF, LF, and CR with escaped sequences to preserve content
/// while keeping output line-based.
fn sanitize_plain_text(text: &str) -> String {
    text.replace("\r\n", "\\r\\n")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

/// Get the ranking boost value for a tag using the provided config.
fn tag_boost_value(tag: &Tag, config: &RankingConfig) -> i32 {
    config.tag_boosts.get(tag).copied().unwrap_or(0)
}

/// Convert a single tag to its display string.
///
/// Uses the serde rename value where defined, otherwise uses lowercase Debug format.
fn tag_to_display_string(tag: &Tag) -> String {
    match tag {
        Tag::Url => "url".to_string(),
        Tag::Domain => "domain".to_string(),
        Tag::IPv4 => "ipv4".to_string(),
        Tag::IPv6 => "ipv6".to_string(),
        Tag::FilePath => "filepath".to_string(),
        Tag::RegistryPath => "regpath".to_string(),
        Tag::Guid => "guid".to_string(),
        Tag::Email => "email".to_string(),
        Tag::Base64 => "b64".to_string(),
        Tag::FormatString => "fmt".to_string(),
        Tag::UserAgent => "user-agent-ish".to_string(),
        Tag::DemangledSymbol => "demangled".to_string(),
        Tag::Import => "import".to_string(),
        Tag::Export => "export".to_string(),
        Tag::Version => "version".to_string(),
        Tag::Manifest => "manifest".to_string(),
        Tag::Resource => "resource".to_string(),
        Tag::DylibPath => "dylib-path".to_string(),
        Tag::Rpath => "rpath".to_string(),
        Tag::RpathVariable => "rpath-var".to_string(),
        Tag::FrameworkPath => "framework-path".to_string(),
    }
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
    let mut end_index = truncate_at;

    // Ensure we don't split a multi-byte character
    for (idx, _) in s.char_indices() {
        if idx <= truncate_at {
            end_index = idx;
        } else {
            break;
        }
    }

    // Handle case where we need to include at least one character
    if end_index == 0 && !s.is_empty() {
        if let Some((idx, _)) = s.char_indices().nth(1) {
            end_index = idx;
        } else {
            end_index = s.len();
        }
    }

    format!("{}...", &s[..end_index])
}

/// Text alignment for padding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alignment {
    /// Left-align text (pad on right).
    Left,
    /// Right-align text (pad on left).
    Right,
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
    use crate::output::OutputFormat;
    use crate::types::{Encoding, StringSource};

    fn make_test_string(text: &str) -> FoundString {
        FoundString::new(
            text.to_string(),
            Encoding::Ascii,
            0x1000,
            text.len() as u32,
            StringSource::SectionData,
        )
    }

    fn make_metadata() -> OutputMetadata {
        OutputMetadata::new("test.bin".to_string(), OutputFormat::Table, 10, 10)
    }

    // Tests for format_tags
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
            ];

            for tag in all_tags {
                let display = tag_to_display_string(&tag);
                assert!(!display.is_empty(), "Tag {:?} should have display", tag);
                assert!(display.is_ascii(), "Tag display should be ASCII");
            }
        }
    }

    // Tests for truncate_string
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

    // Tests for pad_string
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

    // Tests for format_table
    mod format_table_tests {
        use super::*;

        #[test]
        fn empty_strings_returns_empty() {
            let result = format_table_with_mode(&[], &make_metadata(), true).unwrap();
            assert_eq!(result, "");
        }

        #[test]
        fn single_string_tty_mode() {
            let strings = vec![make_test_string("test string")];
            let result = format_table_with_mode(&strings, &make_metadata(), true).unwrap();

            // Should have header, separator, and one data row
            let lines: Vec<&str> = result.lines().collect();
            assert_eq!(lines.len(), 3);
            assert!(lines[0].contains("String"));
            assert!(lines[0].contains("Tags"));
            assert!(lines[0].contains("Score"));
            assert!(lines[0].contains("Section"));
            assert!(lines[1].contains("---"));
            assert!(lines[2].contains("test string"));
        }

        #[test]
        fn single_string_plain_mode() {
            let strings = vec![make_test_string("test string")];
            let result = format_table_with_mode(&strings, &make_metadata(), false).unwrap();

            assert_eq!(result, "test string");
        }

        #[test]
        fn multiple_strings_plain_mode() {
            let strings = vec![
                make_test_string("first"),
                make_test_string("second"),
                make_test_string("third"),
            ];
            let result = format_table_with_mode(&strings, &make_metadata(), false).unwrap();

            assert_eq!(result, "first\nsecond\nthird");
        }

        #[test]
        fn string_with_tags_displayed() {
            let mut found = make_test_string("http://example.com");
            found.tags = vec![Tag::Url, Tag::Domain];

            let result = format_table_with_mode(&[found], &make_metadata(), true).unwrap();
            assert!(result.contains("url"));
        }

        #[test]
        fn string_with_section_displayed() {
            let found = make_test_string("test").with_section(".rodata".to_string());

            let result = format_table_with_mode(&[found], &make_metadata(), true).unwrap();
            assert!(result.contains(".rodata"));
        }

        #[test]
        fn string_with_score_displayed() {
            let found = make_test_string("test").with_score(150);

            let result = format_table_with_mode(&[found], &make_metadata(), true).unwrap();
            assert!(result.contains("150"));
        }

        #[test]
        fn long_string_truncated_in_tty() {
            let long_text = "a".repeat(100);
            let strings = vec![make_test_string(&long_text)];
            let result = format_table_with_mode(&strings, &make_metadata(), true).unwrap();

            // Should contain truncated version with ...
            assert!(result.contains("..."));
            // Should not contain the full 100 character string
            assert!(!result.contains(&long_text));
        }

        #[test]
        fn long_string_not_truncated_in_plain() {
            let long_text = "a".repeat(100);
            let strings = vec![make_test_string(&long_text)];
            let result = format_table_with_mode(&strings, &make_metadata(), false).unwrap();

            // Plain mode should have full string
            assert_eq!(result, long_text);
        }

        #[test]
        fn missing_optional_fields_handled() {
            // String with no section, no tags, default score
            let found = make_test_string("minimal");

            let result = format_table_with_mode(&[found], &make_metadata(), true).unwrap();
            // Should not crash and should contain the string
            assert!(result.contains("minimal"));
        }

        #[test]
        fn special_characters_in_string() {
            let strings = vec![make_test_string("tab\there"), make_test_string("pipe|here")];
            let result = format_table_with_mode(&strings, &make_metadata(), false).unwrap();

            // Each string should be on its own line in output
            let lines: Vec<&str> = result.lines().collect();
            assert_eq!(lines.len(), 2);
            assert!(lines[0].contains("tab\there"));
            assert!(lines[1].contains("pipe|here"));
        }

        #[test]
        fn string_with_embedded_newline() {
            let strings = vec![make_test_string("line1\nline2")];
            let result = format_table_with_mode(&strings, &make_metadata(), false).unwrap();
            assert_eq!(result, "line1\\nline2");
        }
    }

    // Tests for column width calculation
    mod column_width_tests {
        use super::*;

        #[test]
        fn section_width_minimum() {
            let strings = vec![make_test_string("test")];
            let width = calculate_section_width(&strings);
            assert_eq!(width, "Section".len());
        }

        #[test]
        fn section_width_from_content() {
            let strings = vec![make_test_string("test").with_section(".rodata.str1.1".to_string())];
            let width = calculate_section_width(&strings);
            assert_eq!(width, ".rodata.str1.1".len());
        }

        #[test]
        fn section_width_capped_at_max() {
            let long_section = "a".repeat(50);
            let strings = vec![make_test_string("test").with_section(long_section)];
            let width = calculate_section_width(&strings);
            assert_eq!(width, SECTION_COLUMN_WIDTH);
        }

        #[test]
        fn tags_width_minimum() {
            let strings = vec![make_test_string("test")];
            let width = calculate_tags_width(&strings);
            assert_eq!(width, "Tags".len());
        }

        #[test]
        fn tags_width_from_content() {
            let mut found = make_test_string("test");
            found.tags = vec![Tag::Url, Tag::Domain];
            let width = calculate_tags_width(&[found]);
            assert_eq!(width, "Tags".len());
        }
    }
}
