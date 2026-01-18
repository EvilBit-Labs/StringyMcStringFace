//! TTY mode table output for Stringy.
//!
//! This module provides formatted table output with aligned columns for terminal display.

use crate::types::{FoundString, Result};

use super::formatting::{Alignment, format_tags, pad_string, truncate_string};
use super::{
    OutputMetadata, SCORE_COLUMN_WIDTH, SECTION_COLUMN_WIDTH, STRING_COLUMN_WIDTH,
    TAGS_COLUMN_WIDTH,
};

/// Format strings as an aligned table for TTY output.
///
/// Creates a table with headers and aligned columns showing:
/// - String text (truncated if necessary)
/// - Tags (comma-separated, limited count)
/// - Score (right-aligned)
/// - Section name
pub(super) fn format_table_tty(
    strings: &[FoundString],
    _metadata: &OutputMetadata,
) -> Result<String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::table::format_table_with_mode;
    use crate::output::table::test_helpers::{make_metadata, make_test_string};
    use crate::types::Tag;

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
    fn missing_optional_fields_handled() {
        // String with no section, no tags, default score
        let found = make_test_string("minimal");

        let result = format_table_with_mode(&[found], &make_metadata(), true).unwrap();
        // Should not crash and should contain the string
        assert!(result.contains("minimal"));
    }

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
