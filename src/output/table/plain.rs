//! Plain text output for non-TTY environments.
//!
//! This module provides simple one-string-per-line output suitable for piping
//! to other command-line tools like grep, awk, or sed.

use crate::types::{FoundString, Result};

/// Format strings as plain text for non-TTY output.
///
/// Outputs only the string text, one per line, suitable for piping to other tools.
pub(super) fn format_table_plain(strings: &[FoundString]) -> Result<String> {
    let lines: Vec<String> = strings
        .iter()
        .map(|s| sanitize_plain_text(&s.text))
        .collect();
    Ok(lines.join("\n"))
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

#[cfg(test)]
mod tests {
    use crate::output::table::format_table_with_mode;
    use crate::output::table::test_helpers::{make_metadata, make_test_string};

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
    fn long_string_not_truncated_in_plain() {
        let long_text = "a".repeat(100);
        let strings = vec![make_test_string(&long_text)];
        let result = format_table_with_mode(&strings, &make_metadata(), false).unwrap();

        // Plain mode should have full string
        assert_eq!(result, long_text);
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

    #[test]
    fn string_with_crlf() {
        let strings = vec![make_test_string("line1\r\nline2")];
        let result = format_table_with_mode(&strings, &make_metadata(), false).unwrap();
        assert_eq!(result, "line1\\r\\nline2");
    }

    #[test]
    fn string_with_cr() {
        let strings = vec![make_test_string("line1\rline2")];
        let result = format_table_with_mode(&strings, &make_metadata(), false).unwrap();
        assert_eq!(result, "line1\\rline2");
    }
}
