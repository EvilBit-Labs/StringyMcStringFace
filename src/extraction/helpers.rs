//! Helper functions for string extraction
//!
//! This module contains utility functions used by the extraction framework:
//!
//! - [`apply_semantic_enrichment`]: Applies semantic tagging and symbol demangling
//! - [`extract_ascii_utf8_strings`]: Extracts ASCII/UTF-8 strings from raw bytes
//! - [`is_printable_text_byte`]: Checks if a byte is printable ASCII text
//! - [`could_be_utf8_byte`]: Checks if a byte could be part of a UTF-8 sequence

use crate::classification::{SemanticClassifier, SymbolDemangler};
use crate::types::{ContainerInfo, FoundString, SectionInfo, SectionType, StringContext};

/// Apply semantic enrichment (classification and demangling) to extracted strings
///
/// Iterates over the extracted strings, applying symbol demangling and semantic
/// classification based on the container format and section context.
pub(super) fn apply_semantic_enrichment(
    strings: &mut [FoundString],
    container_info: &ContainerInfo,
) {
    let classifier = SemanticClassifier::new();
    let demangler = SymbolDemangler::new();

    // Build a map from section name to SectionInfo for fast lookup
    let section_map: std::collections::HashMap<&str, &SectionInfo> = container_info
        .sections
        .iter()
        .map(|s| (s.name.as_str(), s))
        .collect();

    for string in strings {
        demangler.demangle(string);

        // Look up section info to get real section_type
        let section_type = string
            .section
            .as_ref()
            .and_then(|name| section_map.get(name.as_str()))
            .map(|info| info.section_type)
            .unwrap_or(SectionType::Other);

        let context = StringContext::new(
            section_type,
            container_info.format,
            string.encoding,
            string.source,
        );
        let context = match &string.section {
            Some(name) => context.with_section_name(name.clone()),
            None => context,
        };
        let tags = classifier.classify(&string.text, &context);
        for tag in tags {
            if !string.tags.contains(&tag) {
                string.tags.push(tag);
            }
        }
    }
}

/// Check if a byte is printable text (ASCII or common whitespace)
///
/// Printable text includes characters from 0x20 (space) to 0x7E (~),
/// plus common whitespace characters: tab (0x09), newline (0x0A), and
/// carriage return (0x0D).
///
/// **Note on printable character definitions**: This function is used by the UTF-8-capable
/// extraction helpers and includes common whitespace characters (tab, newline, carriage return)
/// to handle text files and formatted data. This differs from the ASCII-only `is_printable_ascii`
/// function in `extraction::ascii`, which only considers the strict printable range (0x20-0x7E)
/// without whitespace control characters. This difference ensures that:
/// - ASCII-only extraction (`extraction::ascii`) produces strict, predictable results
/// - UTF-8-capable extraction (this module) can handle formatted text with line breaks
///
/// When using both extractors on the same data, be aware that they may produce different
/// results due to this definitional difference.
pub(crate) fn is_printable_text_byte(byte: u8) -> bool {
    matches!(byte, 0x09 | 0x0A | 0x0D | 0x20..=0x7E)
}

/// Check if a byte could be part of a valid UTF-8 sequence
///
/// This includes printable ASCII, UTF-8 continuation bytes (0x80-0xBF),
/// and UTF-8 start bytes (0xC2-0xF4 for valid UTF-8 sequences).
pub(crate) fn could_be_utf8_byte(byte: u8) -> bool {
    is_printable_text_byte(byte) || matches!(byte, 0x80..=0xBF | 0xC2..=0xF4)
}

/// Extract ASCII and UTF-8 strings from byte data
///
/// Scans through the byte data looking for sequences of printable characters
/// and valid UTF-8 sequences. When a byte that cannot be part of a valid
/// string is encountered, checks if the accumulated sequence meets the minimum
/// length requirement and validates it as UTF-8. Strings exceeding max_length
/// are skipped during extraction.
///
/// # Arguments
///
/// * `data` - Byte slice to scan
/// * `min_length` - Minimum string length in bytes
/// * `max_length` - Maximum string length in bytes
///
/// # Returns
///
/// Vector of tuples containing (text, relative_offset, length)
pub(super) fn extract_ascii_utf8_strings(
    data: &[u8],
    min_length: usize,
    max_length: usize,
) -> Vec<(String, usize, usize)> {
    let mut strings = Vec::new();
    let mut current_string_start: Option<usize> = None;
    let mut current_string_bytes = Vec::new();

    for (i, &byte) in data.iter().enumerate() {
        if could_be_utf8_byte(byte) {
            if current_string_start.is_none() {
                current_string_start = Some(i);
            }
            current_string_bytes.push(byte);
        } else {
            // End of current string candidate
            // Check length conditions first, then extract start to avoid borrow checker issues
            // Separate if blocks needed: collapsing would cause borrow checker errors with std::mem::take
            #[allow(clippy::collapsible_if)]
            if current_string_bytes.len() >= min_length && current_string_bytes.len() <= max_length
            {
                if let Some(start) = current_string_start {
                    // Store length before moving
                    let len = current_string_bytes.len();
                    // Move buffer out to avoid cloning
                    let bytes = std::mem::take(&mut current_string_bytes);
                    // Try to convert to UTF-8 string
                    match String::from_utf8(bytes) {
                        Ok(text) => {
                            // Create entry tuple to move text into it explicitly
                            let entry = (text, start, len);
                            strings.push(entry);
                        }
                        Err(_) => {
                            // Invalid UTF-8, skip this candidate
                        }
                    }
                }
            }
            current_string_start = None;
            current_string_bytes.clear();
        }
    }

    // Handle string at end of data
    // Separate if blocks needed: collapsing would cause borrow checker errors with std::mem::take
    #[allow(clippy::collapsible_if)]
    if current_string_bytes.len() >= min_length && current_string_bytes.len() <= max_length {
        if let Some(start) = current_string_start {
            // Store length before moving
            let len = current_string_bytes.len();
            // Move buffer out to avoid cloning
            let bytes = std::mem::take(&mut current_string_bytes);
            match String::from_utf8(bytes) {
                Ok(text) => {
                    // Create entry tuple to move text into it explicitly
                    let entry = (text, start, len);
                    strings.push(entry);
                }
                Err(_) => {
                    // Invalid UTF-8, skip
                }
            }
        }
    }

    strings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_printable_text_byte() {
        // Printable ASCII
        assert!(is_printable_text_byte(b' '));
        assert!(is_printable_text_byte(b'A'));
        assert!(is_printable_text_byte(b'z'));
        assert!(is_printable_text_byte(b'0'));
        assert!(is_printable_text_byte(b'9'));
        assert!(is_printable_text_byte(b'~'));

        // Common whitespace
        assert!(is_printable_text_byte(b'\t'));
        assert!(is_printable_text_byte(b'\n'));
        assert!(is_printable_text_byte(b'\r'));

        // Non-printable
        assert!(!is_printable_text_byte(0x00));
        assert!(!is_printable_text_byte(0x1F));
        assert!(!is_printable_text_byte(0x7F));
        assert!(!is_printable_text_byte(0xFF));
    }

    #[test]
    fn test_extract_ascii_utf8_strings() {
        // Test with ASCII strings
        let data = b"Hello\0World\0Test123";
        let strings = extract_ascii_utf8_strings(data, 4, 4096);
        assert_eq!(strings.len(), 3);
        assert_eq!(strings[0].0, "Hello");
        assert_eq!(strings[0].1, 0);
        assert_eq!(strings[1].0, "World");
        assert_eq!(strings[1].1, 6);
        assert_eq!(strings[2].0, "Test123");
        assert_eq!(strings[2].1, 12);
    }

    #[test]
    fn test_extract_ascii_utf8_strings_utf8() {
        // Test with UTF-8 strings
        let data = "Hello \u{4e16}\u{754c}\0Test".as_bytes();
        let strings = extract_ascii_utf8_strings(data, 4, 4096);
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].0, "Hello \u{4e16}\u{754c}");
        assert_eq!(strings[1].0, "Test");
    }

    #[test]
    fn test_extract_ascii_utf8_strings_min_length() {
        // Test minimum length filtering
        let data = b"Hi\0Test\0AB\0LongString";
        let strings = extract_ascii_utf8_strings(data, 4, 4096);
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].0, "Test");
        assert_eq!(strings[1].0, "LongString");
    }

    #[test]
    fn test_extract_ascii_utf8_strings_empty() {
        // Test with empty data
        let data = b"";
        let strings = extract_ascii_utf8_strings(data, 4, 4096);
        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_ascii_utf8_strings_binary() {
        // Test with binary data
        let data = &[0x00, 0xFF, 0x01, 0x02, 0x03];
        let strings = extract_ascii_utf8_strings(data, 4, 4096);
        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_ascii_utf8_strings_at_boundaries() {
        // Test strings at start and end
        let data = b"Start\0Middle\0EndTest";
        let strings = extract_ascii_utf8_strings(data, 4, 4096);
        assert_eq!(strings.len(), 3);
        assert_eq!(strings[0].0, "Start");
        assert_eq!(strings[0].1, 0);
        assert_eq!(strings[2].0, "EndTest");
    }

    #[test]
    fn test_extract_ascii_utf8_strings_max_length() {
        // Test maximum length filtering in helper
        let data = b"Short\0VeryLongStringHere";
        let strings = extract_ascii_utf8_strings(data, 4, 10);
        // Only "Short" should pass max_length filter
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].0, "Short");
        assert!(!strings.iter().any(|s| s.0 == "VeryLongStringHere"));
    }
}
