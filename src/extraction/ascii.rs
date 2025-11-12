//! ASCII String Extraction Module
//!
//! This module provides foundational ASCII string extraction functionality for StringyMcStringFace.
//! It implements byte-level scanning for contiguous printable ASCII sequences and serves as the
//! reference implementation for future UTF-8, UTF-16LE, and UTF-16BE extractors.
//!
//! # Examples
//!
//! ## Basic ASCII String Extraction
//!
//! ```rust
//! use stringy::extraction::ascii::{extract_ascii_strings, ExtractionConfig as AsciiConfig};
//!
//! let data = b"Hello\0World\0Test123";
//! let config = AsciiConfig::default();
//! let strings = extract_ascii_strings(data, &config);
//!
//! for string in strings {
//!     println!("Found: {} at offset {}", string.text, string.offset);
//! }
//! ```
//!
//! ## Section-Aware Extraction
//!
//! ```rust
//! use stringy::extraction::ascii::{extract_from_section, ExtractionConfig as AsciiConfig};
//! use stringy::types::{SectionInfo, SectionType};
//!
//! let section = SectionInfo {
//!     name: ".rodata".to_string(),
//!     offset: 100,
//!     size: 50,
//!     rva: Some(0x1000),
//!     section_type: SectionType::StringData,
//!     is_executable: false,
//!     is_writable: false,
//!     weight: 1.0,
//! };
//!
//! let data = b"prefix\0Hello World\0suffix";
//! let config = AsciiConfig::default();
//! let strings = extract_from_section(&section, data, &config);
//!
//! // Strings will have section metadata populated
//! for string in strings {
//!     assert_eq!(string.section, Some(".rodata".to_string()));
//! }
//! ```
//!
//! ## Custom Configuration
//!
//! ```rust
//! use stringy::extraction::ascii::{extract_ascii_strings, ExtractionConfig as AsciiConfig};
//!
//! // Extract only strings between 8 and 100 bytes
//! let config = AsciiConfig {
//!     min_length: 8,
//!     max_length: Some(100),
//! };
//!
//! let data = b"Short\0MediumString\0VeryLongStringHere";
//! let strings = extract_ascii_strings(data, &config);
//! // Only "MediumString" will be extracted
//! ```

use crate::types::{Encoding, FoundString, SectionInfo, StringSource};

/// Configuration for ASCII string extraction
///
/// Controls minimum and maximum string length filtering during extraction.
/// This structure serves as the foundation for future configuration expansion
/// (encoding preferences, tag filters, etc.) as mentioned in the issue.
///
/// # Default Values
///
/// - `min_length`: 4 (standard minimum to reduce noise)
/// - `max_length`: None (no upper limit by default)
///
/// # Examples
///
/// ```rust
/// use stringy::extraction::ascii::ExtractionConfig as AsciiConfig;
///
/// // Use default configuration
/// let config = AsciiConfig::default();
///
/// // Custom minimum length
/// let config = AsciiConfig::new(8);
///
/// // Custom minimum and maximum length
/// let config = AsciiConfig {
///     min_length: 5,
///     max_length: Some(256),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractionConfig {
    /// Minimum string length in bytes (default: 4)
    pub min_length: usize,
    /// Maximum string length in bytes (default: None, no limit)
    pub max_length: Option<usize>,
}

impl Default for ExtractionConfig {
    fn default() -> Self {
        Self {
            min_length: 4,
            max_length: None,
        }
    }
}

impl ExtractionConfig {
    /// Create a new `ExtractionConfig` with custom minimum length
    ///
    /// The maximum length will be set to `None` (no limit).
    ///
    /// # Arguments
    ///
    /// * `min_length` - Minimum string length in bytes
    ///
    /// # Examples
    ///
    /// ```rust
    /// use stringy::extraction::ascii::ExtractionConfig as AsciiConfig;
    ///
    /// let config = AsciiConfig::new(8);
    /// assert_eq!(config.min_length, 8);
    /// assert_eq!(config.max_length, None);
    /// ```
    pub fn new(min_length: usize) -> Self {
        Self {
            min_length,
            max_length: None,
        }
    }
}

/// Check if a byte is in the printable ASCII range
///
/// Printable ASCII includes characters from 0x20 (space) through 0x7E (tilde).
/// This range covers all standard printable ASCII characters.
///
/// **Note**: This function only considers the strict printable ASCII range (0x20-0x7E).
/// Unlike the UTF-8-capable `is_printable_ascii` helper in `extraction::mod.rs`, this
/// function does NOT include common whitespace characters like tab (0x09), newline (0x0A),
/// or carriage return (0x0D). This ensures ASCII-only extraction produces consistent,
/// predictable results without including control characters that may appear in binary data.
///
/// # Arguments
///
/// * `byte` - The byte to check
///
/// # Returns
///
/// `true` if the byte is printable ASCII, `false` otherwise
///
/// # Examples
///
/// ```rust
/// use stringy::extraction::ascii::is_printable_ascii;
///
/// assert!(is_printable_ascii(b' '));
/// assert!(is_printable_ascii(b'A'));
/// assert!(is_printable_ascii(b'z'));
/// assert!(is_printable_ascii(b'0'));
/// assert!(is_printable_ascii(b'~'));
/// assert!(!is_printable_ascii(0x00));
/// assert!(!is_printable_ascii(0x1F));
/// assert!(!is_printable_ascii(0x7F));
/// ```
#[inline]
pub fn is_printable_ascii(byte: u8) -> bool {
    (0x20..=0x7E).contains(&byte)
}

/// Extract ASCII strings from a byte slice
///
/// Scans through the byte slice looking for contiguous sequences of printable
/// ASCII characters. When a non-printable byte is encountered, checks if the
/// accumulated sequence meets the minimum length threshold and creates a
/// `FoundString` entry if it does.
///
/// **Note on StringSource**: This function performs raw byte-level scanning without
/// section context, but currently uses `StringSource::SectionData` as the source type.
/// A more appropriate variant (e.g., `StringSource::RawData`) may be added in a future
/// update to better distinguish raw scans from section-aware extraction.
///
/// # Arguments
///
/// * `data` - Byte slice to scan for ASCII strings
/// * `config` - Extraction configuration (minimum/maximum length)
///
/// # Returns
///
/// Vector of `FoundString` entries with the following metadata:
/// - `text`: UTF-8 string from accumulated bytes
/// - `encoding`: `Encoding::Ascii`
/// - `offset`: Start position in the data slice (relative offset)
/// - `length`: Byte count of the string
/// - `source`: `StringSource::SectionData` (see note above)
/// - `section`: `None` (use `extract_from_section` for section metadata)
/// - `rva`: `None` (use `extract_from_section` for RVA)
/// - `tags`: Empty vector
/// - `score`: 0
///
/// # Algorithm
///
/// 1. Iterate through the byte slice tracking current string start position and accumulated bytes
/// 2. When encountering a printable ASCII byte, accumulate it in the current string buffer
/// 3. When encountering a non-printable byte, check if accumulated length meets minimum threshold
/// 4. If threshold met, create a `FoundString` with proper metadata
/// 5. Handle end-of-buffer edge case by checking accumulated string after loop completes
/// 6. Apply max_length filtering if configured
///
/// # Examples
///
/// ```rust
/// use stringy::extraction::ascii::{extract_ascii_strings, ExtractionConfig as AsciiConfig};
///
/// let data = b"Hello\0World\0Test123";
/// let config = AsciiConfig::default();
/// let strings = extract_ascii_strings(data, &config);
///
/// assert_eq!(strings.len(), 3);
/// assert_eq!(strings[0].text, "Hello");
/// assert_eq!(strings[0].offset, 0);
/// assert_eq!(strings[1].text, "World");
/// assert_eq!(strings[1].offset, 6);
/// ```
pub fn extract_ascii_strings(data: &[u8], config: &ExtractionConfig) -> Vec<FoundString> {
    let mut strings = Vec::new();
    let mut current_string_start: Option<usize> = None;
    let mut current_string_bytes = Vec::new();

    for (i, &byte) in data.iter().enumerate() {
        if is_printable_ascii(byte) {
            if current_string_start.is_none() {
                current_string_start = Some(i);
            }
            current_string_bytes.push(byte);
        } else {
            // End of current string candidate
            if let Some(start) = current_string_start {
                let len = current_string_bytes.len();

                // Check minimum length
                if len >= config.min_length {
                    // Check maximum length if configured
                    let within_max = config.max_length.is_none_or(|max| len <= max);

                    if within_max {
                        // Move buffer out to avoid cloning
                        let bytes = std::mem::take(&mut current_string_bytes);
                        // Convert to UTF-8 string (ASCII is valid UTF-8)
                        if let Ok(text) = String::from_utf8(bytes) {
                            strings.push(FoundString {
                                text,
                                encoding: Encoding::Ascii,
                                offset: start as u64,
                                length: len as u32,
                                source: StringSource::SectionData,
                                section: None,
                                rva: None,
                                tags: Vec::new(),
                                score: 0,
                            });
                        }
                    }
                }
            }
            current_string_start = None;
            current_string_bytes.clear();
        }
    }

    // Handle string at end of buffer
    if let Some(start) = current_string_start {
        let len = current_string_bytes.len();

        // Check minimum length
        if len >= config.min_length {
            // Check maximum length if configured
            let within_max = config.max_length.is_none_or(|max| len <= max);

            if within_max {
                // Move buffer out to avoid cloning
                let bytes = std::mem::take(&mut current_string_bytes);
                // Convert to UTF-8 string (ASCII is valid UTF-8)
                if let Ok(text) = String::from_utf8(bytes) {
                    strings.push(FoundString {
                        text,
                        encoding: Encoding::Ascii,
                        offset: start as u64,
                        length: len as u32,
                        source: StringSource::SectionData,
                        section: None,
                        rva: None,
                        tags: Vec::new(),
                        score: 0,
                    });
                }
            }
        }
    }

    strings
}

/// Extract ASCII strings from a specific section with proper metadata population
///
/// This is a section-aware wrapper around `extract_ascii_strings` that:
/// 1. Calculates the section data slice using section.offset and section.size
/// 2. Calls `extract_ascii_strings` on the section data slice
/// 3. Post-processes each FoundString to adjust offsets (add section.offset)
/// 4. Populates section field with section.name
/// 5. Populates rva field with calculated value (section.rva + relative_offset) if section.rva is Some
///
/// # Arguments
///
/// * `section` - Section metadata containing offset, size, name, and optional RVA
/// * `data` - Full binary data
/// * `config` - Extraction configuration
///
/// # Returns
///
/// Vector of `FoundString` entries with complete metadata including:
/// - Absolute file offsets (section.offset + relative_offset)
/// - Section names
/// - RVA values (if section.rva is available)
///
/// # Edge Cases
///
/// - Empty input data: returns empty vector
/// - Data smaller than minimum length: returns empty vector
/// - Section boundaries: ensures slice doesn't exceed data.len()
/// - Section offset + size overflow: uses checked arithmetic
///
/// # Examples
///
/// ```rust
/// use stringy::extraction::ascii::{extract_from_section, ExtractionConfig as AsciiConfig};
/// use stringy::types::{SectionInfo, SectionType};
///
/// let section = SectionInfo {
///     name: ".rodata".to_string(),
///     offset: 100,
///     size: 50,
///     rva: Some(0x1000),
///     section_type: SectionType::StringData,
///     is_executable: false,
///     is_writable: false,
///     weight: 1.0,
/// };
///
/// let data = b"prefix\0Hello World\0suffix";
/// let config = AsciiConfig::default();
/// let strings = extract_from_section(&section, data, &config);
///
/// // Strings will have absolute offsets and section metadata
/// for string in strings {
///     assert!(string.offset >= section.offset);
///     assert_eq!(string.section, Some(".rodata".to_string()));
/// }
/// ```
pub fn extract_from_section(
    section: &SectionInfo,
    data: &[u8],
    config: &ExtractionConfig,
) -> Vec<FoundString> {
    // Early return for zero-sized sections
    if section.size == 0 {
        return Vec::new();
    }

    // Calculate section data slice with bounds checking
    let section_offset = section.offset as usize;
    let section_size = section.size as usize;

    // Check if section offset is beyond data length
    if section_offset >= data.len() {
        return Vec::new();
    }

    // Calculate end offset with overflow protection
    let end_offset = section_offset
        .checked_add(section_size)
        .unwrap_or(data.len())
        .min(data.len());

    // Extract section data slice
    let section_data = &data[section_offset..end_offset];

    // Extract strings from section data
    let mut strings = extract_ascii_strings(section_data, config);

    // Post-process: adjust offsets and populate metadata
    for string in &mut strings {
        // Adjust offset: add section.offset to relative offset
        string.offset += section.offset;

        // Populate section name
        string.section = Some(section.name.clone());

        // Populate RVA if section has RVA
        if let Some(section_rva) = section.rva {
            // Calculate relative offset within section
            let relative_offset = string.offset - section.offset;
            string.rva = Some(section_rva + relative_offset);
        }
    }

    strings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SectionType;

    #[test]
    fn test_is_printable_ascii() {
        // Printable ASCII range
        assert!(is_printable_ascii(0x20)); // space
        assert!(is_printable_ascii(0x21)); // !
        assert!(is_printable_ascii(0x41)); // A
        assert!(is_printable_ascii(0x5A)); // Z
        assert!(is_printable_ascii(0x61)); // a
        assert!(is_printable_ascii(0x7A)); // z
        assert!(is_printable_ascii(0x30)); // 0
        assert!(is_printable_ascii(0x39)); // 9
        assert!(is_printable_ascii(0x7E)); // ~

        // Non-printable
        assert!(!is_printable_ascii(0x00));
        assert!(!is_printable_ascii(0x1F));
        assert!(!is_printable_ascii(0x7F));
        assert!(!is_printable_ascii(0x80));
        assert!(!is_printable_ascii(0xFF));
    }

    #[test]
    fn test_extract_ascii_strings_basic() {
        let data = b"Hello\0World\0Test123";
        let config = ExtractionConfig::default();
        let strings = extract_ascii_strings(data, &config);

        assert_eq!(strings.len(), 3);
        assert_eq!(strings[0].text, "Hello");
        assert_eq!(strings[0].offset, 0);
        assert_eq!(strings[0].length, 5);
        assert_eq!(strings[0].encoding, Encoding::Ascii);
        assert_eq!(strings[0].source, StringSource::SectionData);

        assert_eq!(strings[1].text, "World");
        assert_eq!(strings[1].offset, 6);
        assert_eq!(strings[1].length, 5);

        assert_eq!(strings[2].text, "Test123");
        assert_eq!(strings[2].offset, 12);
        assert_eq!(strings[2].length, 7);
    }

    #[test]
    fn test_extract_ascii_strings_custom_min_length() {
        let data = b"Hi\0Test\0AB\0LongString";
        let config = ExtractionConfig::new(3);
        let strings = extract_ascii_strings(data, &config);

        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].text, "Test");
        assert_eq!(strings[1].text, "LongString");
    }

    #[test]
    fn test_extract_ascii_strings_min_length_5() {
        let data = b"Hi\0Test\0AB\0LongString";
        let config = ExtractionConfig::new(5);
        let strings = extract_ascii_strings(data, &config);

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].text, "LongString");
    }

    #[test]
    fn test_extract_ascii_strings_min_length_10() {
        let data = b"Short\0Medium\0VeryLongString";
        let config = ExtractionConfig::new(10);
        let strings = extract_ascii_strings(data, &config);

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].text, "VeryLongString");
    }

    #[test]
    fn test_extract_ascii_strings_empty_input() {
        let data = b"";
        let config = ExtractionConfig::default();
        let strings = extract_ascii_strings(data, &config);

        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_ascii_strings_no_strings_found() {
        let data = &[0x00, 0xFF, 0x01, 0x02, 0x03];
        let config = ExtractionConfig::default();
        let strings = extract_ascii_strings(data, &config);

        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_ascii_strings_string_at_buffer_start() {
        let data = b"Start\0Middle\0End";
        let config = ExtractionConfig::new(3);
        let strings = extract_ascii_strings(data, &config);

        assert_eq!(strings.len(), 3);
        assert_eq!(strings[0].text, "Start");
        assert_eq!(strings[0].offset, 0);
    }

    #[test]
    fn test_extract_ascii_strings_string_at_buffer_end() {
        let data = b"Start\0Middle\0EndTest";
        let config = ExtractionConfig::default();
        let strings = extract_ascii_strings(data, &config);

        assert_eq!(strings.len(), 3);
        assert_eq!(strings[2].text, "EndTest");
        assert_eq!(strings[2].offset, 13);
    }

    #[test]
    fn test_extract_ascii_strings_single_char_below_minimum() {
        let data = b"A\0B\0C\0Test";
        let config = ExtractionConfig::default();
        let strings = extract_ascii_strings(data, &config);

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].text, "Test");
    }

    #[test]
    fn test_extract_ascii_strings_exact_minimum_length() {
        let data = b"Test\0ABCD";
        let config = ExtractionConfig::default();
        let strings = extract_ascii_strings(data, &config);

        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].text, "Test");
        assert_eq!(strings[0].length, 4);
        assert_eq!(strings[1].text, "ABCD");
        assert_eq!(strings[1].length, 4);
    }

    #[test]
    fn test_extract_ascii_strings_offset_calculation() {
        let data = b"First\0Second\0Third";
        let config = ExtractionConfig::default();
        let strings = extract_ascii_strings(data, &config);

        assert_eq!(strings[0].offset, 0);
        assert_eq!(strings[1].offset, 6);
        assert_eq!(strings[2].offset, 13);
    }

    #[test]
    fn test_extract_ascii_strings_max_length_filtering() {
        let data = b"Short\0VeryLongStringHere\0Medium";
        let config = ExtractionConfig {
            min_length: 4,
            max_length: Some(10),
        };
        let strings = extract_ascii_strings(data, &config);

        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].text, "Short");
        assert_eq!(strings[1].text, "Medium");
        assert!(!strings.iter().any(|s| s.text == "VeryLongStringHere"));
    }

    #[test]
    fn test_extract_ascii_strings_max_length_exact() {
        let data = b"Exactly10\0TooLongString";
        let config = ExtractionConfig {
            min_length: 4,
            max_length: Some(10),
        };
        let strings = extract_ascii_strings(data, &config);

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].text, "Exactly10");
    }

    #[test]
    fn test_extract_ascii_strings_multiple_strings_sequence() {
        // Use min_length=3 to test extraction of 3-character strings ("One", "Two")
        // which would be filtered out by the default min_length=4
        let data = b"One\0Two\0Three\0Four";
        let config = ExtractionConfig::new(3);
        let strings = extract_ascii_strings(data, &config);

        assert_eq!(strings.len(), 4);
        assert_eq!(strings[0].text, "One");
        assert_eq!(strings[1].text, "Two");
        assert_eq!(strings[2].text, "Three");
        assert_eq!(strings[3].text, "Four");
    }

    #[test]
    fn test_extract_ascii_strings_separated_by_single_byte() {
        let data = b"First\x01Second\x02Third";
        let config = ExtractionConfig::default();
        let strings = extract_ascii_strings(data, &config);

        assert_eq!(strings.len(), 3);
        assert_eq!(strings[0].text, "First");
        assert_eq!(strings[1].text, "Second");
        assert_eq!(strings[2].text, "Third");
    }

    #[test]
    fn test_extract_ascii_strings_very_long_string() {
        let long_string = "A".repeat(1000);
        let data = format!("{}\0Test", long_string).into_bytes();
        let config = ExtractionConfig {
            min_length: 4,
            max_length: Some(100),
        };
        let strings = extract_ascii_strings(&data, &config);

        // Very long string should be filtered out by max_length
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].text, "Test");
    }

    #[test]
    fn test_extract_from_section_basic() {
        let section = SectionInfo {
            name: ".rodata".to_string(),
            offset: 0,
            size: 20,
            rva: Some(0x1000),
            section_type: SectionType::StringData,
            is_executable: false,
            is_writable: false,
            weight: 1.0,
        };

        let data = b"Hello World\0Test";
        let config = ExtractionConfig::default();
        let strings = extract_from_section(&section, data, &config);

        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].text, "Hello World");
        assert_eq!(strings[0].offset, 0);
        assert_eq!(strings[0].section, Some(".rodata".to_string()));
        assert_eq!(strings[0].rva, Some(0x1000));
        assert_eq!(strings[1].text, "Test");
        assert_eq!(strings[1].offset, 12);
        assert_eq!(strings[1].rva, Some(0x100C));
    }

    #[test]
    fn test_extract_from_section_with_offset() {
        let section = SectionInfo {
            name: ".data".to_string(),
            offset: 100,
            size: 20,
            rva: Some(0x2000),
            section_type: SectionType::WritableData,
            is_executable: false,
            is_writable: true,
            weight: 0.5,
        };

        let mut data = vec![0u8; 120];
        let test_data = b"Hello\0World";
        data[100..100 + test_data.len()].copy_from_slice(test_data);
        let config = ExtractionConfig::default();
        let strings = extract_from_section(&section, &data, &config);

        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].text, "Hello");
        assert_eq!(strings[0].offset, 100);
        assert_eq!(strings[0].section, Some(".data".to_string()));
        assert_eq!(strings[0].rva, Some(0x2000));
        assert_eq!(strings[1].text, "World");
        assert_eq!(strings[1].offset, 106);
        assert_eq!(strings[1].rva, Some(0x2006));
    }

    #[test]
    fn test_extract_from_section_section_metadata() {
        let section = SectionInfo {
            name: ".text".to_string(),
            offset: 50,
            size: 30,
            rva: Some(0x3000),
            section_type: SectionType::Code,
            is_executable: true,
            is_writable: false,
            weight: 0.1,
        };

        let mut data = vec![0u8; 80];
        let test_data = b"TestString\0Another";
        data[50..50 + test_data.len()].copy_from_slice(test_data);
        let config = ExtractionConfig::default();
        let strings = extract_from_section(&section, &data, &config);

        for string in &strings {
            assert_eq!(string.section, Some(".text".to_string()));
            assert!(string.offset >= section.offset);
            if let Some(rva) = string.rva {
                assert!(rva >= section.rva.unwrap());
            }
        }
    }

    #[test]
    fn test_extract_from_section_no_rva() {
        let section = SectionInfo {
            name: ".rodata".to_string(),
            offset: 0,
            size: 15,
            rva: None,
            section_type: SectionType::StringData,
            is_executable: false,
            is_writable: false,
            weight: 1.0,
        };

        let data = b"Hello\0World";
        let config = ExtractionConfig::default();
        let strings = extract_from_section(&section, data, &config);

        assert_eq!(strings.len(), 2);
        for string in &strings {
            assert_eq!(string.rva, None);
            assert_eq!(string.section, Some(".rodata".to_string()));
        }
    }

    #[test]
    fn test_extract_from_section_empty_section() {
        let section = SectionInfo {
            name: ".empty".to_string(),
            offset: 0,
            size: 0,
            rva: None,
            section_type: SectionType::Other,
            is_executable: false,
            is_writable: false,
            weight: 0.0,
        };

        let data = b"Some data";
        let config = ExtractionConfig::default();
        let strings = extract_from_section(&section, data, &config);

        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_from_section_section_boundaries() {
        let section = SectionInfo {
            name: ".data".to_string(),
            offset: 10,
            size: 15,
            rva: Some(0x1000),
            section_type: SectionType::WritableData,
            is_executable: false,
            is_writable: true,
            weight: 0.5,
        };

        let data = b"prefix\0Hello World\0suffix";
        let config = ExtractionConfig::default();
        let strings = extract_from_section(&section, data, &config);

        // Should only extract strings within section boundaries
        for string in &strings {
            assert!(string.offset >= section.offset);
            assert!(string.offset < section.offset + section.size);
        }
    }

    #[test]
    fn test_extract_from_section_out_of_bounds() {
        let section = SectionInfo {
            name: ".invalid".to_string(),
            offset: 1000,
            size: 100,
            rva: None,
            section_type: SectionType::Other,
            is_executable: false,
            is_writable: false,
            weight: 0.0,
        };

        let data = b"small data";
        let config = ExtractionConfig::default();
        let strings = extract_from_section(&section, data, &config);

        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_from_section_overflow_protection() {
        let section = SectionInfo {
            name: ".overflow".to_string(),
            offset: u64::MAX - 10,
            size: 100,
            rva: None,
            section_type: SectionType::Other,
            is_executable: false,
            is_writable: false,
            weight: 0.0,
        };

        let data = b"test data";
        let config = ExtractionConfig::default();
        let strings = extract_from_section(&section, data, &config);

        // Should handle overflow gracefully
        assert!(strings.is_empty());
    }

    #[test]
    fn test_extraction_config_default() {
        let config = ExtractionConfig::default();
        assert_eq!(config.min_length, 4);
        assert_eq!(config.max_length, None);
    }

    #[test]
    fn test_extraction_config_new() {
        let config = ExtractionConfig::new(8);
        assert_eq!(config.min_length, 8);
        assert_eq!(config.max_length, None);
    }

    #[test]
    fn test_extraction_config_custom() {
        let config = ExtractionConfig {
            min_length: 5,
            max_length: Some(256),
        };
        assert_eq!(config.min_length, 5);
        assert_eq!(config.max_length, Some(256));
    }
}
