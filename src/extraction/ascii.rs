//! ASCII String Extraction Module
//!
//! This module provides foundational ASCII string extraction for Stringy.
//! It implements byte-level scanning for contiguous printable ASCII sequences and serves
//! as the reference implementation for future UTF-8, UTF-16LE, and UTF-16BE extractors.
//!
//! # Examples
//!
//! ```rust
//! use stringy::extraction::ascii::{extract_ascii_strings, extract_from_section, AsciiExtractionConfig};
//! use stringy::types::{SectionInfo, SectionType};
//!
//! // Basic extraction from raw data
//! let data = b"Hello\0World\0Test123";
//! let config = AsciiExtractionConfig::default();
//! let strings = extract_ascii_strings(data, &config);
//!
//! // Section-aware extraction
//! let section = SectionInfo {
//!     name: ".rodata".to_string(),
//!     offset: 0,
//!     size: 20,
//!     rva: Some(0x1000),
//!     section_type: SectionType::StringData,
//!     is_executable: false,
//!     is_writable: false,
//!     weight: 1.0,
//! };
//! let strings = extract_from_section(&section, data, &config);
//! ```

use crate::extraction::config::NoiseFilterConfig;
use crate::extraction::filters::{CompositeNoiseFilter, FilterContext};
use crate::types::{Encoding, FoundString, SectionInfo, StringSource};

/// Configuration for ASCII string extraction
///
/// Controls minimum and maximum string length filtering. This structure serves as the
/// foundation for future configuration expansion, including encoding preferences and
/// tag filters as mentioned in the issue.
///
/// # Default Values
///
/// - `min_length`: 4 (standard minimum to reduce noise)
/// - `max_length`: None (no upper limit by default)
///
/// # Examples
///
/// ```rust
/// use stringy::extraction::ascii::AsciiExtractionConfig;
///
/// // Use default configuration
/// let config = AsciiExtractionConfig::default();
///
/// // Custom minimum length
/// let config = AsciiExtractionConfig::new(8);
///
/// // Custom minimum and maximum length
/// let mut config = AsciiExtractionConfig::default();
/// config.max_length = Some(256);
/// ```
#[derive(Debug, Clone)]
pub struct AsciiExtractionConfig {
    /// Minimum string length in bytes (default: 4)
    pub min_length: usize,
    /// Maximum string length in bytes (default: None, no limit)
    pub max_length: Option<usize>,
}

impl Default for AsciiExtractionConfig {
    fn default() -> Self {
        Self {
            min_length: 4,
            max_length: None,
        }
    }
}

impl AsciiExtractionConfig {
    /// Create a new AsciiExtractionConfig with custom minimum length
    ///
    /// # Arguments
    ///
    /// * `min_length` - Minimum string length in bytes
    ///
    /// # Returns
    ///
    /// New AsciiExtractionConfig with specified minimum length and default max_length (None)
    ///
    /// # Example
    ///
    /// ```rust
    /// use stringy::extraction::ascii::AsciiExtractionConfig;
    ///
    /// let config = AsciiExtractionConfig::new(8);
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
/// **Note on printable character definitions**: This function uses a strict definition
/// of printable ASCII (0x20-0x7E only), excluding whitespace control characters like
/// tab, newline, and carriage return. This differs from `is_printable_text_byte` in
/// `extraction::mod`, which includes common whitespace characters (0x09, 0x0A, 0x0D)
/// to handle formatted text. This strict definition ensures ASCII-only extraction
/// produces predictable, consistent results.
///
/// # Arguments
///
/// * `byte` - Byte to check
///
/// # Returns
///
/// `true` if the byte is printable ASCII, `false` otherwise
///
/// # Example
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
/// Scans through the byte slice looking for contiguous sequences of printable ASCII
/// characters. When a non-printable byte is encountered, checks if the accumulated
/// sequence meets the minimum length threshold and creates a FoundString entry.
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
/// # Arguments
///
/// * `data` - Byte slice to scan for ASCII strings
/// * `config` - Extraction configuration
///
/// # Returns
///
/// Vector of FoundString entries with the following metadata:
/// - `text`: UTF-8 string from accumulated bytes
/// - `encoding`: `Encoding::Ascii`
/// - `offset`: Start position in the data slice
/// - `length`: Byte count
/// - `source`: `StringSource::SectionData`
/// - `tags`: Empty vector
/// - `score`: 0
/// - `section`: None
/// - `rva`: None
///
/// # Edge Cases
///
/// - Empty input data returns empty vector
/// - Data smaller than minimum length returns empty vector
/// - String at buffer start (start_offset = 0)
/// - String at buffer end (checked after loop)
/// - Very long strings are filtered by max_length if configured
///
/// # Example
///
/// ```rust
/// use stringy::extraction::ascii::{extract_ascii_strings, AsciiExtractionConfig};
///
/// let data = b"Hello\0World\0Test123";
/// let config = AsciiExtractionConfig::default();
/// let strings = extract_ascii_strings(data, &config);
///
/// assert_eq!(strings.len(), 3);
/// assert_eq!(strings[0].text, "Hello");
/// assert_eq!(strings[0].offset, 0);
/// assert_eq!(strings[1].text, "World");
/// assert_eq!(strings[1].offset, 6);
/// ```
pub fn extract_ascii_strings(data: &[u8], config: &AsciiExtractionConfig) -> Vec<FoundString> {
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
                    if let Some(max_len) = config.max_length
                        && len > max_len
                    {
                        // Skip this string, reset accumulator
                        current_string_start = None;
                        current_string_bytes.clear();
                        continue;
                    }
                    // Convert bytes to UTF-8 string (ASCII is valid UTF-8)
                    let bytes = std::mem::take(&mut current_string_bytes);
                    let text = String::from_utf8(bytes).expect("ASCII bytes should be valid UTF-8");
                    strings.push(FoundString {
                        text,
                        original_text: None,
                        encoding: Encoding::Ascii,
                        offset: start as u64,
                        rva: None,
                        section: None,
                        length: len as u32,
                        tags: Vec::new(),
                        score: 0,
                        section_weight: None,
                        semantic_boost: None,
                        noise_penalty: None,
                        source: StringSource::SectionData,
                        confidence: 1.0,
                    });
                }
            }
            current_string_start = None;
            current_string_bytes.clear();
        }
    }

    // Handle string at end of buffer
    if let Some(start) = current_string_start {
        let len = current_string_bytes.len();
        if len >= config.min_length {
            // Check maximum length if configured
            if let Some(max_len) = config.max_length {
                if len > max_len {
                    // Skip this string
                } else {
                    let bytes = std::mem::take(&mut current_string_bytes);
                    let text = String::from_utf8(bytes).expect("ASCII bytes should be valid UTF-8");
                    strings.push(FoundString {
                        text,
                        original_text: None,
                        encoding: Encoding::Ascii,
                        offset: start as u64,
                        rva: None,
                        section: None,
                        length: len as u32,
                        tags: Vec::new(),
                        score: 0,
                        section_weight: None,
                        semantic_boost: None,
                        noise_penalty: None,
                        source: StringSource::SectionData,
                        confidence: 1.0,
                    });
                }
            } else {
                let bytes = std::mem::take(&mut current_string_bytes);
                let text = String::from_utf8(bytes).expect("ASCII bytes should be valid UTF-8");
                strings.push(FoundString {
                    text,
                    original_text: None,
                    encoding: Encoding::Ascii,
                    offset: start as u64,
                    rva: None,
                    section: None,
                    length: len as u32,
                    tags: Vec::new(),
                    score: 0,
                    section_weight: None,
                    semantic_boost: None,
                    noise_penalty: None,
                    source: StringSource::SectionData,
                    confidence: 1.0,
                });
            }
        }
    }

    strings
}

/// Extract ASCII strings from a specific section with proper metadata population
///
/// This function extracts strings from a section of the binary, adjusting offsets
/// and populating section-specific metadata (section name, RVA). It also applies
/// noise filtering if enabled in the extraction configuration.
///
/// # Implementation
///
/// 1. Calculate section data slice using section.offset and section.size, with bounds checking
/// 2. Call `extract_ascii_strings` on the section data slice
/// 3. For each candidate string, compute confidence using noise filters if enabled
/// 4. Apply confidence threshold filtering if noise filtering is enabled
/// 5. Post-process each FoundString to adjust offsets (add section.offset to relative offsets)
/// 6. Populate section field with section.name.clone()
/// 7. Populate rva field with calculated value (section.rva + relative_offset) if section.rva is Some
/// 8. Return the adjusted vector of FoundStrings
///
/// # Arguments
///
/// * `section` - Section metadata
/// * `data` - Raw binary data
/// * `config` - Extraction configuration
/// * `noise_filter_config` - Optional noise filter configuration (if None, filtering is skipped)
/// * `noise_filtering_enabled` - Whether to apply noise filtering
/// * `min_confidence_threshold` - Minimum confidence threshold for filtering
///
/// # Returns
///
/// Vector of FoundString entries with complete metadata including:
/// - Adjusted absolute offsets (section.offset + relative_offset)
/// - Section name populated
/// - RVA calculated if section.rva is available
/// - Confidence scores computed from noise filters
///
/// # Edge Cases
///
/// - Section boundaries: ensures slice doesn't exceed data.len()
/// - Section offset + size overflow: uses checked arithmetic
/// - Empty sections return empty vector
/// - Sections beyond data bounds return empty vector
///
/// # Example
///
/// ```rust
/// use stringy::extraction::ascii::{extract_from_section, AsciiExtractionConfig};
/// use stringy::extraction::config::NoiseFilterConfig;
/// use stringy::types::{SectionInfo, SectionType};
///
/// let section = SectionInfo {
///     name: ".rodata".to_string(),
///     offset: 10,
///     size: 20,
///     rva: Some(0x1000),
///     section_type: SectionType::StringData,
///     is_executable: false,
///     is_writable: false,
///     weight: 1.0,
/// };
///
/// let data = b"prefix\0Hello World\0suffix";
/// let config = AsciiExtractionConfig::default();
/// let noise_config = Some(NoiseFilterConfig::default());
/// let strings = extract_from_section(&section, data, &config, noise_config.as_ref(), true, 0.5);
///
/// // Strings will have adjusted offsets and section metadata
/// for string in strings {
///     assert_eq!(string.section, Some(".rodata".to_string()));
///     assert!(string.offset >= 10);
/// }
/// ```
pub fn extract_from_section(
    section: &SectionInfo,
    data: &[u8],
    config: &AsciiExtractionConfig,
    noise_filter_config: Option<&NoiseFilterConfig>,
    noise_filtering_enabled: bool,
    min_confidence_threshold: f32,
) -> Vec<FoundString> {
    // Calculate section data slice with bounds checking
    let section_offset = section.offset as usize;
    let section_size = section.size as usize;

    // Check if section is out of bounds
    if section_offset >= data.len() {
        return Vec::new();
    }

    // Calculate end offset with checked arithmetic
    let end_offset = section_offset
        .checked_add(section_size)
        .unwrap_or(data.len())
        .min(data.len());

    // Extract section data slice
    let section_data = &data[section_offset..end_offset];

    // Extract strings from section data
    let strings = extract_ascii_strings(section_data, config);

    // Build filter context from section
    let filter_context = FilterContext::from_section(section);

    // Create composite noise filter if filtering is enabled and config is provided
    let filter = if noise_filtering_enabled {
        noise_filter_config.map(CompositeNoiseFilter::new)
    } else {
        None
    };

    // Post-process: compute confidence, apply threshold, adjust offsets and populate metadata
    let mut filtered_strings = Vec::new();
    for mut string in strings {
        // Compute confidence if filtering is enabled
        if let Some(ref noise_filter) = filter {
            string.confidence = noise_filter.calculate_confidence(&string.text, &filter_context);
            // Apply threshold filtering
            if noise_filtering_enabled && string.confidence < min_confidence_threshold {
                continue;
            }
        } else {
            // If filtering is disabled, keep default confidence of 1.0
            string.confidence = 1.0;
        }

        // Adjust offset: add section.offset to relative offset
        // string.offset is relative to section_data (starts at 0), so add section.offset
        let relative_offset = string.offset;
        string.offset = section.offset + relative_offset;

        // Populate section name
        string.section = Some(section.name.clone());

        // Calculate and populate RVA if section.rva is available
        if let Some(base_rva) = section.rva {
            // relative_offset is the offset within the section
            string.rva = Some(base_rva + relative_offset);
        }

        filtered_strings.push(string);
    }

    filtered_strings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SectionInfo, SectionType};

    // Helper to create test section
    fn create_test_section(name: &str, offset: u64, size: u64, rva: Option<u64>) -> SectionInfo {
        SectionInfo {
            name: name.to_string(),
            offset,
            size,
            rva,
            section_type: SectionType::StringData,
            is_executable: false,
            is_writable: false,
            weight: 1.0,
        }
    }

    #[test]
    fn test_is_printable_ascii() {
        // Printable ASCII range (0x20-0x7E)
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
        assert!(!is_printable_ascii(0xFF));
    }

    #[test]
    fn test_extract_ascii_strings_basic() {
        // Basic extraction with default minimum length (4)
        let data = b"Hello\0World\0Test";
        let config = AsciiExtractionConfig::default();
        let strings = extract_ascii_strings(data, &config);

        assert_eq!(strings.len(), 3);
        assert_eq!(strings[0].text, "Hello");
        assert_eq!(strings[0].offset, 0);
        assert_eq!(strings[0].encoding, Encoding::Ascii);
        assert_eq!(strings[0].source, StringSource::SectionData);
        assert_eq!(strings[1].text, "World");
        assert_eq!(strings[1].offset, 6);
        assert_eq!(strings[2].text, "Test");
        assert_eq!(strings[2].offset, 12);
    }

    #[test]
    fn test_extract_ascii_strings_custom_min_length() {
        // Custom minimum length filtering
        let data = b"Hi\0Test\0AB\0LongString";
        let config = AsciiExtractionConfig::new(3);
        let strings = extract_ascii_strings(data, &config);

        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].text, "Test");
        assert_eq!(strings[1].text, "LongString");
        // "Hi" and "AB" should be filtered out (length < 3)
    }

    #[test]
    fn test_extract_ascii_strings_min_length_5() {
        let data = b"Test\0Hello\0World";
        let config = AsciiExtractionConfig::new(5);
        let strings = extract_ascii_strings(data, &config);

        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].text, "Hello");
        assert_eq!(strings[1].text, "World");
        // "Test" should be filtered out (length < 5)
    }

    #[test]
    fn test_extract_ascii_strings_min_length_10() {
        let data = b"Short\0VeryLongStringHere";
        let config = AsciiExtractionConfig::new(10);
        let strings = extract_ascii_strings(data, &config);

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].text, "VeryLongStringHere");
    }

    #[test]
    fn test_extract_ascii_strings_empty_input() {
        // Empty input edge case
        let data = b"";
        let config = AsciiExtractionConfig::default();
        let strings = extract_ascii_strings(data, &config);

        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_ascii_strings_no_strings_found() {
        // No strings found (all binary data)
        let data = &[0x00, 0xFF, 0x01, 0x02, 0x03];
        let config = AsciiExtractionConfig::default();
        let strings = extract_ascii_strings(data, &config);

        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_ascii_strings_string_at_start() {
        // String at buffer start
        let data = b"Start\0Middle\0End";
        let config = AsciiExtractionConfig::default();
        let strings = extract_ascii_strings(data, &config);

        // "End" is only 3 characters, below min_length=4, so filtered out
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].text, "Start");
        assert_eq!(strings[0].offset, 0);
        assert_eq!(strings[1].text, "Middle");
    }

    #[test]
    fn test_extract_ascii_strings_string_at_end() {
        // String at buffer end
        let data = b"Start\0Middle\0EndTest";
        let config = AsciiExtractionConfig::default();
        let strings = extract_ascii_strings(data, &config);

        assert_eq!(strings.len(), 3);
        assert_eq!(strings[2].text, "EndTest");
        assert_eq!(strings[2].offset, 13);
    }

    #[test]
    fn test_extract_ascii_strings_single_char_below_minimum() {
        // Single character below minimum
        let data = b"A\0Test\0B\0C";
        let config = AsciiExtractionConfig::default();
        let strings = extract_ascii_strings(data, &config);

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].text, "Test");
        // Single characters should be filtered out
    }

    #[test]
    fn test_extract_ascii_strings_exact_minimum_length() {
        // Exact minimum length string
        let data = b"Test\0Hello";
        let config = AsciiExtractionConfig::default(); // min_length = 4
        let strings = extract_ascii_strings(data, &config);

        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].text, "Test");
        assert_eq!(strings[0].length, 4);
        assert_eq!(strings[1].text, "Hello");
    }

    #[test]
    fn test_extract_ascii_strings_offset_calculation() {
        // Offset calculation correctness
        let data = b"prefix\0Hello\0World\0suffix";
        let config = AsciiExtractionConfig::default();
        let strings = extract_ascii_strings(data, &config);

        // All strings are >= 4 characters, so all should be extracted
        assert_eq!(strings.len(), 4);
        assert_eq!(strings[0].text, "prefix");
        assert_eq!(strings[0].offset, 0);
        assert_eq!(strings[1].text, "Hello");
        assert_eq!(strings[1].offset, 7); // "prefix\0" = 7 bytes
        assert_eq!(strings[2].text, "World");
        assert_eq!(strings[2].offset, 13); // "prefix\0Hello\0" = 13 bytes
        assert_eq!(strings[3].text, "suffix");
        assert_eq!(strings[3].offset, 19); // "prefix\0Hello\0World\0" = 19 bytes
    }

    #[test]
    fn test_extract_ascii_strings_multiple_strings_sequence() {
        // Multiple strings in sequence
        let data = b"First\0Second\0Third\0Fourth";
        let config = AsciiExtractionConfig::default();
        let strings = extract_ascii_strings(data, &config);

        assert_eq!(strings.len(), 4);
        assert_eq!(strings[0].text, "First");
        assert_eq!(strings[1].text, "Second");
        assert_eq!(strings[2].text, "Third");
        assert_eq!(strings[3].text, "Fourth");
    }

    #[test]
    fn test_extract_ascii_strings_separated_by_single_byte() {
        // Strings separated by single non-printable byte
        let data = b"Hello\x00World\x01Test";
        let config = AsciiExtractionConfig::default();
        let strings = extract_ascii_strings(data, &config);

        assert_eq!(strings.len(), 3);
        assert_eq!(strings[0].text, "Hello");
        assert_eq!(strings[1].text, "World");
        assert_eq!(strings[2].text, "Test");
    }

    #[test]
    fn test_extract_ascii_strings_max_length_filtering() {
        // Max length filtering if configured
        let data = b"Short\0VeryLongStringHere";
        let config = AsciiExtractionConfig {
            max_length: Some(10),
            ..Default::default()
        };
        let strings = extract_ascii_strings(data, &config);

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].text, "Short");
        // "VeryLongStringHere" should be filtered out (length > 10)
    }

    #[test]
    fn test_extract_ascii_strings_very_long_string() {
        // Very long strings (test max_length enforcement)
        let long_string = "A".repeat(1000);
        let data = format!("{}\0Short", long_string).into_bytes();
        let config = AsciiExtractionConfig {
            max_length: Some(100),
            ..Default::default()
        };
        let strings = extract_ascii_strings(&data, &config);

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].text, "Short");
        // Very long string should be filtered out
    }

    #[test]
    fn test_extract_from_section_basic() {
        // Basic section extraction
        let section = create_test_section(".rodata", 0, 20, Some(0x1000));
        let data = b"Hello World\0Test";
        let config = AsciiExtractionConfig::default();
        let strings = extract_from_section(&section, data, &config, None, false, 0.5);

        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].text, "Hello World");
        assert_eq!(strings[0].offset, 0);
        assert_eq!(strings[0].rva, Some(0x1000));
        assert_eq!(strings[0].section, Some(".rodata".to_string()));
        assert_eq!(strings[1].text, "Test");
        assert_eq!(strings[1].offset, 12);
        assert_eq!(strings[1].rva, Some(0x100C));
    }

    #[test]
    fn test_extract_from_section_offset_adjustment() {
        // Section metadata population (verify section name and RVA)
        // data = b"prefix\0Hello World\0suffix"
        //        "prefix\0" = 7 bytes, so "Hello World" starts at offset 7
        // Section should start at 7 to include "Hello World"
        let section = create_test_section(".data", 7, 12, Some(0x2000));
        let data = b"prefix\0Hello World\0suffix";
        let config = AsciiExtractionConfig::default();
        let strings = extract_from_section(&section, data, &config, None, false, 0.5);

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].text, "Hello World");
        // Section starts at 7, "Hello World" is at relative offset 0 within section
        // Absolute offset = section.offset (7) + relative_offset (0) = 7
        assert_eq!(strings[0].offset, 7);
        assert_eq!(strings[0].rva, Some(0x2000));
        assert_eq!(strings[0].section, Some(".data".to_string()));
    }

    #[test]
    fn test_extract_from_section_rva_calculation() {
        // RVA calculation with section offset
        let section = create_test_section(".text", 5, 10, Some(0x1000));
        let data = b"pre\0Hello\0suf";
        let config = AsciiExtractionConfig::default();
        let strings = extract_from_section(&section, data, &config, None, false, 0.5);

        if !strings.is_empty() {
            // Section data is data[5..15] = "Hello\0suf"
            // "Hello" is at relative offset 0
            // Absolute offset = 5 + 0 = 5
            // RVA = 0x1000 + 0 = 0x1000
            assert_eq!(strings[0].offset, 5);
            assert_eq!(strings[0].rva, Some(0x1000));
        }
    }

    #[test]
    fn test_extract_from_section_no_rva() {
        // Section without RVA
        let section = create_test_section(".data", 0, 20, None);
        let data = b"Hello World\0Test";
        let config = AsciiExtractionConfig::default();
        let strings = extract_from_section(&section, data, &config, None, false, 0.5);

        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].rva, None);
        assert_eq!(strings[1].rva, None);
    }

    #[test]
    fn test_extract_from_section_section_name() {
        // Verify section name is populated
        let section = create_test_section(".custom", 0, 20, Some(0x3000));
        let data = b"Test String\0Another";
        let config = AsciiExtractionConfig::default();
        let strings = extract_from_section(&section, data, &config, None, false, 0.5);

        for string in &strings {
            assert_eq!(string.section, Some(".custom".to_string()));
        }
    }

    #[test]
    fn test_extract_from_section_bounds_checking() {
        // Section boundaries (ensure slice doesn't exceed data.len())
        let section = create_test_section(".data", 0, 1000, None);
        let data = b"Short data";
        let config = AsciiExtractionConfig::default();
        let strings = extract_from_section(&section, data, &config, None, false, 0.5);

        // Should only extract from available data, not panic
        assert!(strings.len() <= 1);
    }

    #[test]
    fn test_extract_from_section_out_of_bounds() {
        // Section offset + size overflow (use checked arithmetic)
        let section = create_test_section(".data", 1000, 100, None);
        let data = b"Short data";
        let config = AsciiExtractionConfig::default();
        let strings = extract_from_section(&section, data, &config, None, false, 0.5);

        // Should return empty vector, not panic
        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_from_section_empty_section() {
        // Empty section
        let section = create_test_section(".empty", 0, 0, None);
        let data = b"Some data";
        let config = AsciiExtractionConfig::default();
        let strings = extract_from_section(&section, data, &config, None, false, 0.5);

        assert!(strings.is_empty());
    }

    #[test]
    fn test_extraction_config_default() {
        let config = AsciiExtractionConfig::default();
        assert_eq!(config.min_length, 4);
        assert_eq!(config.max_length, None);
    }

    #[test]
    fn test_extraction_config_new() {
        let config = AsciiExtractionConfig::new(8);
        assert_eq!(config.min_length, 8);
        assert_eq!(config.max_length, None);
    }

    #[test]
    fn test_extraction_config_custom_max_length() {
        let config = AsciiExtractionConfig {
            max_length: Some(256),
            ..Default::default()
        };
        assert_eq!(config.min_length, 4);
        assert_eq!(config.max_length, Some(256));
    }
}
