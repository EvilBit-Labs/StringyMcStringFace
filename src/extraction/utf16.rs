//! UTF-16 String Extraction Module
//!
//! This module provides UTF-16 string extraction for Stringy, supporting both
//! UTF-16LE (Little-Endian) and UTF-16BE (Big-Endian) byte orders. It implements byte-level
//! scanning for contiguous UTF-16 character sequences with advanced confidence scoring and
//! noise filtering integration.
//!
//! # Examples
//!
//! ```rust
//! use stringy::extraction::utf16::{extract_utf16_strings, extract_from_section, Utf16ExtractionConfig, ByteOrder};
//! use stringy::types::{SectionInfo, SectionType};
//!
//! // Basic extraction from raw data with auto byte order detection
//! let data = &[0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00, 0x00, 0x00]; // "Hello\0" in UTF-16LE
//! let config = Utf16ExtractionConfig::default();
//! let strings = extract_utf16_strings(data, &config);
//!
//! // Section-aware extraction
//! let section = SectionInfo {
//!     name: ".rdata".to_string(),
//!     offset: 0,
//!     size: 12,
//!     rva: Some(0x1000),
//!     section_type: SectionType::StringData,
//!     is_executable: false,
//!     is_writable: false,
//!     weight: 1.0,
//! };
//! let strings = extract_from_section(&section, data, &config, None, false, 0.5);
//! ```

use crate::extraction::config::NoiseFilterConfig;
use crate::extraction::filters::{CompositeNoiseFilter, FilterContext};
use crate::types::{Encoding, FoundString, SectionInfo, StringSource};

/// Byte order for UTF-16 string extraction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteOrder {
    /// Little-Endian (most common on Windows)
    LE,
    /// Big-Endian (found in Java .class files, network protocols)
    BE,
    /// Automatically detect both byte orders
    Auto,
}

/// Configuration for UTF-16 string extraction
///
/// Controls minimum and maximum character count filtering, byte order selection,
/// and confidence thresholds. Character count refers to the number of UTF-16 code units
/// (characters), not bytes.
///
/// # Default Values
///
/// - `min_length`: 3 (minimum character count = 6 bytes)
/// - `max_length`: None (no upper limit by default)
/// - `byte_order`: Auto (detect both LE and BE)
/// - `confidence_threshold`: 0.5 (minimum UTF-16-specific confidence)
///
/// # Examples
///
/// ```rust
/// use stringy::extraction::utf16::{Utf16ExtractionConfig, ByteOrder};
///
/// // Use default configuration
/// let config = Utf16ExtractionConfig::default();
///
/// // Custom minimum character length
/// let config = Utf16ExtractionConfig::new(5);
///
/// // Custom configuration
/// let mut config = Utf16ExtractionConfig::default();
/// config.max_length = Some(256);
/// config.byte_order = ByteOrder::LE;
/// config.confidence_threshold = 0.6;
/// ```
#[derive(Debug, Clone)]
pub struct Utf16ExtractionConfig {
    /// Minimum string length in UTF-16 code units (default: 3)
    pub min_length: usize,
    /// Maximum string length in UTF-16 code units (default: None, no limit)
    pub max_length: Option<usize>,
    /// Which byte order(s) to scan (default: Auto)
    pub byte_order: ByteOrder,
    /// Minimum UTF-16-specific confidence threshold (default: 0.5)
    pub confidence_threshold: f32,
    /// Whether to scan both even and odd alignments (default: false)
    ///
    /// When enabled, performs two passes: first starting at index 0 (even), then at index 1 (odd).
    /// This can find UTF-16 strings that start at unaligned positions within the section slice,
    /// but doubles the scanning time.
    pub scan_both_alignments: bool,
}

impl Default for Utf16ExtractionConfig {
    fn default() -> Self {
        Self {
            min_length: 3,
            max_length: None,
            byte_order: ByteOrder::Auto,
            confidence_threshold: 0.5,
            scan_both_alignments: false,
        }
    }
}

impl Utf16ExtractionConfig {
    /// Create a new Utf16ExtractionConfig with custom minimum character length
    ///
    /// # Arguments
    ///
    /// * `min_length` - Minimum character count
    ///
    /// # Returns
    ///
    /// New Utf16ExtractionConfig with specified minimum length and default values for other fields
    ///
    /// # Example
    ///
    /// ```rust
    /// use stringy::extraction::utf16::Utf16ExtractionConfig;
    ///
    /// let config = Utf16ExtractionConfig::new(5);
    /// assert_eq!(config.min_length, 5);
    /// assert_eq!(config.max_length, None);
    /// ```
    pub fn new(min_length: usize) -> Self {
        Self {
            min_length,
            max_length: None,
            byte_order: ByteOrder::Auto,
            confidence_threshold: 0.5,
            scan_both_alignments: false,
        }
    }
}

/// Check if a UTF-16 code unit or surrogate pair is printable
///
/// A UTF-16 character is considered printable if:
/// - It represents a valid Unicode code point (not a lone surrogate or non-character)
/// - Valid surrogate pairs (high + low) are decoded and checked for printability
/// - It is not a control character (except whitespace)
/// - It falls within printable ranges: >= 0x20 excluding 0x7F..0x9F control range
/// - It includes whitespace characters like U+00A0 (non-breaking space)
///
/// # Arguments
///
/// * `code_unit` - UTF-16 code unit (u16)
/// * `next_code_unit` - Optional next code unit for surrogate pair detection
///
/// # Returns
///
/// `(is_printable, consumed_units)` - Returns true if printable, and number of code units consumed (1 or 2)
#[inline]
pub fn is_printable_code_unit_or_pair(
    code_unit: u16,
    next_code_unit: Option<u16>,
) -> (bool, usize) {
    // Check for high surrogate (0xD800..0xDBFF)
    if (0xD800..=0xDBFF).contains(&code_unit) {
        // Need next code unit to form a valid pair
        if let Some(low) = next_code_unit {
            // Check if it's a valid low surrogate (0xDC00..0xDFFF)
            if (0xDC00..=0xDFFF).contains(&low) {
                // Decode surrogate pair to code point
                let high_bits = (code_unit as u32 & 0x3FF) << 10;
                let low_bits = low as u32 & 0x3FF;
                let code_point = 0x10000 + high_bits + low_bits;

                // Check if the decoded character is printable
                if let Some(ch) = char::from_u32(code_point) {
                    // Allow whitespace characters
                    if ch.is_whitespace() {
                        return (true, 2);
                    }

                    // Exclude control characters
                    if ch.is_control() {
                        return (false, 2);
                    }

                    // For code points >= 0x20, exclude 0x7F..0x9F control range
                    if code_point >= 0x20 && !(0x7F..=0x9F).contains(&code_point) {
                        return (true, 2);
                    }
                }
                // Invalid surrogate pair or non-character
                return (false, 2);
            } else {
                // Lone high surrogate - invalid
                return (false, 1);
            }
        } else {
            // Lone high surrogate without next unit - invalid
            return (false, 1);
        }
    }

    // Check for low surrogate (0xDC00..0xDFFF) - should not appear alone
    if (0xDC00..=0xDFFF).contains(&code_unit) {
        return (false, 1);
    }

    // Exclude non-characters (0xFDD0..0xFDEF, and U+FFFE/U+FFFF)
    if (0xFDD0..=0xFDEF).contains(&code_unit) || code_unit == 0xFFFE || code_unit == 0xFFFF {
        return (false, 1);
    }

    // Convert to u32 for char conversion
    let code_point = code_unit as u32;

    // Try to convert to char for classification
    if let Some(ch) = char::from_u32(code_point) {
        // Allow whitespace characters (including U+00A0 non-breaking space)
        if ch.is_whitespace() {
            return (true, 1);
        }

        // Exclude control characters
        if ch.is_control() {
            return (false, 1);
        }

        // For code points >= 0x20, exclude 0x7F..0x9F control range
        if code_point >= 0x20 && !(0x7F..=0x9F).contains(&code_point) {
            return (true, 1);
        }
    }

    (false, 1)
}

/// Check if a UTF-16LE character is printable (legacy function for backward compatibility)
///
/// This function is kept for backward compatibility but delegates to `is_printable_code_unit_or_pair`.
/// For new code, prefer using `is_printable_code_unit_or_pair` directly.
///
/// # Arguments
///
/// * `low` - Low byte of the UTF-16LE character
/// * `high` - High byte of the UTF-16LE character
///
/// # Returns
///
/// `true` if the character is printable, `false` otherwise
#[inline]
pub fn is_printable_utf16le_char(low: u8, high: u8) -> bool {
    let code_unit = u16::from_le_bytes([low, high]);
    let (is_printable, _) = is_printable_code_unit_or_pair(code_unit, None);
    is_printable
}

/// Decode UTF-16LE byte sequence to UTF-8 String and return u16 vector
///
/// Converts a UTF-16LE byte sequence to a UTF-8 String using `u16::from_le_bytes`
/// and `String::from_utf16`. Also returns the u16 vector for confidence scoring.
/// Handles odd-length inputs gracefully by truncating the last byte.
///
/// # Arguments
///
/// * `bytes` - UTF-16LE encoded byte slice
///
/// # Returns
///
/// `Result<(String, Vec<u16>)>` - Decoded UTF-8 string and u16 vector, or error if decoding fails
fn decode_utf16le(bytes: &[u8]) -> Result<(String, Vec<u16>), ()> {
    // Handle odd-length input by truncating last byte
    let even_bytes = if bytes.len() % 2 == 1 {
        &bytes[..bytes.len() - 1]
    } else {
        bytes
    };

    // Convert to u16 slice
    let u16_slice: Vec<u16> = even_bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();

    // Decode UTF-16 to String
    let decoded = String::from_utf16(&u16_slice).map_err(|_| ())?;

    Ok((decoded, u16_slice))
}

/// Decode UTF-16BE byte sequence to UTF-8 String and return u16 vector
///
/// Converts a UTF-16BE byte sequence to a UTF-8 String using `u16::from_be_bytes`
/// and `String::from_utf16`. Also returns the u16 vector for confidence scoring.
/// Handles odd-length inputs gracefully by truncating the last byte.
///
/// # Arguments
///
/// * `bytes` - UTF-16BE encoded byte slice
///
/// # Returns
///
/// `Result<(String, Vec<u16>)>` - Decoded UTF-8 string and u16 vector, or error if decoding fails
fn decode_utf16be(bytes: &[u8]) -> Result<(String, Vec<u16>), ()> {
    // Handle odd-length input by truncating last byte
    let even_bytes = if bytes.len() % 2 == 1 {
        &bytes[..bytes.len() - 1]
    } else {
        bytes
    };

    // Convert to u16 slice
    let u16_slice: Vec<u16> = even_bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
        .collect();

    // Decode UTF-16 to String
    let decoded = String::from_utf16(&u16_slice).map_err(|_| ())?;

    Ok((decoded, u16_slice))
}

/// Decode UTF-16LE byte sequence to UTF-8 String (public API)
///
/// Converts a UTF-16LE byte sequence to a UTF-8 String using `u16::from_le_bytes`
/// and `String::from_utf16`. Handles odd-length inputs gracefully by truncating
/// the last byte.
///
/// # Arguments
///
/// * `bytes` - UTF-16LE encoded byte slice
///
/// # Returns
///
/// Decoded UTF-8 string, or error if decoding fails
#[allow(clippy::result_unit_err)]
pub fn decode_utf16le_bytes(bytes: &[u8]) -> Result<String, ()> {
    decode_utf16le(bytes).map(|(s, _)| s)
}

/// Validate UTF-16 sequence (surrogate pairs and code points)
///
/// Checks if a sequence of UTF-16 code units forms valid UTF-16 sequences.
///
/// # Arguments
///
/// * `chars` - Slice of UTF-16 code units
///
/// # Returns
///
/// `true` if the sequence is valid UTF-16
#[allow(dead_code)]
fn is_valid_utf16_sequence(chars: &[u16]) -> bool {
    let mut i = 0;
    while i < chars.len() {
        let code_unit = chars[i];

        // Check for high surrogate
        if (0xD800..=0xDBFF).contains(&code_unit) {
            // Need low surrogate next
            if i + 1 >= chars.len() {
                return false; // Lone high surrogate
            }
            let low = chars[i + 1];
            if !(0xDC00..=0xDFFF).contains(&low) {
                return false; // Invalid low surrogate
            }
            i += 2; // Consume both surrogates
        } else if (0xDC00..=0xDFFF).contains(&code_unit) {
            // Lone low surrogate
            return false;
        } else {
            i += 1; // Regular code unit
        }
    }
    true
}

/// Check valid Unicode range for code points
///
/// Validates code points are in valid Unicode ranges, penalizes private use areas
/// and invalid surrogates.
///
/// # Arguments
///
/// * `chars` - Slice of UTF-16 code units
///
/// # Returns
///
/// Confidence score component (0.0-1.0)
fn check_valid_unicode_range(chars: &[u16]) -> f32 {
    if chars.is_empty() {
        return 0.0;
    }

    let mut valid_count = 0;
    let mut i = 0;

    while i < chars.len() {
        let code_unit = chars[i];

        // Handle surrogate pairs
        if (0xD800..=0xDBFF).contains(&code_unit) {
            if i + 1 < chars.len() {
                let low = chars[i + 1];
                if (0xDC00..=0xDFFF).contains(&low) {
                    // Valid surrogate pair
                    let high_bits = (code_unit as u32 & 0x3FF) << 10;
                    let low_bits = low as u32 & 0x3FF;
                    let code_point = 0x10000 + high_bits + low_bits;

                    // Check valid ranges: U+0020-U+D7FF, U+E000-U+FFFD, U+10000-U+10FFFF
                    if (0x0020..=0xD7FF).contains(&code_point)
                        || (0xE000..=0xFFFD).contains(&code_point)
                        || (0x10000..=0x10FFFF).contains(&code_point)
                    {
                        valid_count += 2; // Count both surrogates
                    }
                    i += 2;
                    continue;
                }
            }
            // Invalid surrogate pair
            i += 1;
            continue;
        }

        // Check for low surrogate (should not appear alone)
        if (0xDC00..=0xDFFF).contains(&code_unit) {
            i += 1;
            continue;
        }

        // Check valid ranges: U+0020-U+D7FF, U+E000-U+FFFD
        if (0x0020..=0xD7FF).contains(&(code_unit as u32))
            || (0xE000..=0xFFFD).contains(&(code_unit as u32))
        {
            valid_count += 1;
        }

        i += 1;
    }

    if chars.is_empty() {
        0.0
    } else {
        valid_count as f32 / chars.len() as f32
    }
}

/// Detect suspicious null patterns
///
/// Detects patterns like every-other-null, fixed-offset nulls, excessive nulls
/// that indicate binary data rather than legitimate UTF-16 strings.
///
/// # Arguments
///
/// * `chars` - Slice of UTF-16 code units
///
/// # Returns
///
/// Penalty score (0.0 = no penalty, higher = more suspicious)
fn check_null_pattern(chars: &[u16]) -> f32 {
    if chars.is_empty() {
        return 0.0;
    }

    let null_count = chars.iter().filter(|&&c| c == 0x0000).count();
    let null_ratio = null_count as f32 / chars.len() as f32;

    // Excessive nulls (>30%)
    if null_ratio > 0.3 {
        return 0.5; // High penalty
    }

    // Check for regular null patterns (every 2nd, 4th, 8th position)
    if chars.len() >= 4 {
        let mut pattern_matches = 0;
        let mut pattern_total = 0;

        // Check every-other-null pattern
        for i in (0..chars.len()).step_by(2) {
            if i + 1 < chars.len() {
                pattern_total += 1;
                if chars[i] == 0x0000 || chars[i + 1] == 0x0000 {
                    pattern_matches += 1;
                }
            }
        }

        if pattern_total > 0 {
            let pattern_ratio = pattern_matches as f32 / pattern_total as f32;
            if pattern_ratio > 0.5 {
                return 0.3; // Moderate penalty for regular patterns
            }
        }
    }

    0.0 // No penalty
}

/// Calculate ratio of ASCII-range characters
///
/// Calculates the ratio of characters in ASCII range (U+0020-U+007E).
/// Boosts confidence for ASCII-heavy strings.
///
/// # Arguments
///
/// * `chars` - Slice of UTF-16 code units
///
/// # Returns
///
/// ASCII ratio (0.0-1.0)
fn check_ascii_ratio(chars: &[u16]) -> f32 {
    if chars.is_empty() {
        return 0.0;
    }

    let mut ascii_count = 0;
    let mut i = 0;

    while i < chars.len() {
        let code_unit = chars[i];

        // Handle surrogate pairs (non-ASCII)
        if (0xD800..=0xDBFF).contains(&code_unit) {
            if i + 1 < chars.len() {
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }

        // Check ASCII range (U+0020-U+007E)
        if (0x0020..=0x007E).contains(&(code_unit as u32)) {
            ascii_count += 1;
        }

        i += 1;
    }

    ascii_count as f32 / chars.len() as f32
}

/// Calculate ratio of printable characters
///
/// Calculates the ratio of printable characters including common Unicode ranges.
///
/// # Arguments
///
/// * `chars` - Slice of UTF-16 code units
///
/// # Returns
///
/// Printable ratio (0.0-1.0)
fn check_printable_ratio(chars: &[u16]) -> f32 {
    if chars.is_empty() {
        return 0.0;
    }

    let mut printable_count = 0;
    let mut i = 0;

    while i < chars.len() {
        let code_unit = chars[i];
        let next_code_unit = if i + 1 < chars.len() {
            Some(chars[i + 1])
        } else {
            None
        };

        let (is_printable, consumed) = is_printable_code_unit_or_pair(code_unit, next_code_unit);
        if is_printable {
            printable_count += consumed;
        }
        i += consumed;
    }

    if chars.is_empty() {
        0.0
    } else {
        printable_count as f32 / chars.len() as f32
    }
}

/// Verify byte order consistency throughout the string
///
/// Checks that the byte order pattern matches the expected byte order by examining
/// the distribution of high/low bytes. For ASCII-range characters:
/// - LE: low bytes should be non-zero, high bytes should be zero
/// - BE: high bytes should be non-zero, low bytes should be zero
///
/// # Arguments
///
/// * `chars` - Slice of UTF-16 code units (u16 values)
/// * `byte_order` - Byte order being checked
///
/// # Returns
///
/// Consistency score (0.0-1.0)
fn check_byte_order_consistency(chars: &[u16], byte_order: ByteOrder) -> f32 {
    if chars.is_empty() {
        return 1.0;
    }

    let mut consistent_count = 0;
    let mut ascii_count = 0;

    for &code_unit in chars {
        // Check if this is an ASCII-range character (U+0020-U+007E)
        if (0x0020..=0x007E).contains(&code_unit) {
            ascii_count += 1;

            // Extract low and high bytes
            let low_byte = (code_unit & 0xFF) as u8;
            let high_byte = ((code_unit >> 8) & 0xFF) as u8;

            match byte_order {
                ByteOrder::LE => {
                    // For LE, low byte should be non-zero (the ASCII value), high byte should be zero
                    if low_byte != 0 && high_byte == 0 {
                        consistent_count += 1;
                    }
                }
                ByteOrder::BE => {
                    // For BE, high byte should be non-zero (the ASCII value), low byte should be zero
                    if high_byte != 0 && low_byte == 0 {
                        consistent_count += 1;
                    }
                }
                ByteOrder::Auto => {
                    // For Auto, we can't determine consistency without knowing which byte order was detected
                    // Return neutral score
                    return 1.0;
                }
            }
        }
    }

    if ascii_count == 0 {
        // No ASCII characters to check, return neutral score
        return 1.0;
    }

    // Return ratio of consistent ASCII characters
    consistent_count as f32 / ascii_count as f32
}

/// Calculate UTF-16-specific confidence score
///
/// Combines multiple heuristics to calculate a confidence score for UTF-16 strings.
/// Uses weighted formula with penalties for suspicious patterns.
///
/// # Arguments
///
/// * `chars` - Slice of UTF-16 code units
/// * `byte_order` - Byte order being checked
///
/// # Returns
///
/// Confidence score (0.0-1.0)
fn calculate_utf16_confidence(chars: &[u16], byte_order: ByteOrder) -> f32 {
    if chars.is_empty() {
        return 0.0;
    }

    // Calculate individual components
    let valid_unicode_ratio = check_valid_unicode_range(chars);
    let printable_ratio = check_printable_ratio(chars);
    let ascii_ratio = check_ascii_ratio(chars);
    let null_pattern_penalty = check_null_pattern(chars);

    // Weights for combining heuristics
    let valid_unicode_weight = 0.3;
    let printable_weight = 0.4;
    let ascii_weight = 0.2;
    let byte_order_weight = 0.1;

    // Calculate base confidence
    let mut confidence = (valid_unicode_weight * valid_unicode_ratio)
        + (printable_weight * printable_ratio)
        + (ascii_weight * ascii_ratio)
        + (byte_order_weight * check_byte_order_consistency(chars, byte_order));

    // Apply penalties
    confidence -= null_pattern_penalty;

    // Clamp to 0.0-1.0 range
    confidence.clamp(0.0, 1.0)
}

/// Extract UTF-16LE strings from a byte slice (internal)
///
/// Scans through the byte slice looking for contiguous sequences of printable UTF-16LE
/// characters. When a non-printable character or null terminator is encountered, checks
/// if the accumulated sequence meets the minimum character length and confidence thresholds.
///
/// # Arguments
///
/// * `data` - Byte slice to scan for UTF-16LE strings
/// * `config` - Extraction configuration
///
/// # Returns
///
/// Vector of FoundString entries
fn extract_utf16le_strings_internal(
    data: &[u8],
    config: &Utf16ExtractionConfig,
) -> Vec<FoundString> {
    extract_utf16_strings_with_byte_order(data, config, ByteOrder::LE)
}

/// Extract UTF-16BE strings from a byte slice (internal)
///
/// Scans through the byte slice looking for contiguous sequences of printable UTF-16BE
/// characters. When a non-printable character or null terminator is encountered, checks
/// if the accumulated sequence meets the minimum character length and confidence thresholds.
///
/// # Arguments
///
/// * `data` - Byte slice to scan for UTF-16BE strings
/// * `config` - Extraction configuration
///
/// # Returns
///
/// Vector of FoundString entries
fn extract_utf16be_strings_internal(
    data: &[u8],
    config: &Utf16ExtractionConfig,
) -> Vec<FoundString> {
    extract_utf16_strings_with_byte_order(data, config, ByteOrder::BE)
}

/// Generic UTF-16 string extraction with specified byte order
///
/// Scans through the byte slice looking for contiguous sequences of printable UTF-16
/// characters in the specified byte order. Handles both even and odd alignment scanning.
fn extract_utf16_strings_with_byte_order(
    data: &[u8],
    config: &Utf16ExtractionConfig,
    byte_order: ByteOrder,
) -> Vec<FoundString> {
    let mut strings = Vec::new();

    if data.len() < 2 {
        return strings;
    }

    // Helper function to scan from a given start offset
    let scan_from_offset = |start_offset: usize| -> Vec<FoundString> {
        let mut found_strings = Vec::new();
        let mut i = start_offset;
        while i + 1 < data.len() {
            let mut char_count = 0;
            let start = i;
            let mut has_null_terminator = false;

            // Accumulate printable UTF-16 characters
            while i + 1 < data.len() {
                // Read current code unit as u16
                let code_unit = match byte_order {
                    ByteOrder::LE => u16::from_le_bytes([data[i], data[i + 1]]),
                    ByteOrder::BE => u16::from_be_bytes([data[i], data[i + 1]]),
                    ByteOrder::Auto => unreachable!(),
                };

                // Check for null terminator (0x0000)
                if code_unit == 0x0000 {
                    has_null_terminator = true;
                    break;
                }

                // Check if we have a next code unit for surrogate pair detection
                let next_code_unit = if i + 3 < data.len() {
                    Some(match byte_order {
                        ByteOrder::LE => u16::from_le_bytes([data[i + 2], data[i + 3]]),
                        ByteOrder::BE => u16::from_be_bytes([data[i + 2], data[i + 3]]),
                        ByteOrder::Auto => unreachable!(),
                    })
                } else {
                    None
                };

                // Check if character is printable (handles surrogate pairs)
                let (is_printable, consumed_units) =
                    is_printable_code_unit_or_pair(code_unit, next_code_unit);

                if is_printable {
                    char_count += 1;
                    i += consumed_units * 2;
                } else {
                    break;
                }
            }

            // Check if we found a valid string
            if char_count >= config.min_length {
                if let Some(max_len) = config.max_length
                    && char_count > max_len
                {
                    i += 2;
                    continue;
                }

                let end = if has_null_terminator { i + 2 } else { i };
                let string_bytes = &data[start..end.min(data.len())];
                let bytes_for_decoding = if has_null_terminator && string_bytes.len() >= 2 {
                    &string_bytes[..string_bytes.len() - 2]
                } else {
                    string_bytes
                };

                // Decode to UTF-8 and get u16 vector
                let decode_result = match byte_order {
                    ByteOrder::LE => decode_utf16le(bytes_for_decoding),
                    ByteOrder::BE => decode_utf16be(bytes_for_decoding),
                    ByteOrder::Auto => unreachable!(),
                };

                if let Ok((text, u16_vec)) = decode_result {
                    let utf16_confidence = calculate_utf16_confidence(&u16_vec, byte_order);

                    if utf16_confidence >= config.confidence_threshold {
                        found_strings.push(FoundString {
                            text,
                            encoding: match byte_order {
                                ByteOrder::LE => Encoding::Utf16Le,
                                ByteOrder::BE => Encoding::Utf16Be,
                                ByteOrder::Auto => unreachable!(),
                            },
                            offset: start as u64,
                            rva: None,
                            section: None,
                            length: bytes_for_decoding.len() as u32,
                            tags: Vec::new(),
                            score: 0,
                            source: StringSource::SectionData,
                            confidence: utf16_confidence,
                        });
                    }
                }
            }

            // Move to next potential start position
            i += 2;
        }
        found_strings
    };

    // First pass: scan starting at even offset (index 0)
    strings.extend(scan_from_offset(0));

    // Second pass: scan starting at odd offset (index 1) if enabled
    if config.scan_both_alignments && data.len() >= 3 {
        strings.extend(scan_from_offset(1));
    }

    strings
}

/// Extract UTF-16 strings from a byte slice (main extraction function)
///
/// Calls both LE and BE extractors based on config.byte_order.
///
/// # Arguments
///
/// * `data` - Byte slice to scan for UTF-16 strings
/// * `config` - Extraction configuration
///
/// # Returns
///
/// Vector of FoundString entries
pub fn extract_utf16_strings(data: &[u8], config: &Utf16ExtractionConfig) -> Vec<FoundString> {
    let mut strings = Vec::new();

    match config.byte_order {
        ByteOrder::LE => {
            strings.extend(extract_utf16le_strings_internal(data, config));
        }
        ByteOrder::BE => {
            strings.extend(extract_utf16be_strings_internal(data, config));
        }
        ByteOrder::Auto => {
            // Extract both LE and BE, merge results
            let le_strings = extract_utf16le_strings_internal(data, config);
            let be_strings = extract_utf16be_strings_internal(data, config);

            // Helper to add string with deduplication
            let mut add_with_dedup = |string: FoundString| {
                if let Some(existing) = strings.iter_mut().find(|s| {
                    s.offset == string.offset
                        && s.encoding == string.encoding
                        && s.text == string.text
                }) {
                    if string.confidence > existing.confidence {
                        *existing = string;
                    }
                } else {
                    strings.push(string);
                }
            };

            for string in le_strings {
                add_with_dedup(string);
            }
            for string in be_strings {
                add_with_dedup(string);
            }
        }
    }

    strings
}

/// Extract UTF-16LE strings from a byte slice (public API for backward compatibility)
///
/// This function is kept for backward compatibility. For new code, prefer using
/// `extract_utf16_strings` with appropriate `ByteOrder` configuration.
pub fn extract_utf16le_strings(data: &[u8], config: &Utf16ExtractionConfig) -> Vec<FoundString> {
    let mut config_le = config.clone();
    config_le.byte_order = ByteOrder::LE;
    extract_utf16_strings(data, &config_le)
}

/// Extract UTF-16 strings from a specific section with proper metadata population
///
/// This function extracts strings from a section of the binary, adjusting offsets
/// and populating section-specific metadata (section name, RVA). It also applies
/// noise filtering if enabled in the extraction configuration.
///
/// # Implementation
///
/// 1. Calculate section data slice using section.offset and section.size, with bounds checking
/// 2. Call `extract_utf16_strings` on the section data slice
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
pub fn extract_from_section(
    section: &SectionInfo,
    data: &[u8],
    config: &Utf16ExtractionConfig,
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
    let strings = extract_utf16_strings(section_data, config);

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
            // Combine UTF-16 confidence with noise filter confidence
            let noise_confidence = noise_filter.calculate_confidence(&string.text, &filter_context);
            // Use the minimum of UTF-16 confidence and noise confidence
            string.confidence = string.confidence.min(noise_confidence);
            // Apply threshold filtering
            if noise_filtering_enabled && string.confidence < min_confidence_threshold {
                continue;
            }
        } else {
            // If filtering is disabled, keep UTF-16 confidence
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

    // Helper to create UTF-16LE test data
    fn create_utf16le_string(text: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        for ch in text.chars() {
            let code_point = ch as u32;
            if code_point <= 0xFFFF {
                let u16_val = code_point as u16;
                bytes.extend_from_slice(&u16_val.to_le_bytes());
            } else {
                // Surrogate pair
                let code_point = code_point - 0x10000;
                let high = 0xD800 + ((code_point >> 10) as u16);
                let low = 0xDC00 + ((code_point & 0x3FF) as u16);
                bytes.extend_from_slice(&high.to_le_bytes());
                bytes.extend_from_slice(&low.to_le_bytes());
            }
        }
        bytes
    }

    // Helper to create UTF-16BE test data
    fn create_utf16be_string(text: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        for ch in text.chars() {
            let code_point = ch as u32;
            if code_point <= 0xFFFF {
                let u16_val = code_point as u16;
                bytes.extend_from_slice(&u16_val.to_be_bytes());
            } else {
                // Surrogate pair
                let code_point = code_point - 0x10000;
                let high = 0xD800 + ((code_point >> 10) as u16);
                let low = 0xDC00 + ((code_point & 0x3FF) as u16);
                bytes.extend_from_slice(&high.to_be_bytes());
                bytes.extend_from_slice(&low.to_be_bytes());
            }
        }
        bytes
    }

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
    fn test_extract_utf16le_basic() {
        let mut data = create_utf16le_string("Hello");
        data.extend_from_slice(&[0x00, 0x00]);
        let world = create_utf16le_string("World");
        data.extend_from_slice(&world);
        data.extend_from_slice(&[0x00, 0x00]);

        let config = Utf16ExtractionConfig {
            byte_order: ByteOrder::LE,
            ..Default::default()
        };
        let strings = extract_utf16_strings(&data, &config);

        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].text, "Hello");
        assert_eq!(strings[0].encoding, Encoding::Utf16Le);
        assert_eq!(strings[1].text, "World");
    }

    #[test]
    fn test_extract_utf16be_basic() {
        let mut data = create_utf16be_string("Hello");
        data.extend_from_slice(&[0x00, 0x00]);
        let world = create_utf16be_string("World");
        data.extend_from_slice(&world);
        data.extend_from_slice(&[0x00, 0x00]);

        let config = Utf16ExtractionConfig {
            byte_order: ByteOrder::BE,
            ..Default::default()
        };
        let strings = extract_utf16_strings(&data, &config);

        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].text, "Hello");
        assert_eq!(strings[0].encoding, Encoding::Utf16Be);
        assert_eq!(strings[1].text, "World");
    }

    #[test]
    fn test_extract_utf16_auto_detects_le() {
        let mut data = create_utf16le_string("Hello");
        data.extend_from_slice(&[0x00, 0x00]);

        let config = Utf16ExtractionConfig {
            byte_order: ByteOrder::Auto,
            ..Default::default()
        };
        let strings = extract_utf16_strings(&data, &config);

        assert!(!strings.is_empty());
        assert_eq!(strings[0].text, "Hello");
        assert_eq!(strings[0].encoding, Encoding::Utf16Le);
    }

    #[test]
    fn test_extract_utf16_auto_detects_be() {
        let mut data = create_utf16be_string("Hello");
        data.extend_from_slice(&[0x00, 0x00]);

        let config = Utf16ExtractionConfig {
            byte_order: ByteOrder::Auto,
            scan_both_alignments: false, // Ensure we're not scanning odd offsets
            ..Default::default()
        };
        let strings = extract_utf16_strings(&data, &config);

        assert!(!strings.is_empty());
        // Find the BE string (should be the correct one)
        let be_string = strings
            .iter()
            .find(|s| s.encoding == Encoding::Utf16Be && s.text == "Hello");
        assert!(be_string.is_some(), "Should find BE string 'Hello'");
        if let Some(s) = be_string {
            assert_eq!(s.text, "Hello");
            assert_eq!(s.encoding, Encoding::Utf16Be);
        }
    }

    #[test]
    fn test_extract_utf16_mixed_ascii_unicode() {
        let mut data = create_utf16le_string("Hello 世界");
        data.extend_from_slice(&[0x00, 0x00]);

        let config = Utf16ExtractionConfig {
            byte_order: ByteOrder::LE,
            ..Default::default()
        };
        let strings = extract_utf16_strings(&data, &config);

        assert!(!strings.is_empty());
        assert_eq!(strings[0].text, "Hello 世界");
    }

    #[test]
    fn test_utf16_min_length_filtering() {
        let mut data = create_utf16le_string("Hi");
        data.extend_from_slice(&[0x00, 0x00]);
        let test = create_utf16le_string("Test");
        data.extend_from_slice(&test);
        data.extend_from_slice(&[0x00, 0x00]);

        let config = Utf16ExtractionConfig {
            min_length: 3,
            byte_order: ByteOrder::LE,
            ..Default::default()
        };
        let strings = extract_utf16_strings(&data, &config);

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].text, "Test");
    }

    #[test]
    fn test_utf16_confidence_legitimate_string() {
        let data = create_utf16le_string("Microsoft Corporation");
        let config = Utf16ExtractionConfig {
            byte_order: ByteOrder::LE,
            confidence_threshold: 0.5,
            ..Default::default()
        };
        let strings = extract_utf16_strings(&data, &config);

        assert!(!strings.is_empty());
        assert!(strings[0].confidence >= 0.5);
    }

    #[test]
    fn test_utf16_confidence_null_pattern_penalty() {
        // Create data with null-interleaved pattern (false positive)
        let data = vec![
            0x41, 0x00, 0x00, 0x00, 0x42, 0x00, 0x00, 0x00, 0x43, 0x00, 0x00, 0x00,
        ]; // "A\0B\0C\0" pattern

        let config = Utf16ExtractionConfig {
            byte_order: ByteOrder::LE,
            confidence_threshold: 0.3, // Lower threshold to see if it gets filtered
            ..Default::default()
        };
        let strings = extract_utf16_strings(&data, &config);

        // Should have low confidence or be filtered out
        if !strings.is_empty() {
            assert!(strings[0].confidence < 0.7);
        }
    }

    #[test]
    fn test_utf16_empty_data() {
        let data = &[];
        let config = Utf16ExtractionConfig::default();
        let strings = extract_utf16_strings(data, &config);
        assert!(strings.is_empty());
    }

    #[test]
    fn test_utf16_odd_length_data() {
        let data = &[0x48, 0x00, 0x65, 0x00, 0x6C];
        let config = Utf16ExtractionConfig::default();
        let _strings = extract_utf16_strings(data, &config);
        // Should not panic
    }

    #[test]
    fn test_extract_from_section_metadata() {
        let section = create_test_section(".rdata", 0, 30, Some(0x1000));
        let mut data = create_utf16le_string("Hello World");
        data.extend_from_slice(&[0x00, 0x00]);

        let config = Utf16ExtractionConfig::default();
        let strings = extract_from_section(&section, &data, &config, None, false, 0.5);

        assert!(!strings.is_empty());
        assert_eq!(strings[0].section, Some(".rdata".to_string()));
        assert_eq!(strings[0].rva, Some(0x1000));
    }
}
