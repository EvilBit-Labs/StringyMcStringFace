//! UTF-16LE String Extraction Module
//!
//! This module provides UTF-16LE string extraction for StringyMcStringFace, following
//! the pattern established in the ASCII extractor. It implements byte-level scanning
//! for contiguous UTF-16LE character sequences with confidence scoring and noise filtering.
//!
//! # Examples
//!
//! ```rust
//! use stringy::extraction::utf16::{extract_utf16le_strings, extract_from_section, Utf16ExtractionConfig};
//! use stringy::types::{SectionInfo, SectionType};
//!
//! // Basic extraction from raw data
//! let data = &[0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00, 0x00, 0x00]; // "Hello\0" in UTF-16LE
//! let config = Utf16ExtractionConfig::default();
//! let strings = extract_utf16le_strings(data, &config);
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
//! let strings = extract_from_section(&section, data, &config, None, false, 0.7);
//! ```

use crate::extraction::config::NoiseFilterConfig;
use crate::extraction::filters::{CompositeNoiseFilter, FilterContext};
use crate::types::{Encoding, FoundString, SectionInfo, StringSource};

/// Configuration for UTF-16LE string extraction
///
/// Controls minimum and maximum character count filtering, as well as confidence thresholds.
/// Character count refers to the number of UTF-16 code units (characters), not bytes.
///
/// # Default Values
///
/// - `min_char_len`: 3 (minimum character count = 6 bytes)
/// - `max_char_len`: None (no upper limit by default)
/// - `min_confidence`: 0.7 (minimum confidence threshold)
///
/// # Examples
///
/// ```rust
/// use stringy::extraction::utf16::Utf16ExtractionConfig;
///
/// // Use default configuration
/// let config = Utf16ExtractionConfig::default();
///
/// // Custom minimum character length
/// let config = Utf16ExtractionConfig::new(5);
///
/// // Custom minimum and maximum character length
/// let mut config = Utf16ExtractionConfig::default();
/// config.max_char_len = Some(256);
/// config.min_confidence = 0.8;
/// ```
#[derive(Debug, Clone)]
pub struct Utf16ExtractionConfig {
    /// Minimum character count (default: 3)
    pub min_char_len: usize,
    /// Maximum character count (default: None, no limit)
    pub max_char_len: Option<usize>,
    /// Minimum confidence threshold (default: 0.7)
    pub min_confidence: f32,
}

impl Default for Utf16ExtractionConfig {
    fn default() -> Self {
        Self {
            min_char_len: 3,
            max_char_len: None,
            min_confidence: 0.7,
        }
    }
}

impl Utf16ExtractionConfig {
    /// Create a new Utf16ExtractionConfig with custom minimum character length
    ///
    /// # Arguments
    ///
    /// * `min_char_len` - Minimum character count
    ///
    /// # Returns
    ///
    /// New Utf16ExtractionConfig with specified minimum character length and default max_char_len (None)
    ///
    /// # Example
    ///
    /// ```rust
    /// use stringy::extraction::utf16::Utf16ExtractionConfig;
    ///
    /// let config = Utf16ExtractionConfig::new(5);
    /// assert_eq!(config.min_char_len, 5);
    /// assert_eq!(config.max_char_len, None);
    /// ```
    pub fn new(min_char_len: usize) -> Self {
        Self {
            min_char_len,
            max_char_len: None,
            min_confidence: 0.7,
        }
    }
}

/// Check if a UTF-16LE code unit or surrogate pair is printable
///
/// A UTF-16LE character is considered printable if:
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
///
/// # Example
///
/// ```rust
/// use stringy::extraction::utf16::is_printable_code_unit_or_pair;
///
/// assert_eq!(is_printable_code_unit_or_pair(0x0048, None), (true, 1)); // 'H'
/// assert_eq!(is_printable_code_unit_or_pair(0x0020, None), (true, 1)); // space
/// assert_eq!(is_printable_code_unit_or_pair(0x0000, None), (false, 1)); // null terminator
/// ```
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

/// Decode UTF-16LE byte sequence to UTF-8 String
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
///
/// # Example
///
/// ```rust
/// use stringy::extraction::utf16::decode_utf16le_bytes;
///
/// // "Hello" in UTF-16LE: 48 00 65 00 6C 00 6C 00 6F 00
/// let bytes = &[0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00];
/// let result = decode_utf16le_bytes(bytes);
/// assert!(result.is_ok());
/// assert_eq!(result.unwrap(), "Hello");
/// ```
#[allow(clippy::result_unit_err)]
pub fn decode_utf16le_bytes(bytes: &[u8]) -> Result<String, ()> {
    crate::extraction::util::decode_utf16le_bytes(bytes, false).map_err(|_| ())
}

/// Calculate confidence score for a UTF-16LE string candidate
///
/// Confidence is based on:
/// - Percentage of printable characters (>90% = high, >70% = medium, >50% = low)
/// - Presence of proper null termination (bonus)
/// - Character count (longer strings get slight bonus)
///
/// # Arguments
///
/// * `data` - Byte slice containing the UTF-16LE string candidate
/// * `char_count` - Number of UTF-16 characters found
/// * `has_null_terminator` - Whether the string has a proper null terminator (0x00 0x00)
///
/// # Returns
///
/// Confidence score between 0.0 and 1.0
///
/// # Example
///
/// ```rust
/// use stringy::extraction::utf16::calculate_confidence;
///
/// // High confidence: all printable with null terminator
/// let data = &[0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00, 0x00, 0x00];
/// let confidence = calculate_confidence(data, 5, true);
/// assert!(confidence > 0.9);
/// ```
pub fn calculate_confidence(data: &[u8], char_count: usize, has_null_terminator: bool) -> f32 {
    if char_count == 0 {
        return 0.0;
    }

    // Count printable characters (operating on u16 code units, handling surrogate pairs)
    let mut printable_count = 0;
    let mut total_chars = 0;
    let mut i = 0;

    while i + 1 < data.len() {
        let code_unit = u16::from_le_bytes([data[i], data[i + 1]]);

        // Check if we have a next code unit for surrogate pair detection
        let next_code_unit = if i + 3 < data.len() {
            Some(u16::from_le_bytes([data[i + 2], data[i + 3]]))
        } else {
            None
        };

        let (is_printable, consumed_units) =
            is_printable_code_unit_or_pair(code_unit, next_code_unit);
        total_chars += 1; // Count as single character (even if surrogate pair)
        if is_printable {
            printable_count += 1;
        }

        i += consumed_units * 2; // Advance by number of bytes
    }

    if total_chars == 0 {
        return 0.0;
    }

    let printable_ratio = printable_count as f32 / total_chars as f32;

    // Base confidence from printable ratio
    let mut confidence = if printable_ratio > 0.9 {
        0.9 // High confidence
    } else if printable_ratio > 0.7 {
        0.7 // Medium confidence
    } else if printable_ratio > 0.5 {
        0.5 // Low confidence
    } else {
        0.2 // Very low confidence
    };

    // Bonus for proper null termination
    if has_null_terminator {
        confidence = (confidence + 0.1f32).min(1.0f32);
    }

    // Slight bonus for reasonable length (3-100 characters)
    if (3..=100).contains(&char_count) {
        confidence = (confidence + 0.05f32).min(1.0f32);
    }

    confidence
}

/// Extract UTF-16LE strings from a byte slice with a specific starting parity
///
/// Scans through the byte slice starting at a specific byte offset parity (0 for even, 1 for odd).
/// This allows scanning both alignments to catch strings that may be misaligned.
///
/// # Arguments
///
/// * `data` - Byte slice to scan for UTF-16LE strings
/// * `config` - Extraction configuration
/// * `start_parity` - Starting byte offset parity (0 for even, 1 for odd)
///
/// # Returns
///
/// Vector of FoundString entries
fn extract_utf16le_strings_with_parity(
    data: &[u8],
    config: &Utf16ExtractionConfig,
    start_parity: usize,
) -> Vec<FoundString> {
    let mut strings = Vec::new();

    // Need at least 2 bytes for a UTF-16LE character
    if data.len() < 2 {
        return strings;
    }

    // Scan starting at specified parity offset
    let mut i = start_parity;
    while i + 1 < data.len() {
        let mut char_count = 0;
        let start = i;
        let mut has_null_terminator = false;

        // Accumulate printable UTF-16LE characters (operating on u16 code units)
        while i + 1 < data.len() {
            // Read current code unit as u16
            let code_unit = u16::from_le_bytes([data[i], data[i + 1]]);

            // Check for null terminator (0x0000)
            if code_unit == 0x0000 {
                has_null_terminator = true;
                break;
            }

            // Check if we have a next code unit for surrogate pair detection
            let next_code_unit = if i + 3 < data.len() {
                Some(u16::from_le_bytes([data[i + 2], data[i + 3]]))
            } else {
                None
            };

            // Check if character is printable (handles surrogate pairs)
            let (is_printable, consumed_units) =
                is_printable_code_unit_or_pair(code_unit, next_code_unit);

            if is_printable {
                char_count += 1; // Count as single character (even if surrogate pair)
                i += consumed_units * 2; // Advance by number of bytes (2 per code unit)
            } else {
                // Non-printable character or lone surrogate, end of string candidate
                break;
            }
        }

        // Check if we found a valid string
        if char_count >= config.min_char_len {
            // Check maximum length if configured
            if let Some(max_len) = config.max_char_len
                && char_count > max_len
            {
                // Skip this string, move to next position
                i += 2;
                continue;
            }

            // Calculate end position (including null terminator if present)
            let end = if has_null_terminator { i + 2 } else { i };

            // Extract the string bytes (excluding null terminator for decoding)
            let string_bytes = &data[start..end.min(data.len())];
            let bytes_for_decoding = if has_null_terminator && string_bytes.len() >= 2 {
                &string_bytes[..string_bytes.len() - 2]
            } else {
                string_bytes
            };

            // Decode to UTF-8
            if let Ok(text) = decode_utf16le_bytes(bytes_for_decoding) {
                // Calculate confidence score
                let confidence =
                    calculate_confidence(bytes_for_decoding, char_count, has_null_terminator);

                // Apply confidence threshold
                if confidence >= config.min_confidence {
                    strings.push(FoundString {
                        text,
                        encoding: Encoding::Utf16Le,
                        offset: start as u64,
                        rva: None,
                        section: None,
                        length: bytes_for_decoding.len() as u32,
                        tags: Vec::new(),
                        score: 0,
                        source: StringSource::SectionData,
                        confidence,
                    });
                }
            }
        }

        // Move to next potential start position
        // If we found a null terminator, skip past it
        if has_null_terminator {
            i += 2;
        } else {
            // Move forward by 2 bytes to try next alignment
            i += 2;
        }
    }

    strings
}

/// Extract UTF-16LE strings from a byte slice
///
/// Scans through the byte slice looking for contiguous sequences of printable UTF-16LE
/// characters. When a non-printable character or null terminator is encountered, checks
/// if the accumulated sequence meets the minimum character length and confidence thresholds.
///
/// This function scans at even offsets (parity 0) by default. For comprehensive extraction
/// that handles misaligned strings, use `extract_from_section` which scans both alignments.
///
/// # Algorithm
///
/// 1. Iterate through the byte slice at even offsets (UTF-16LE requires 2-byte alignment)
/// 2. For each position, accumulate printable UTF-16LE characters
/// 3. Detect null termination (0x00 0x00 sequence)
/// 4. Calculate confidence score for each candidate
/// 5. Filter by minimum character length and confidence threshold
/// 6. Convert to `FoundString` with `Encoding::Utf16Le`, proper offset, length (in bytes), and confidence score
/// 7. Handle edge cases: partial strings at buffer boundaries, strings at start/end of data
///
/// # Arguments
///
/// * `data` - Byte slice to scan for UTF-16LE strings
/// * `config` - Extraction configuration
///
/// # Returns
///
/// Vector of FoundString entries with the following metadata:
/// - `text`: UTF-8 string decoded from UTF-16LE bytes
/// - `encoding`: `Encoding::Utf16Le`
/// - `offset`: Start position in the data slice
/// - `length`: Byte count
/// - `source`: `StringSource::SectionData`
/// - `tags`: Empty vector
/// - `score`: 0
/// - `section`: None
/// - `rva`: None
/// - `confidence`: Calculated confidence score
///
/// # Edge Cases
///
/// - Empty input data returns empty vector
/// - Data smaller than minimum length returns empty vector
/// - String at buffer start (start_offset = 0)
/// - String at buffer end (checked after loop)
/// - Odd-length data is handled gracefully (last byte ignored)
///
/// # Example
///
/// ```rust
/// use stringy::extraction::utf16::{extract_utf16le_strings, Utf16ExtractionConfig};
///
/// // "Hello\0World\0" in UTF-16LE
/// let data = &[
///     0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00, 0x00, 0x00, // "Hello\0"
///     0x57, 0x00, 0x6F, 0x00, 0x72, 0x00, 0x6C, 0x00, 0x64, 0x00, 0x00, 0x00, // "World\0"
/// ];
/// let config = Utf16ExtractionConfig::default();
/// let strings = extract_utf16le_strings(data, &config);
///
/// assert_eq!(strings.len(), 2);
/// assert_eq!(strings[0].text, "Hello");
/// assert_eq!(strings[0].offset, 0);
/// assert_eq!(strings[1].text, "World");
/// assert_eq!(strings[1].offset, 12);
/// ```
pub fn extract_utf16le_strings(data: &[u8], config: &Utf16ExtractionConfig) -> Vec<FoundString> {
    extract_utf16le_strings_with_parity(data, config, 0)
}

/// Extract UTF-16LE strings from a specific section with proper metadata population
///
/// This function extracts strings from a section of the binary, adjusting offsets
/// and populating section-specific metadata (section name, RVA). It also applies
/// noise filtering if enabled in the extraction configuration.
///
/// # Implementation
///
/// 1. Calculate section data slice using section.offset and section.size, with bounds checking
/// 2. Call `extract_utf16le_strings` on the section data slice
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
/// use stringy::extraction::utf16::{extract_from_section, Utf16ExtractionConfig};
/// use stringy::extraction::config::NoiseFilterConfig;
/// use stringy::types::{SectionInfo, SectionType};
///
/// let section = SectionInfo {
///     name: ".rdata".to_string(),
///     offset: 10,
///     size: 20,
///     rva: Some(0x1000),
///     section_type: SectionType::StringData,
///     is_executable: false,
///     is_writable: false,
///     weight: 1.0,
/// };
///
/// // "Hello\0" in UTF-16LE
/// let data = &[
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // prefix
///     0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00, 0x00, 0x00, // "Hello\0"
/// ];
/// let config = Utf16ExtractionConfig::default();
/// let noise_config = Some(NoiseFilterConfig::default());
/// let strings = extract_from_section(&section, data, &config, noise_config.as_ref(), true, 0.5);
///
/// // Strings will have adjusted offsets and section metadata
/// for string in strings {
///     assert_eq!(string.section, Some(".rdata".to_string()));
///     assert!(string.offset >= 10);
/// }
/// ```
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

    // Compute starting parity based on section offset
    // UTF-16LE strings must be aligned to even byte offsets in the file
    // If section starts at even offset, strings aligned to file are at even offsets relative to section (parity 0)
    // If section starts at odd offset, strings aligned to file are at odd offsets relative to section (parity 1)
    // However, we also need to scan with the opposite parity to catch strings that might be misaligned
    let start_parity = (section.offset % 2) as usize;

    // Extract strings from section data with section's natural alignment
    let mut strings = extract_utf16le_strings_with_parity(section_data, config, start_parity);

    // Also scan with opposite parity to catch misaligned strings
    // This helps catch strings that might be at different alignments within the section
    let opposite_parity = 1 - start_parity;
    let opposite_strings =
        extract_utf16le_strings_with_parity(section_data, config, opposite_parity);

    // Merge results, avoiding duplicates and overlapping strings
    // Prefer strings found at natural alignment (already in strings)
    let mut seen_text: std::collections::HashSet<String> = std::collections::HashSet::new();
    for string in &strings {
        seen_text.insert(string.text.clone());
    }

    for string in opposite_strings {
        // Skip if we already have this text from natural alignment scan
        if seen_text.contains(&string.text) {
            continue;
        }

        // Filter out misaligned strings by checking confidence
        // Misaligned strings typically have lower confidence due to invalid character sequences
        if string.confidence < config.min_confidence {
            continue;
        }

        // Check if this string overlaps significantly with any existing string
        let mut overlaps = false;
        for existing in &strings {
            // Check if strings overlap by comparing their byte ranges
            // Strings overlap if their offsets are within each other's length
            let existing_start = existing.offset as usize;
            let existing_end = existing_start + existing.length as usize;
            let new_start = string.offset as usize;
            let new_end = new_start + string.length as usize;

            // Check for overlap (allowing small gaps)
            if new_start < existing_end && new_end > existing_start {
                overlaps = true;
                break;
            }
        }

        if !overlaps {
            seen_text.insert(string.text.clone());
            strings.push(string);
        }
    }

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
            // Combine extraction confidence with noise filter confidence
            let noise_confidence = noise_filter.calculate_confidence(&string.text, &filter_context);
            // Use the minimum of extraction confidence and noise confidence
            string.confidence = string.confidence.min(noise_confidence);
            // Apply threshold filtering
            if noise_filtering_enabled && string.confidence < min_confidence_threshold {
                continue;
            }
        } else {
            // If filtering is disabled, keep extraction confidence
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
    fn test_is_printable_utf16le_char() {
        // Printable ASCII characters
        assert!(is_printable_utf16le_char(0x20, 0x00)); // space
        assert!(is_printable_utf16le_char(0x41, 0x00)); // 'A'
        assert!(is_printable_utf16le_char(0x7A, 0x00)); // 'z'
        assert!(is_printable_utf16le_char(0x30, 0x00)); // '0'
        assert!(is_printable_utf16le_char(0x7E, 0x00)); // '~'

        // Common whitespace
        assert!(is_printable_utf16le_char(0x09, 0x00)); // tab
        assert!(is_printable_utf16le_char(0x0A, 0x00)); // newline
        assert!(is_printable_utf16le_char(0x0D, 0x00)); // carriage return
        assert!(is_printable_utf16le_char(0xA0, 0x00)); // non-breaking space (U+00A0)

        // Non-ASCII printable characters (BMP)
        assert!(is_printable_utf16le_char(0xFF, 0x00)); // 'ÿ' (U+00FF)
        assert!(is_printable_utf16le_char(0x48, 0x01)); // 'ň' (U+0148)
        assert!(is_printable_utf16le_char(0xA9, 0x00)); // '©' (U+00A9)

        // Non-printable
        assert!(!is_printable_utf16le_char(0x00, 0x00)); // null
        assert!(!is_printable_utf16le_char(0x1F, 0x00)); // control character
        assert!(!is_printable_utf16le_char(0x7F, 0x00)); // DEL (control)
        assert!(!is_printable_utf16le_char(0x80, 0x00)); // control (0x80-0x9F range)
        assert!(!is_printable_utf16le_char(0x9F, 0x00)); // control (0x80-0x9F range)

        // Surrogates (should be excluded)
        assert!(!is_printable_utf16le_char(0x00, 0xD8)); // high surrogate start
        assert!(!is_printable_utf16le_char(0xFF, 0xDF)); // low surrogate end

        // Non-characters (should be excluded)
        assert!(!is_printable_utf16le_char(0xD0, 0xFD)); // 0xFDD0
        assert!(!is_printable_utf16le_char(0xEF, 0xFD)); // 0xFDEF
        assert!(!is_printable_utf16le_char(0xFE, 0xFF)); // U+FFFE
        assert!(!is_printable_utf16le_char(0xFF, 0xFF)); // U+FFFF
    }

    #[test]
    fn test_decode_utf16le_bytes() {
        // "Hello" in UTF-16LE
        let bytes = &[0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00];
        let result = decode_utf16le_bytes(bytes);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Hello");

        // Empty input
        let result = decode_utf16le_bytes(&[]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "");

        // Odd-length input (should truncate last byte)
        let bytes = &[0x48, 0x00, 0x65, 0x00, 0x6C];
        let result = decode_utf16le_bytes(bytes);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "He");
    }

    #[test]
    fn test_calculate_confidence() {
        // High confidence: all printable with null terminator
        let data = &[0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00];
        let confidence = calculate_confidence(data, 5, true);
        assert!(confidence > 0.9);

        // Medium confidence: all printable without null terminator (gets length bonus)
        let confidence = calculate_confidence(data, 5, false);
        assert!(confidence >= 0.7);

        // Low confidence: mixed printable/non-printable (using control character 0x7F DEL)
        let data = &[0x48, 0x00, 0x7F, 0x00, 0x6C, 0x00];
        let confidence = calculate_confidence(data, 3, false);
        assert!(confidence < 0.7);
    }

    #[test]
    fn test_extract_utf16le_strings_basic() {
        // "Hello\0World\0" in UTF-16LE
        let mut data = create_utf16le_string("Hello");
        data.extend_from_slice(&[0x00, 0x00]); // null terminator
        let world = create_utf16le_string("World");
        data.extend_from_slice(&world);
        data.extend_from_slice(&[0x00, 0x00]); // null terminator

        let config = Utf16ExtractionConfig::default();
        let strings = extract_utf16le_strings(&data, &config);

        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].text, "Hello");
        assert_eq!(strings[0].offset, 0);
        assert_eq!(strings[0].encoding, Encoding::Utf16Le);
        assert_eq!(strings[1].text, "World");
        assert_eq!(strings[1].offset, 12); // "Hello\0" = 10 bytes + 2 null bytes
    }

    #[test]
    fn test_extract_utf16le_strings_minimum_length() {
        // "Hi\0Test\0AB\0LongString\0" in UTF-16LE
        let mut data = create_utf16le_string("Hi");
        data.extend_from_slice(&[0x00, 0x00]);
        let test = create_utf16le_string("Test");
        data.extend_from_slice(&test);
        data.extend_from_slice(&[0x00, 0x00]);
        let ab = create_utf16le_string("AB");
        data.extend_from_slice(&ab);
        data.extend_from_slice(&[0x00, 0x00]);
        let long = create_utf16le_string("LongString");
        data.extend_from_slice(&long);
        data.extend_from_slice(&[0x00, 0x00]);

        let config = Utf16ExtractionConfig::new(3); // min_char_len = 3
        let strings = extract_utf16le_strings(&data, &config);

        // "Hi" (2 chars) and "AB" (2 chars) should be filtered out
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].text, "Test");
        assert_eq!(strings[1].text, "LongString");
    }

    #[test]
    fn test_extract_utf16le_strings_empty_input() {
        let data = &[];
        let config = Utf16ExtractionConfig::default();
        let strings = extract_utf16le_strings(data, &config);
        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_utf16le_strings_no_valid_strings() {
        // Binary data with no valid UTF-16LE sequences
        let data = &[0xFF, 0xFF, 0x01, 0x02, 0x03, 0x04];
        let config = Utf16ExtractionConfig::default();
        let strings = extract_utf16le_strings(data, &config);
        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_utf16le_strings_null_terminated() {
        // Test proper null termination detection
        let mut data = create_utf16le_string("Test");
        data.extend_from_slice(&[0x00, 0x00]); // null terminator
        let hello = create_utf16le_string("Hello");
        data.extend_from_slice(&hello);
        data.extend_from_slice(&[0x00, 0x00]); // null terminator

        let config = Utf16ExtractionConfig::default();
        let strings = extract_utf16le_strings(&data, &config);

        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].text, "Test");
        assert_eq!(strings[1].text, "Hello");
    }

    #[test]
    fn test_extract_utf16le_strings_string_at_start() {
        // String at buffer start
        let mut data = create_utf16le_string("Start");
        data.extend_from_slice(&[0x00, 0x00]);
        let middle = create_utf16le_string("Middle");
        data.extend_from_slice(&middle);
        data.extend_from_slice(&[0x00, 0x00]);

        let config = Utf16ExtractionConfig::default();
        let strings = extract_utf16le_strings(&data, &config);

        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].text, "Start");
        assert_eq!(strings[0].offset, 0);
    }

    #[test]
    fn test_extract_utf16le_strings_string_at_end() {
        // String at buffer end without null terminator
        let mut data = create_utf16le_string("Start");
        data.extend_from_slice(&[0x00, 0x00]);
        let end = create_utf16le_string("EndTest");
        data.extend_from_slice(&end);

        let config = Utf16ExtractionConfig::default();
        let strings = extract_utf16le_strings(&data, &config);

        assert_eq!(strings.len(), 2);
        assert_eq!(strings[1].text, "EndTest");
    }

    #[test]
    fn test_extract_utf16le_strings_odd_length_data() {
        // Odd-length data should be handled gracefully
        let data = &[0x48, 0x00, 0x65, 0x00, 0x6C]; // Odd length
        let config = Utf16ExtractionConfig::default();
        let strings = extract_utf16le_strings(data, &config);
        // Should not panic, may or may not find strings depending on alignment
        assert!(strings.len() <= 1);
    }

    #[test]
    fn test_extract_utf16le_strings_max_length_filtering() {
        // Test maximum length filtering
        let mut data = create_utf16le_string("Short");
        data.extend_from_slice(&[0x00, 0x00]);
        let long_string = "A".repeat(100);
        let long = create_utf16le_string(&long_string);
        data.extend_from_slice(&long);
        data.extend_from_slice(&[0x00, 0x00]);

        let config = Utf16ExtractionConfig {
            max_char_len: Some(10),
            ..Default::default()
        };
        let strings = extract_utf16le_strings(&data, &config);

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].text, "Short");
    }

    #[test]
    fn test_extract_from_section_basic() {
        let section = create_test_section(".rdata", 0, 30, Some(0x1000));
        let mut data = create_utf16le_string("Hello World");
        data.extend_from_slice(&[0x00, 0x00]);
        let test = create_utf16le_string("Test");
        data.extend_from_slice(&test);
        data.extend_from_slice(&[0x00, 0x00]);

        let config = Utf16ExtractionConfig::default();
        let strings = extract_from_section(&section, &data, &config, None, false, 0.5);

        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].text, "Hello World");
        assert_eq!(strings[0].offset, 0);
        assert_eq!(strings[0].rva, Some(0x1000));
        assert_eq!(strings[0].section, Some(".rdata".to_string()));
    }

    #[test]
    fn test_extract_from_section_offset_adjustment() {
        let section = create_test_section(".data", 7, 12, Some(0x2000));
        let mut prefix = vec![0x00; 7];
        let hello = create_utf16le_string("Hello");
        prefix.extend_from_slice(&hello);
        prefix.extend_from_slice(&[0x00, 0x00]);

        let config = Utf16ExtractionConfig::default();
        let strings = extract_from_section(&section, &prefix, &config, None, false, 0.5);

        // Should find "Hello" string
        let hello_strings: Vec<_> = strings.iter().filter(|s| s.text == "Hello").collect();
        assert!(
            !hello_strings.is_empty(),
            "Should find at least one 'Hello' string"
        );
        // Find the one at the correct offset (7)
        let hello_at_offset = hello_strings.iter().find(|s| s.offset == 7);
        assert!(hello_at_offset.is_some(), "Should find 'Hello' at offset 7");
        assert_eq!(hello_at_offset.unwrap().rva, Some(0x2000));
    }

    #[test]
    fn test_extract_from_section_bounds_checking() {
        let section = create_test_section(".data", 0, 1000, None);
        let data = create_utf16le_string("Short data");
        let config = Utf16ExtractionConfig::default();
        let strings = extract_from_section(&section, &data, &config, None, false, 0.5);

        // Should only extract from available data, not panic
        assert!(strings.len() <= 1);
    }

    #[test]
    fn test_extract_from_section_out_of_bounds() {
        let section = create_test_section(".data", 1000, 100, None);
        let data = create_utf16le_string("Short data");
        let config = Utf16ExtractionConfig::default();
        let strings = extract_from_section(&section, &data, &config, None, false, 0.5);

        // Should return empty vector, not panic
        assert!(strings.is_empty());
    }

    #[test]
    fn test_config_defaults() {
        let config = Utf16ExtractionConfig::default();
        assert_eq!(config.min_char_len, 3);
        assert_eq!(config.max_char_len, None);
        assert_eq!(config.min_confidence, 0.7);
    }

    #[test]
    fn test_config_new() {
        let config = Utf16ExtractionConfig::new(5);
        assert_eq!(config.min_char_len, 5);
        assert_eq!(config.max_char_len, None);
        assert_eq!(config.min_confidence, 0.7);
    }
}
