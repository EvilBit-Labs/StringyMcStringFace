//! UTF-16 string extraction functions
//!
//! Contains the core extraction logic for scanning byte slices for UTF-16 strings
//! in both LE and BE byte orders, as well as section-aware extraction with metadata
//! population and noise filtering.

use crate::extraction::config::NoiseFilterConfig;
use crate::extraction::filters::{CompositeNoiseFilter, FilterContext};
use crate::types::{Encoding, FoundString, SectionInfo, StringSource};

use super::ByteOrder;
use super::Utf16ExtractionConfig;
use super::confidence::calculate_utf16_confidence;
use super::validation::is_printable_code_unit_or_pair;

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
// Unit error is intentional: callers only need success/failure, no actionable error detail
#[allow(clippy::result_unit_err)]
pub fn decode_utf16le_bytes(bytes: &[u8]) -> Result<String, ()> {
    decode_utf16le(bytes).map(|(s, _)| s)
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
pub(crate) fn extract_utf16le_strings_internal(
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
pub(crate) fn extract_utf16be_strings_internal(
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
                            original_text: None,
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
                            section_weight: None,
                            semantic_boost: None,
                            noise_penalty: None,
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
    let strings = super::extract_utf16_strings(section_data, config);

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
