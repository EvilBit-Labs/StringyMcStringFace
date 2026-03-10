//! Core ASCII string extraction functions
//!
//! Contains the main extraction algorithms for scanning byte slices
//! and section-aware extraction with metadata population.

use crate::extraction::config::NoiseFilterConfig;
use crate::extraction::filters::{CompositeNoiseFilter, FilterContext};
use crate::types::{Encoding, FoundString, SectionInfo, StringSource};

use super::{AsciiExtractionConfig, is_printable_ascii};

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
                        display_score: None,
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
                        display_score: None,
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
                    display_score: None,
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
/// let section = SectionInfo::new(
///     ".rodata".to_string(),
///     10,
///     20,
///     SectionType::StringData,
///     1.0,
/// )
/// .with_rva(0x1000);
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
