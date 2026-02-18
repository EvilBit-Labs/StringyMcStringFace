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

mod confidence;
mod config;
mod extraction;
#[cfg(test)]
mod tests;
mod validation;

pub use config::Utf16ExtractionConfig;
pub use extraction::{decode_utf16le_bytes, extract_from_section};
pub use validation::{is_printable_code_unit_or_pair, is_printable_utf16le_char};

use std::collections::HashMap;

use crate::types::{Encoding, FoundString};
use extraction::{extract_utf16be_strings_internal, extract_utf16le_strings_internal};

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
            // Extract both LE and BE, merge results with O(1) dedup
            let le_strings = extract_utf16le_strings_internal(data, config);
            let be_strings = extract_utf16be_strings_internal(data, config);

            // Use HashMap for O(1) dedup by (offset, encoding, text)
            let mut seen: HashMap<(u64, Encoding, String), usize> = HashMap::new();

            for string in le_strings.into_iter().chain(be_strings) {
                let key = (string.offset, string.encoding, string.text.clone());
                if let Some(&idx) = seen.get(&key) {
                    if string.confidence > strings[idx].confidence {
                        strings[idx] = string;
                    }
                } else {
                    seen.insert(key, strings.len());
                    strings.push(string);
                }
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
    let config_le = Utf16ExtractionConfig {
        byte_order: ByteOrder::LE,
        ..config.clone()
    };
    extract_utf16_strings(data, &config_le)
}
