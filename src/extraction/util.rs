//! Utility functions for string extraction
//!
//! This module provides shared utility functions used across multiple extractors.

use crate::types::Result;

/// Decode UTF-16LE byte sequence to UTF-8 String
///
/// Converts a UTF-16LE byte sequence to a UTF-8 String using `u16::from_le_bytes`
/// and `String::from_utf16`. Handles odd-length inputs gracefully by truncating
/// the last byte.
///
/// # Arguments
///
/// * `bytes` - UTF-16LE encoded byte slice
/// * `trim_nulls` - Whether to trim trailing null terminators from the decoded string
///
/// # Returns
///
/// Decoded UTF-8 string, or error if decoding fails
///
/// # Example
///
/// ```rust
/// use stringy::extraction::util::decode_utf16le_bytes;
///
/// // "Hello" in UTF-16LE: 48 00 65 00 6C 00 6C 00 6F 00
/// let bytes = &[0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00];
/// let result = decode_utf16le_bytes(bytes, false);
/// assert!(result.is_ok());
/// assert_eq!(result.unwrap(), "Hello");
/// ```
pub fn decode_utf16le_bytes(bytes: &[u8], trim_nulls: bool) -> Result<String> {
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
    let decoded = String::from_utf16(&u16_slice)
        .map_err(|_| crate::types::StringyError::EncodingError { offset: 0 })?;

    // Optionally trim trailing null terminators
    if trim_nulls {
        Ok(decoded.trim_end_matches('\0').to_string())
    } else {
        Ok(decoded)
    }
}
