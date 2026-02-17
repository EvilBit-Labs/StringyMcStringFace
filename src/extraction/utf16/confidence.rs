//! UTF-16 confidence scoring
//!
//! Functions for calculating confidence scores on extracted UTF-16 strings.
//! Uses multiple heuristics including ASCII ratio, printable ratio, byte order
//! consistency, and Unicode range validation.

use super::ByteOrder;
use super::validation::{
    check_null_pattern, check_valid_unicode_range, is_printable_code_unit_or_pair,
};

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
pub(crate) fn calculate_utf16_confidence(chars: &[u16], byte_order: ByteOrder) -> f32 {
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
