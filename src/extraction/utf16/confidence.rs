//! UTF-16 confidence scoring
//!
//! Functions for calculating confidence scores on extracted UTF-16 strings.
//! Uses multiple heuristics including ASCII ratio, printable ratio, byte order
//! consistency, and Unicode range validation.

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

    printable_count as f32 / chars.len() as f32
}

/// Calculate UTF-16-specific confidence score
///
/// Combines multiple heuristics to calculate a confidence score for UTF-16 strings.
/// Uses weighted formula with penalties for suspicious patterns.
///
/// # Arguments
///
/// * `chars` - Slice of UTF-16 code units
///
/// # Returns
///
/// Confidence score (0.0-1.0)
pub(crate) fn calculate_utf16_confidence(chars: &[u16]) -> f32 {
    if chars.is_empty() {
        return 0.0;
    }

    // Calculate individual components
    let valid_unicode_ratio = check_valid_unicode_range(chars);
    let printable_ratio = check_printable_ratio(chars);
    let ascii_ratio = check_ascii_ratio(chars);
    let null_pattern_penalty = check_null_pattern(chars);

    // Weights for combining heuristics (must sum to 1.0)
    let valid_unicode_weight = 0.35;
    let printable_weight = 0.45;
    let ascii_weight = 0.2;

    // Calculate base confidence
    let mut confidence = (valid_unicode_weight * valid_unicode_ratio)
        + (printable_weight * printable_ratio)
        + (ascii_weight * ascii_ratio);

    // Apply penalties
    confidence -= null_pattern_penalty;

    // Clamp to 0.0-1.0 range
    confidence.clamp(0.0, 1.0)
}
