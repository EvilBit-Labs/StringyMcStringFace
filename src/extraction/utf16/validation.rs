//! UTF-16 validation functions
//!
//! Functions for validating UTF-16 sequences, checking Unicode ranges,
//! detecting null patterns, and determining character printability.

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

                // Reject noncharacters in supplementary planes (U+xFFFE, U+xFFFF)
                if code_point & 0xFFFE == 0xFFFE {
                    return (false, 2);
                }

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
pub(crate) fn check_valid_unicode_range(chars: &[u16]) -> f32 {
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

    valid_count as f32 / chars.len() as f32
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
pub(crate) fn check_null_pattern(chars: &[u16]) -> f32 {
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
