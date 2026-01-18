//! Data format classification patterns
//!
//! This module provides GUID, email, Base64, format string, and user agent detection.

use crate::types::Tag;
use once_cell::sync::Lazy;
use regex::Regex;

/// Regular expression for matching GUIDs/UUIDs
///
/// Pattern matches standard GUID format: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
/// Also matches without braces and in lowercase.
pub(crate) static GUID_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$").unwrap()
});

/// Regular expression for matching email addresses
///
/// Pattern matches basic email format: user@domain.tld
pub(crate) static EMAIL_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap());

/// Regular expression for matching printf-style format strings
///
/// Pattern detects format specifiers like %s, %d, %x, %f, etc.
pub(crate) static FORMAT_STRING_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"%[-+0 #]*(\d+|\*)?(\.(\d+|\*))?(hh?|ll?|[Lzjt])?[diouxXeEfFgGaAcspn%]").unwrap()
});

/// Regular expression for matching common user agent patterns
///
/// Pattern matches common browser/bot user agent strings.
pub(crate) static USER_AGENT_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^Mozilla/\d|^curl/|^Wget/|^python-requests|^libwww-perl|^Java/|^Apache-HttpClient|^okhttp/|^PostmanRuntime/")
        .unwrap()
});

/// Classifies a GUID/UUID
///
/// # Arguments
/// * `text` - The text to check for GUID format
///
/// # Returns
/// Returns `Some(Tag::Guid)` if valid, `None` otherwise.
pub fn classify_guid(text: &str) -> Option<Tag> {
    if GUID_REGEX.is_match(text) {
        Some(Tag::Guid)
    } else {
        None
    }
}

/// Classifies an email address
///
/// # Arguments
/// * `text` - The text to check for email format
///
/// # Returns
/// Returns `Some(Tag::Email)` if valid, `None` otherwise.
pub fn classify_email(text: &str) -> Option<Tag> {
    if EMAIL_REGEX.is_match(text) {
        Some(Tag::Email)
    } else {
        None
    }
}

/// Classifies Base64-encoded data
///
/// This is a broad/ambiguous tag with potential false positives.
/// Returns `Some(Tag::Base64)` if the text appears to be Base64 encoded.
///
/// Detection criteria:
/// - Minimum length of 16 characters
/// - Only valid Base64 characters (A-Z, a-z, 0-9, +, /, =)
/// - Proper padding (if present)
/// - Length is a multiple of 4 or has valid padding
/// - For unpadded strings: must have both uppercase and lowercase letters
pub fn classify_base64(text: &str) -> Option<Tag> {
    // Minimum length to reduce false positives
    if text.len() < 16 {
        return None;
    }

    // Check if it's valid Base64 characters only
    let is_base64_chars = text
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');

    if !is_base64_chars {
        return None;
    }

    // Count padding characters
    let padding_count = text.chars().rev().take_while(|&c| c == '=').count();

    // Padding should be at most 2 characters
    if padding_count > 2 {
        return None;
    }

    // Strip padding for length check
    let content_len = text.len() - padding_count;

    // Valid Base64 content length should avoid mod 4 remainder of 1
    let remainder = (content_len + padding_count) % 4;
    if remainder == 1 {
        return None;
    }

    // Check for character diversity typical of Base64
    let has_upper = text.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = text.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = text.chars().any(|c| c.is_ascii_digit());

    // For strings with padding, the padding itself is strong evidence
    // For strings without padding, require both upper and lowercase
    // to avoid false positives on random alphanumeric strings
    if padding_count == 0 {
        // Require both upper and lower case for unpadded strings
        if !has_upper || !has_lower {
            return None;
        }
    } else {
        // For padded strings, still require some diversity
        let has_diversity = has_digit || (has_upper && has_lower);
        if !has_diversity {
            return None;
        }
    }

    Some(Tag::Base64)
}

/// Classifies a printf-style format string
///
/// # Arguments
/// * `text` - The text to check for format string patterns
///
/// # Returns
/// Returns `Some(Tag::FormatString)` if valid, `None` otherwise.
pub fn classify_format_string(text: &str) -> Option<Tag> {
    // Find all format specifier matches
    let matches: Vec<_> = FORMAT_STRING_REGEX.find_iter(text).collect();

    if matches.is_empty() {
        return None;
    }

    // Check if any match is a real format specifier (not just %%)
    // %% is just an escaped percent sign, not a real format specifier
    let has_real_specifier = matches.iter().any(|m| m.as_str() != "%%");

    if !has_real_specifier {
        return None;
    }

    // Exclude strings that are just a single format specifier
    // (those are likely false positives)
    if text.len() <= 2 {
        return None;
    }

    Some(Tag::FormatString)
}

/// Classifies a user agent string
///
/// # Arguments
/// * `text` - The text to check for user agent patterns
///
/// # Returns
/// Returns `Some(Tag::UserAgent)` if valid, `None` otherwise.
pub fn classify_user_agent(text: &str) -> Option<Tag> {
    if USER_AGENT_REGEX.is_match(text) {
        Some(Tag::UserAgent)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guid_valid_and_invalid() {
        assert!(classify_guid("{12345678-1234-1234-1234-123456789ABC}").is_some());
        assert!(classify_guid("12345678-1234-1234-1234-123456789ABC").is_some());
        assert!(classify_guid("not-a-guid").is_none());
    }

    #[test]
    fn test_email_valid_and_invalid() {
        assert!(classify_email("user@example.com").is_some());
        assert!(classify_email("not an email").is_none());
    }

    #[test]
    fn test_base64_valid_and_invalid() {
        assert!(classify_base64("SGVsbG8gV29ybGQh").is_some());
        assert!(classify_base64("This is not base64!!").is_none());
        assert!(classify_base64("YWJj").is_none());
    }

    #[test]
    fn test_format_string_valid_and_invalid() {
        assert!(classify_format_string("Error: %s at line %d").is_some());
        assert!(classify_format_string("100%% done").is_none());
    }

    #[test]
    fn test_user_agent_valid_and_invalid() {
        assert!(
            classify_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                .is_some()
        );
        assert!(classify_user_agent("Not a user agent").is_none());
    }
}
