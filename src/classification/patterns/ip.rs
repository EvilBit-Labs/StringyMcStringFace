//! IP address classification patterns
//!
//! This module provides IPv4 and IPv6 address detection functionality.

use crate::types::Tag;
use regex::Regex;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::LazyLock;

/// Regular expression for matching IPv4 addresses
///
/// Pattern matches IPv4 addresses with proper octet validation (0-255).
/// Matches the entire string (used after port stripping).
pub(crate) static IPV4_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
        .expect("Invalid IPv4 regex")
});

/// Regular expression for matching IPv6 addresses
///
/// This is a permissive pre-filter that only allows hex digits, colons,
/// and dots (for IPv4-mapped suffixes). Canonical validation is still
/// performed by std::net::Ipv6Addr::from_str.
pub(crate) static IPV6_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^[0-9a-f:.]+$").expect("Invalid IPv6 regex"));

/// Regular expression for detecting and stripping port suffixes
///
/// Matches :port where port is in the valid range 0-65535.
pub(crate) static PORT_SUFFIX_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r":(?:[0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$",
    )
    .expect("Invalid port suffix regex")
});

/// Regular expression for handling bracketed IPv6 addresses
///
/// Matches [IPv6] format used in URLs like [::1]:8080.
pub(crate) static IPV6_BRACKETS_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\[([^\]]+)\]$").expect("Invalid IPv6 brackets regex"));

/// Strips the port suffix from an IP address string if present
///
/// # Arguments
/// * `text` - The text that may contain a port suffix
///
/// # Returns
/// The text with the port suffix removed, or the original text if no port found.
pub fn strip_port(text: &str) -> &str {
    if let Some(mat) = PORT_SUFFIX_REGEX.find(text) {
        &text[..mat.start()]
    } else {
        text
    }
}

/// Strips brackets from an IPv6 address if present
///
/// # Arguments
/// * `text` - The text that may contain bracketed IPv6
///
/// # Returns
/// The IPv6 address without brackets, or the original text if no brackets found.
pub fn strip_ipv6_brackets(text: &str) -> &str {
    if let Some(caps) = IPV6_BRACKETS_REGEX.captures(text)
        && let Some(inner) = caps.get(1)
    {
        return inner.as_str();
    }
    text
}

/// Checks if the given text is a valid IPv4 address
///
/// This method first strips any port suffix, then validates the remaining
/// text as an IPv4 address using both regex and standard library validation.
///
/// # Arguments
/// * `text` - The text to check for IPv4 format
///
/// # Returns
/// Returns `true` if the text is a valid IPv4 address.
pub fn is_ipv4_address(text: &str) -> bool {
    // Strip port suffix if present
    let text_without_port = strip_port(text);

    // Two-stage validation: regex pre-filter first
    if !IPV4_REGEX.is_match(text_without_port) {
        return false;
    }

    // Check for leading zeros in octets (e.g., 192.168.01.1 should be rejected)
    for octet_str in text_without_port.split('.') {
        // If an octet has more than 1 digit and starts with '0', it's invalid
        if octet_str.len() > 1 && octet_str.starts_with('0') {
            return false;
        }
    }

    // Validate using std::net::Ipv4Addr for correctness
    // This is the authoritative check - regex is just a pre-filter
    Ipv4Addr::from_str(text_without_port).is_ok()
}

/// Checks if the given text is a valid IPv6 address
///
/// This method handles bracketed IPv6 addresses (e.g., `[::1]:8080`),
/// strips any port suffix, and validates using both regex and standard library.
///
/// # Arguments
/// * `text` - The text to check for IPv6 format
///
/// # Returns
/// Returns `true` if the text is a valid IPv6 address.
pub fn is_ipv6_address(text: &str) -> bool {
    // Handle bracketed IPv6 addresses like [::1] or [::1]:8080
    let mut ip_text = text;

    // Check for bracketed format
    if text.starts_with('[') {
        // Strip port from the full text first (e.g., [::1]:8080 -> [::1])
        let without_port = strip_port(text);
        // Now extract the IPv6 from brackets
        ip_text = strip_ipv6_brackets(without_port);
    }

    // Permissive pre-filter to reject obvious non-IPv6 strings early
    if !IPV6_REGEX.is_match(ip_text) {
        return false;
    }

    // Basic structure check - must contain colon and only valid hex/colon characters
    if !ip_text.contains(':') {
        return false;
    }

    // Validate using std::net::Ipv6Addr for correctness
    Ipv6Addr::from_str(ip_text).is_ok()
}

/// Classifies IP addresses (both IPv4 and IPv6) in the given text
///
/// # Arguments
/// * `text` - The text to classify
///
/// # Returns
/// A vector of tags (IPv4 and/or IPv6) that apply to the text.
pub fn classify_ip_addresses(text: &str) -> Vec<Tag> {
    let mut tags = Vec::new();

    if is_ipv4_address(text) {
        tags.push(Tag::IPv4);
    }

    if is_ipv6_address(text) {
        tags.push(Tag::IPv6);
    }

    tags
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_valid_and_invalid() {
        assert!(is_ipv4_address("192.168.1.1"));
        assert!(is_ipv4_address("192.168.1.1:8080"));
        assert!(!is_ipv4_address("256.1.1.1"));
        assert!(!is_ipv4_address("01.02.03.04"));
    }

    #[test]
    fn test_ipv6_valid_and_invalid() {
        assert!(is_ipv6_address("2001:db8::1"));
        assert!(is_ipv6_address("[::1]:8080"));
        assert!(!is_ipv6_address("not an ipv6"));
    }

    #[test]
    fn test_classify_ipv4_and_ipv6() {
        let tags = classify_ip_addresses("192.168.1.1");
        assert_eq!(tags, vec![Tag::IPv4]);

        let tags = classify_ip_addresses("2001:db8::1");
        assert_eq!(tags, vec![Tag::IPv6]);
    }

    #[test]
    fn test_classify_no_ip() {
        let tags = classify_ip_addresses("not an ip address");
        assert!(tags.is_empty());
    }
}
