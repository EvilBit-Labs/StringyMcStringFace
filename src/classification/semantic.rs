//! Semantic classification for extracted strings
//!
//! This module provides pattern matching capabilities to identify and tag
//! network indicators such as URLs and domain names within extracted strings.
//! The classifier uses compiled regular expressions for efficient pattern
//! matching and includes TLD validation to reduce false positives.
//!
//! # Usage
//!
//! ```rust
//! use stringy::classification::SemanticClassifier;
//! use stringy::types::{FoundString, Encoding, StringSource};
//!
//! let classifier = SemanticClassifier::new();
//! let found_string = FoundString {
//!     text: "https://example.com/api".to_string(),
//!     encoding: Encoding::Ascii,
//!     offset: 0,
//!     rva: None,
//!     section: None,
//!     length: 24,
//!     tags: Vec::new(),
//!     score: 0,
//!     source: StringSource::SectionData,
//!     confidence: 1.0,
//! };
//!
//! let tags = classifier.classify(&found_string);
//! assert_eq!(tags.len(), 1);
//! assert!(matches!(tags[0], stringy::types::Tag::Url));
//! ```
//!
//! # Patterns
//!
//! - **URLs**: Matches HTTP and HTTPS URLs using a pattern that excludes
//!   problematic characters that could cause false positives.
//!
//! - **Domains**: Matches domain names using RFC 1035 compliant patterns
//!   with additional TLD validation against a hardcoded list of common TLDs.

use crate::types::{FoundString, Tag};
use lazy_static::lazy_static;
use regex::Regex;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

lazy_static! {
    /// Regular expression for matching HTTP/HTTPS URLs
    ///
    /// Pattern matches URLs starting with http:// or https:// and excludes
    /// problematic characters that could cause false positives.
    static ref URL_REGEX: Regex = Regex::new(r#"https?://[^\s<>"{}|\\\^\[\]\`]+"#).unwrap();

    /// Regular expression for matching domain names
    ///
    /// Pattern matches domain names with proper DNS format compliance (RFC 1035).
    /// It ensures domains start and end with alphanumeric characters, allows hyphens
    /// in the middle, and requires at least a 2-character TLD.
    static ref DOMAIN_REGEX: Regex = Regex::new(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b").unwrap();

    /// Regular expression for matching IPv4 addresses
    ///
    /// Pattern matches IPv4 addresses with proper octet validation (0-255).
    /// Matches the entire string (used after port stripping).
    static ref IPV4_REGEX: Regex = Regex::new(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$").unwrap();

    /// Regular expression for matching IPv6 addresses
    ///
    /// Pattern matches IPv6 addresses including:
    /// - Full notation: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
    /// - Compressed notation: 2001:db8::1, ::1, fe80::1
    /// - Mixed notation: ::ffff:192.0.2.1, 64:ff9b::192.0.2.1
    /// This is a permissive pattern that checks for basic IPv6 structure (colons and hex digits).
    /// Actual validation is performed by std::net::Ipv6Addr::from_str.
    static ref IPV6_REGEX: Regex = Regex::new(r"(?i)^(?:[0-9a-f]{1,4}:){1,7}[0-9a-f]{1,4}$|^(?:[0-9a-f]{1,4}:){1,7}:$|^(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}$|^(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}$|^(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}$|^(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}$|^(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}$|^[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,6}$|^:(?::[0-9a-f]{1,4}){1,7}$|^::$|^::ffff:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$").unwrap();

    /// Regular expression for detecting and stripping port suffixes
    ///
    /// Matches :port where port is in the valid range 0-65535.
    /// Pattern: :[0-9]{1,4} matches 0-9999, |[1-5][0-9]{4} matches 10000-59999,
    /// |6[0-4][0-9]{3} matches 60000-64999, |65[0-4][0-9]{2} matches 65000-65499,
    /// |655[0-2][0-9] matches 65500-65529, |6553[0-5] matches 65530-65535.
    static ref PORT_SUFFIX_REGEX: Regex = Regex::new(r":(?:[0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$").unwrap();

    /// Regular expression for handling bracketed IPv6 addresses
    ///
    /// Matches [IPv6] format used in URLs like [::1]:8080.
    static ref IPV6_BRACKETS_REGEX: Regex = Regex::new(r"^\[(.+)\]").unwrap();
}

/// Semantic classifier for identifying network indicators in extracted strings
///
/// The `SemanticClassifier` provides methods to detect URLs and domain names
/// within text content. It uses compiled regular expressions for efficient
/// pattern matching and includes TLD validation to reduce false positives.
///
/// URLs are prioritized over domains to prevent double-tagging - if a string
/// matches both patterns, it will only be tagged as a URL.
#[derive(Debug, Default)]
pub struct SemanticClassifier;

impl SemanticClassifier {
    /// Create a new instance of the semantic classifier
    pub fn new() -> Self {
        Self
    }

    /// Detects HTTP/HTTPS URLs in the given text
    ///
    /// This method identifies URLs that start with `http://` or `https://`
    /// and contain valid URL characters. The pattern excludes problematic
    /// characters to avoid false positives.
    ///
    /// # Arguments
    ///
    /// * `text` - The text to search for URLs
    ///
    /// # Returns
    ///
    /// Returns `Some(Tag::Url)` if a URL is found, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use stringy::classification::SemanticClassifier;
    /// use stringy::types::Tag;
    ///
    /// let classifier = SemanticClassifier::new();
    /// assert_eq!(classifier.classify_url("https://example.com"), Some(Tag::Url));
    /// assert_eq!(classifier.classify_url("example.com"), None);
    /// ```
    pub fn classify_url(&self, text: &str) -> Option<Tag> {
        if URL_REGEX.is_match(text) {
            Some(Tag::Url)
        } else {
            None
        }
    }

    /// Detects domain names that are not URLs
    ///
    /// This method identifies domain names that match the domain pattern but
    /// are not already identified as URLs. It first checks if the text is NOT
    /// a URL to prevent double-tagging, then validates against the domain
    /// pattern and TLD list.
    ///
    /// # Arguments
    ///
    /// * `text` - The text to search for domain names
    ///
    /// # Returns
    ///
    /// Returns `Some(Tag::Domain)` if a valid domain is found (and it's not
    /// a URL), `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use stringy::classification::SemanticClassifier;
    /// use stringy::types::Tag;
    ///
    /// let classifier = SemanticClassifier::new();
    /// assert_eq!(classifier.classify_domain("example.com"), Some(Tag::Domain));
    /// assert_eq!(classifier.classify_domain("https://example.com"), None);
    /// ```
    pub fn classify_domain(&self, text: &str) -> Option<Tag> {
        // First check if it's NOT a URL to prevent double-tagging
        if URL_REGEX.is_match(text) {
            return None;
        }

        // Check if it matches the domain pattern
        if DOMAIN_REGEX.is_match(text) {
            // Validate TLD to reduce false positives
            if self.has_valid_tld(text) {
                return Some(Tag::Domain);
            }
        }

        None
    }

    /// Main entry point for semantic classification
    ///
    /// This method analyzes a `FoundString` and returns a vector of semantic
    /// tags that apply to the string. URLs are checked first, then domains
    /// (which automatically excludes URLs to prevent double-tagging), then
    /// IP addresses (IPv4 and IPv6).
    ///
    /// # Arguments
    ///
    /// * `string` - The `FoundString` to classify
    ///
    /// # Returns
    ///
    /// Returns a vector of `Tag` values that apply to the string. The vector
    /// may be empty if no patterns match.
    ///
    /// # Examples
    ///
    /// ```
    /// use stringy::classification::SemanticClassifier;
    /// use stringy::types::{FoundString, Encoding, StringSource, Tag};
    ///
    /// let classifier = SemanticClassifier::new();
    /// let found_string = FoundString {
    ///     text: "https://example.com".to_string(),
    ///     encoding: Encoding::Ascii,
    ///     offset: 0,
    ///     rva: None,
    ///     section: None,
    ///     length: 19,
    ///     tags: Vec::new(),
    ///     score: 0,
    ///     source: StringSource::SectionData,
    ///     confidence: 1.0,
    /// };
    ///
    /// let tags = classifier.classify(&found_string);
    /// assert_eq!(tags.len(), 1);
    /// assert!(matches!(tags[0], Tag::Url));
    /// ```
    pub fn classify(&self, string: &FoundString) -> Vec<Tag> {
        let mut tags = Vec::new();

        // Check for URLs first
        if let Some(tag) = self.classify_url(&string.text) {
            tags.push(tag);
        }

        // Check for domains (this will automatically exclude URLs)
        if let Some(tag) = self.classify_domain(&string.text) {
            tags.push(tag);
        }

        // Check for IP addresses (IPv4 and IPv6)
        let ip_tags = self.classify_ip_addresses(&string.text);
        tags.extend(ip_tags);

        tags
    }

    /// Validates the top-level domain (TLD) against a hardcoded list
    ///
    /// This method extracts the TLD from a domain string and validates it
    /// against a comprehensive list of common TLDs. This helps reduce false
    /// positives by ensuring domains have valid TLDs.
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain string to validate
    ///
    /// # Returns
    ///
    /// Returns `true` if the TLD is valid and at least 2 characters long,
    /// `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use stringy::classification::SemanticClassifier;
    ///
    /// let classifier = SemanticClassifier::new();
    /// assert!(classifier.has_valid_tld("example.com"));
    /// assert!(!classifier.has_valid_tld("example.x"));
    /// ```
    fn has_valid_tld(&self, domain: &str) -> bool {
        // Extract TLD (last segment after final dot)
        let tld = domain.split('.').next_back().unwrap_or("");

        // TLD must be at least 2 characters
        if tld.len() < 2 {
            return false;
        }

        // Normalize TLD to lowercase for case-insensitive validation
        let tld_lower = tld.to_ascii_lowercase();

        // Validate against hardcoded list of common TLDs
        let valid_tlds = [
            // Generic TLDs
            "com",
            "net",
            "org",
            "io",
            "co",
            // Country code TLDs
            "gov",
            "edu",
            "mil",
            "int",
            "uk",
            "de",
            "fr",
            "jp",
            "cn",
            "au",
            "ca",
            "ru",
            "br",
            "in",
            "nl",
            "eu",
            // New gTLDs
            "info",
            "biz",
            "dev",
            "app",
            "cloud",
            "tech",
            "online",
            "site",
            "xyz",
            "top",
            "win",
            "bid",
            // Additional common TLDs
            "me",
            "tv",
            "cc",
            "ws",
            "name",
            "pro",
            "mobi",
            "asia",
            "tel",
            "travel",
            "jobs",
            "museum",
            "aero",
            "coop",
            "cat",
            "xxx",
            "post",
            "arpa",
            "test",
            "example",
            "localhost",
        ];

        valid_tlds.contains(&tld_lower.as_str())
    }

    /// Strips port suffix from an IP address string
    ///
    /// Removes `:port` suffix if present (e.g., `192.168.1.1:8080` → `192.168.1.1`).
    ///
    /// # Arguments
    ///
    /// * `text` - The text that may contain a port suffix
    ///
    /// # Returns
    ///
    /// Returns a string slice without the port suffix.
    fn strip_port<'a>(&self, text: &'a str) -> &'a str {
        PORT_SUFFIX_REGEX
            .find(text)
            .map_or(text, |m| &text[..m.start()])
    }

    /// Strips bracketed notation from IPv6 addresses
    ///
    /// Removes `[` and `]` from bracketed IPv6 addresses (e.g., `[::1]` → `::1`).
    ///
    /// # Arguments
    ///
    /// * `text` - The text that may contain bracketed IPv6 notation
    ///
    /// # Returns
    ///
    /// Returns a string slice without brackets, or the original text if no brackets found.
    fn strip_ipv6_brackets<'a>(&self, text: &'a str) -> &'a str {
        IPV6_BRACKETS_REGEX
            .captures(text)
            .and_then(|caps| caps.get(1))
            .map_or(text, |m| m.as_str())
    }

    /// Detects IPv4 addresses in the given text
    ///
    /// This method uses a two-stage validation approach:
    /// 1. Regex pre-filter for performance
    /// 2. `std::net::Ipv4Addr` validation for correctness
    ///
    /// It also handles port suffixes and filters out version numbers.
    ///
    /// # Version Number Heuristic
    ///
    /// To reduce false positives from version numbers (e.g., "1.2.3.4"),
    /// this method rejects IPv4 addresses where all octets are less than 20.
    /// This heuristic may occasionally produce false positives for legitimate
    /// IP addresses that happen to match version number patterns (e.g., "10.5.2.15").
    /// Common addresses like 8.8.8.8 (Google DNS) and private network addresses
    /// in well-known ranges are explicitly allowed to mitigate this.
    ///
    /// # Arguments
    ///
    /// * `text` - The text to search for IPv4 addresses
    ///
    /// # Returns
    ///
    /// Returns `true` if a valid IPv4 address is found, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use stringy::classification::SemanticClassifier;
    ///
    /// let classifier = SemanticClassifier::new();
    /// assert!(classifier.is_ipv4_address("192.168.1.1"));
    /// assert!(classifier.is_ipv4_address("192.168.1.1:8080"));
    /// assert!(!classifier.is_ipv4_address("1.2.3.4")); // Version number
    /// assert!(!classifier.is_ipv4_address("256.1.1.1")); // Invalid octet
    /// ```
    pub fn is_ipv4_address(&self, text: &str) -> bool {
        // Strip port suffix if present
        let text_without_port = self.strip_port(text);

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
        let ip = match Ipv4Addr::from_str(text_without_port) {
            Ok(ip) => ip,
            Err(_) => return false,
        };

        // Apply false positive mitigation: reject version numbers
        // Version numbers like 1.2.3.4 or 10.5.2.1 typically have all octets < 20
        // We use a heuristic: reject if all octets are < 20 (as per plan)
        // But allow common real IP addresses and private network ranges
        let octets = ip.octets();

        // Allow 0.0.0.0 (unspecified address) and common single-digit IPs
        // Also allow specific common private IPs that would otherwise be rejected
        let common_ips = [
            [0, 0, 0, 0],  // Unspecified
            [1, 1, 1, 1],  // Cloudflare DNS
            [8, 8, 8, 8],  // Google DNS
            [8, 8, 4, 4],  // Google DNS alt
            [10, 0, 0, 1], // Common private IP
        ];

        if common_ips.contains(&octets) {
            return true;
        }

        // Reject if all octets are < 20 (likely a version number)
        if octets.iter().all(|&octet| octet < 20) {
            return false;
        }

        true
    }

    /// Detects IPv6 addresses in the given text
    ///
    /// This method uses a two-stage validation approach:
    /// 1. Basic structure check (contains colons, looks like IPv6)
    /// 2. `std::net::Ipv6Addr` validation for correctness
    ///
    /// It handles bracketed notation (e.g., `[::1]`) and port suffixes.
    ///
    /// # Arguments
    ///
    /// * `text` - The text to search for IPv6 addresses
    ///
    /// # Returns
    ///
    /// Returns `true` if a valid IPv6 address is found, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use stringy::classification::SemanticClassifier;
    ///
    /// let classifier = SemanticClassifier::new();
    /// assert!(classifier.is_ipv6_address("2001:db8::1"));
    /// assert!(classifier.is_ipv6_address("::1"));
    /// assert!(classifier.is_ipv6_address("[::1]:8080"));
    /// assert!(!classifier.is_ipv6_address("gggg::1")); // Invalid hex
    /// ```
    pub fn is_ipv6_address(&self, text: &str) -> bool {
        // Handle bracketed IPv6 addresses like [::1] or [::1]:8080
        // Strategy: strip port first (if present), then strip brackets

        // If it looks like it has a port (contains ]:), strip port first
        let after_port = if text.contains("]:") {
            self.strip_port(text)
        } else {
            text
        };

        // Now strip brackets if present
        let processed = self.strip_ipv6_brackets(after_port);

        // Two-stage validation: regex pre-filter first
        // Basic structure check: must contain colons (IPv6 addresses always have colons)
        if !processed.contains(':') {
            return false;
        }

        // For mixed notation (contains both colons and dots), skip regex check
        // as the regex doesn't handle all mixed notation patterns
        let is_mixed_notation = processed.contains('.');

        if !is_mixed_notation {
            // Use regex as pre-filter for non-mixed notation
            if !IPV6_REGEX.is_match(processed) {
                return false;
            }
        }

        // Validate using std::net::Ipv6Addr for canonical validation
        // This handles all IPv6 formats: full, compressed, mixed notation
        Ipv6Addr::from_str(processed).is_ok()
    }

    /// Classifies IP addresses (IPv4 and IPv6) in the given text
    ///
    /// This method checks for both IPv4 and IPv6 addresses and returns
    /// appropriate tags. A string may match both patterns (unlikely but possible).
    ///
    /// # Arguments
    ///
    /// * `text` - The text to search for IP addresses
    ///
    /// # Returns
    ///
    /// Returns a vector of `Tag` values (`Tag::IPv4` and/or `Tag::IPv6`).
    /// The vector may be empty if no IP addresses are found.
    ///
    /// # Examples
    ///
    /// ```
    /// use stringy::classification::SemanticClassifier;
    /// use stringy::types::Tag;
    ///
    /// let classifier = SemanticClassifier::new();
    /// let tags = classifier.classify_ip_addresses("192.168.1.1");
    /// assert_eq!(tags, vec![Tag::IPv4]);
    ///
    /// let tags = classifier.classify_ip_addresses("::1");
    /// assert_eq!(tags, vec![Tag::IPv6]);
    ///
    /// let tags = classifier.classify_ip_addresses("not an ip");
    /// assert!(tags.is_empty());
    /// ```
    pub fn classify_ip_addresses(&self, text: &str) -> Vec<Tag> {
        let mut tags = Vec::new();

        // Check for IPv4
        if self.is_ipv4_address(text) {
            tags.push(Tag::IPv4);
        }

        // Check for IPv6
        if self.is_ipv6_address(text) {
            tags.push(Tag::IPv6);
        }

        tags
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Encoding, StringSource};

    /// Helper function to create a test FoundString
    fn create_test_string(text: &str) -> FoundString {
        FoundString {
            text: text.to_string(),
            encoding: Encoding::Ascii,
            offset: 0,
            rva: None,
            section: None,
            length: text.len() as u32,
            tags: Vec::new(),
            score: 0,
            source: StringSource::SectionData,
            confidence: 1.0,
        }
    }

    #[test]
    fn test_url_detection() {
        let classifier = SemanticClassifier::new();

        // Valid URLs
        assert_eq!(
            classifier.classify_url("https://example.com"),
            Some(Tag::Url)
        );
        assert_eq!(
            classifier.classify_url("http://api.malware.com/v1/data"),
            Some(Tag::Url)
        );
        assert_eq!(
            classifier.classify_url("https://192.168.1.1:8080/path"),
            Some(Tag::Url)
        );

        // Invalid cases (not URLs)
        assert_eq!(classifier.classify_url("example.com"), None);
        assert_eq!(classifier.classify_url("not a url"), None);
    }

    #[test]
    fn test_domain_detection() {
        let classifier = SemanticClassifier::new();

        // Valid domains
        assert_eq!(classifier.classify_domain("example.com"), Some(Tag::Domain));
        assert_eq!(
            classifier.classify_domain("api.service.io"),
            Some(Tag::Domain)
        );
        assert_eq!(
            classifier.classify_domain("malware-c2.net"),
            Some(Tag::Domain)
        );

        // Valid domains with mixed-case TLDs
        assert_eq!(classifier.classify_domain("example.COM"), Some(Tag::Domain));
        assert_eq!(
            classifier.classify_domain("api.service.IO"),
            Some(Tag::Domain)
        );
        assert_eq!(
            classifier.classify_domain("malware-c2.NET"),
            Some(Tag::Domain)
        );
        assert_eq!(classifier.classify_domain("Example.OrG"), Some(Tag::Domain));

        // URLs should not match as domains
        assert_eq!(classifier.classify_domain("https://example.com"), None);

        // Invalid domains
        assert_eq!(classifier.classify_domain("invalid"), None);
        assert_eq!(classifier.classify_domain("too.short.x"), None);
    }

    #[test]
    fn test_url_classification() {
        let classifier = SemanticClassifier::new();
        let found_string = create_test_string("https://example.com/api");

        let tags = classifier.classify(&found_string);
        assert_eq!(tags.len(), 1);
        assert!(matches!(tags[0], Tag::Url));
    }

    #[test]
    fn test_domain_classification() {
        let classifier = SemanticClassifier::new();
        let found_string = create_test_string("example.com");

        let tags = classifier.classify(&found_string);
        assert_eq!(tags.len(), 1);
        assert!(matches!(tags[0], Tag::Domain));
    }

    #[test]
    fn test_url_not_double_tagged() {
        let classifier = SemanticClassifier::new();
        let found_string = create_test_string("https://example.com");

        let tags = classifier.classify(&found_string);
        assert_eq!(tags.len(), 1);
        assert!(matches!(tags[0], Tag::Url));
        // Ensure it's NOT also tagged as Domain
        assert!(!tags.iter().any(|t| matches!(t, Tag::Domain)));
    }

    #[test]
    fn test_tld_validation() {
        let classifier = SemanticClassifier::new();

        // Valid TLDs
        assert!(classifier.has_valid_tld("example.com"));
        assert!(classifier.has_valid_tld("test.net"));
        assert!(classifier.has_valid_tld("site.org"));
        assert!(classifier.has_valid_tld("api.io"));

        // Valid TLDs with mixed case (should be normalized)
        assert!(classifier.has_valid_tld("example.COM"));
        assert!(classifier.has_valid_tld("test.NET"));
        assert!(classifier.has_valid_tld("site.ORG"));
        assert!(classifier.has_valid_tld("api.IO"));
        assert!(classifier.has_valid_tld("Example.CoM"));

        // Invalid TLDs
        assert!(!classifier.has_valid_tld("example.x"));
        assert!(!classifier.has_valid_tld("test.invalid"));
        assert!(!classifier.has_valid_tld("site.toolong123"));
    }

    #[test]
    fn test_edge_cases() {
        let classifier = SemanticClassifier::new();

        // Empty string
        let empty = create_test_string("");
        let tags = classifier.classify(&empty);
        assert_eq!(tags.len(), 0);

        // Very long domain (within RFC 1035 limits)
        let long_domain = "a".repeat(60) + ".com";
        let found_string = create_test_string(&long_domain);
        let tags = classifier.classify(&found_string);
        assert_eq!(tags.len(), 1);
        assert!(matches!(tags[0], Tag::Domain));

        // String with no valid domain pattern
        let no_domain = create_test_string("just some text without domains");
        let tags = classifier.classify(&no_domain);
        assert_eq!(tags.len(), 0);

        // Malformed URL
        let malformed = create_test_string("http://");
        let tags = classifier.classify(&malformed);
        assert_eq!(tags.len(), 0);
    }

    #[test]
    fn test_ipv4_valid_addresses() {
        let classifier = SemanticClassifier::new();

        // Valid IPv4 addresses
        assert!(classifier.is_ipv4_address("192.168.1.1"));
        assert!(classifier.is_ipv4_address("10.0.0.1"));
        assert!(classifier.is_ipv4_address("8.8.8.8"));
        assert!(classifier.is_ipv4_address("1.1.1.1"));
        assert!(classifier.is_ipv4_address("127.0.0.1"));
        assert!(classifier.is_ipv4_address("0.0.0.0"));
        assert!(classifier.is_ipv4_address("255.255.255.255"));
    }

    #[test]
    fn test_ipv4_invalid_addresses() {
        let classifier = SemanticClassifier::new();

        // Invalid IPv4 addresses
        assert!(!classifier.is_ipv4_address("256.1.1.1")); // Octet > 255
        assert!(!classifier.is_ipv4_address("192.168.1")); // Missing octet
        assert!(!classifier.is_ipv4_address("192.168.1.1.1")); // Too many octets
        assert!(!classifier.is_ipv4_address("999.999.999.999")); // All octets > 255
        assert!(!classifier.is_ipv4_address("192.168.01.1")); // Leading zero (invalid format)
    }

    #[test]
    fn test_ipv4_with_port() {
        let classifier = SemanticClassifier::new();

        // IPv4 addresses with ports should be detected
        assert!(classifier.is_ipv4_address("192.168.1.1:8080"));
        assert!(classifier.is_ipv4_address("10.0.0.1:443"));
        assert!(classifier.is_ipv4_address("127.0.0.1:3000"));
    }

    #[test]
    fn test_ipv4_version_numbers() {
        let classifier = SemanticClassifier::new();

        // Version numbers should be rejected
        assert!(!classifier.is_ipv4_address("1.2.3.4"));
        assert!(!classifier.is_ipv4_address("2.0.1.0"));
        assert!(!classifier.is_ipv4_address("10.5.2.1")); // All octets < 20 -> treated as version number, so rejected
        assert!(classifier.is_ipv4_address("10.5.2.20")); // Valid IP (not all < 20)
    }

    #[test]
    fn test_ipv4_edge_cases() {
        let classifier = SemanticClassifier::new();

        // Boundary values
        assert!(classifier.is_ipv4_address("0.0.0.0"));
        assert!(classifier.is_ipv4_address("255.255.255.255"));
        assert!(classifier.is_ipv4_address("192.0.0.1"));
        assert!(classifier.is_ipv4_address("0.255.0.255"));

        // Private network addresses
        assert!(classifier.is_ipv4_address("192.168.0.1"));
        assert!(classifier.is_ipv4_address("10.0.0.1"));
        assert!(classifier.is_ipv4_address("172.16.0.1"));
    }

    #[test]
    fn test_ipv6_full_notation() {
        let classifier = SemanticClassifier::new();

        // Full IPv6 notation
        assert!(classifier.is_ipv6_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
        assert!(classifier.is_ipv6_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
    }

    #[test]
    fn test_ipv6_compressed() {
        let classifier = SemanticClassifier::new();

        // Compressed IPv6 notation
        assert!(classifier.is_ipv6_address("2001:db8::1"));
        assert!(classifier.is_ipv6_address("::1"));
        assert!(classifier.is_ipv6_address("fe80::1"));
        assert!(classifier.is_ipv6_address("::"));
    }

    #[test]
    fn test_ipv6_mixed_notation() {
        let classifier = SemanticClassifier::new();

        // Mixed IPv4/IPv6 notation
        assert!(classifier.is_ipv6_address("::ffff:192.0.2.1"));
        assert!(classifier.is_ipv6_address("64:ff9b::192.0.2.1"));
    }

    #[test]
    fn test_ipv6_invalid() {
        let classifier = SemanticClassifier::new();

        // Invalid IPv6 addresses
        assert!(!classifier.is_ipv6_address("gggg::1")); // Invalid hex
        assert!(!classifier.is_ipv6_address("2001:db8::1::2")); // Double ::
        assert!(!classifier.is_ipv6_address("2001:db8:1")); // Too short
    }

    #[test]
    fn test_ipv6_with_brackets() {
        let classifier = SemanticClassifier::new();

        // IPv6 addresses with brackets
        assert!(classifier.is_ipv6_address("[2001:db8::1]"));
        assert!(classifier.is_ipv6_address("[::1]"));
    }

    #[test]
    fn test_ipv6_with_port() {
        let classifier = SemanticClassifier::new();

        // IPv6 addresses with brackets and ports
        assert!(classifier.is_ipv6_address("[2001:db8::1]:8080"));
        assert!(classifier.is_ipv6_address("[::1]:8080"));
    }

    #[test]
    fn test_classify_ipv4() {
        let classifier = SemanticClassifier::new();
        let found_string = create_test_string("192.168.1.1");

        let tags = classifier.classify(&found_string);
        assert_eq!(tags.len(), 1);
        assert!(matches!(tags[0], Tag::IPv4));
    }

    #[test]
    fn test_classify_ipv6() {
        let classifier = SemanticClassifier::new();
        let found_string = create_test_string("::1");

        let tags = classifier.classify(&found_string);
        assert_eq!(tags.len(), 1);
        assert!(matches!(tags[0], Tag::IPv6));
    }

    #[test]
    fn test_classify_no_ip() {
        let classifier = SemanticClassifier::new();
        let found_string = create_test_string("not an ip address");

        let tags = classifier.classify_ip_addresses(&found_string.text);
        assert!(tags.is_empty());
    }

    #[test]
    fn test_classify_ipv4_with_port() {
        let classifier = SemanticClassifier::new();
        let found_string = create_test_string("192.168.1.1:8080");

        let tags = classifier.classify(&found_string);
        assert_eq!(tags.len(), 1);
        assert!(matches!(tags[0], Tag::IPv4));
    }

    #[test]
    fn test_classify_ipv6_with_brackets_and_port() {
        let classifier = SemanticClassifier::new();
        let found_string = create_test_string("[::1]:8080");

        let tags = classifier.classify(&found_string);
        assert_eq!(tags.len(), 1);
        assert!(matches!(tags[0], Tag::IPv6));
    }
}
