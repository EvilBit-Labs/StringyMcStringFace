//! Semantic classification for extracted strings
//!
//! This module provides pattern matching capabilities to identify and tag
//! network indicators such as URLs and domain names within extracted strings.
//! The classifier uses compiled regular expressions for efficient pattern
//! matching and includes TLD validation to reduce false positives.
//!
//! Current capabilities include:
//! - URLs and domain names
//! - IPv4 and IPv6 addresses
//! - POSIX and Windows file paths (including UNC paths)
//! - Windows registry paths
//! - GUIDs/UUIDs
//! - Email addresses
//! - Base64-encoded data
//! - Printf-style format strings
//! - User agent strings
//!
//! # Usage
//!
//! ```rust
//! use stringy::classification::SemanticClassifier;
//! use stringy::types::{FoundString, Encoding, StringSource};
//!
//! let classifier = SemanticClassifier::new();
//! let text = "https://example.com/api";
//! let found_string = FoundString::new(
//!     text.to_string(),
//!     Encoding::Ascii,
//!     0,
//!     text.len() as u32,
//!     StringSource::SectionData,
//! );
//!
//! let tags = classifier.classify(&found_string);
//! assert_eq!(tags.len(), 1);
//! assert!(matches!(tags[0], stringy::types::Tag::Url));
//! ```

use super::patterns;
use crate::types::{FoundString, Tag};
use patterns::ip::{IPV4_REGEX, IPV6_REGEX};
use patterns::network::{DOMAIN_REGEX, URL_REGEX};
use patterns::paths::{
    POSIX_PATH_REGEX, REGISTRY_ABBREV_REGEX, REGISTRY_PATH_REGEX, UNC_PATH_REGEX,
    WINDOWS_PATH_REGEX,
};
use regex::Regex;

// Re-export pattern functions for backward compatibility
pub use patterns::{
    classify_base64, classify_domain, classify_email, classify_format_string, classify_guid,
    classify_ip_addresses, classify_posix_path, classify_registry_path, classify_unc_path,
    classify_url, classify_user_agent, classify_windows_path, has_valid_tld, is_ipv4_address,
    is_ipv6_address, is_suspicious_posix_path, is_suspicious_registry_path,
    is_suspicious_windows_path, is_valid_posix_path, is_valid_registry_path, is_valid_windows_path,
    strip_ipv6_brackets, strip_port,
};

/// Semantic classifier for identifying network indicators in extracted strings
///
/// The `SemanticClassifier` provides methods to detect URLs, domain names,
/// IP addresses, file paths, registry paths, GUIDs, emails, and other patterns
/// within text content. It uses compiled regular expressions for efficient
/// pattern matching and includes validation to reduce false positives.
#[derive(Debug, Default)]
pub struct SemanticClassifier;

/// Internal struct for regex cache address verification (used in testing)
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegexCacheAddresses {
    pub url: usize,
    pub domain: usize,
    pub ipv4: usize,
    pub ipv6: usize,
    pub posix_path: usize,
    pub windows_path: usize,
    pub unc_path: usize,
    pub registry_full: usize,
    pub registry_abbrev: usize,
}

impl SemanticClassifier {
    /// Create a new instance of the semantic classifier
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Returns memory addresses of cached regex patterns (for testing)
    #[doc(hidden)]
    #[must_use]
    pub fn regex_cache_addresses(&self) -> RegexCacheAddresses {
        RegexCacheAddresses {
            url: &*URL_REGEX as *const Regex as usize,
            domain: &*DOMAIN_REGEX as *const Regex as usize,
            ipv4: &*IPV4_REGEX as *const Regex as usize,
            ipv6: &*IPV6_REGEX as *const Regex as usize,
            posix_path: &*POSIX_PATH_REGEX as *const Regex as usize,
            windows_path: &*WINDOWS_PATH_REGEX as *const Regex as usize,
            unc_path: &*UNC_PATH_REGEX as *const Regex as usize,
            registry_full: &*REGISTRY_PATH_REGEX as *const Regex as usize,
            registry_abbrev: &*REGISTRY_ABBREV_REGEX as *const Regex as usize,
        }
    }

    /// Detects HTTP/HTTPS URLs in the given text
    ///
    /// This method identifies URLs that start with `http://` or `https://`
    /// and contain valid URL characters.
    ///
    /// # Arguments
    ///
    /// * `text` - The text to search for URLs
    ///
    /// # Returns
    ///
    /// Returns `Some(Tag::Url)` if a URL is found, `None` otherwise.
    #[must_use]
    pub fn classify_url(&self, text: &str) -> Option<Tag> {
        classify_url(text)
    }

    /// Detects domain names that are not URLs
    ///
    /// This method identifies domain names that match the domain pattern but
    /// are not already identified as URLs.
    ///
    /// # Arguments
    ///
    /// * `text` - The text to search for domain names
    ///
    /// # Returns
    ///
    /// Returns `Some(Tag::Domain)` if a valid domain is found, `None` otherwise.
    #[must_use]
    pub fn classify_domain(&self, text: &str) -> Option<Tag> {
        classify_domain(text)
    }

    /// Main entry point for semantic classification
    ///
    /// This method analyzes a `FoundString` and returns a vector of semantic
    /// tags that apply to the string. URLs are checked first, then domains
    /// (which automatically excludes URLs to prevent double-tagging), then
    /// IP addresses (IPv4 and IPv6), file paths, and other patterns.
    ///
    /// # Arguments
    ///
    /// * `string` - The `FoundString` to classify
    ///
    /// # Returns
    ///
    /// Returns a vector of `Tag` values that apply to the string.
    #[must_use]
    pub fn classify(&self, string: &FoundString) -> Vec<Tag> {
        let mut tags = Vec::new();

        // Check for URLs first
        if let Some(tag) = classify_url(&string.text) {
            tags.push(tag);
        }

        // Check for domains (this will automatically exclude URLs)
        if let Some(tag) = classify_domain(&string.text) {
            tags.push(tag);
        }

        // Check for IP addresses (IPv4 and IPv6)
        let ip_tags = classify_ip_addresses(&string.text);
        tags.extend(ip_tags);

        // Check for file paths (POSIX, Windows, UNC) - only add FilePath tag once
        if classify_posix_path(&string.text).is_some()
            || classify_windows_path(&string.text).is_some()
            || classify_unc_path(&string.text).is_some()
        {
            tags.push(Tag::FilePath);
        }

        // Check for registry paths
        if let Some(tag) = classify_registry_path(&string.text) {
            tags.push(tag);
        }

        // Check for GUIDs
        if let Some(tag) = classify_guid(&string.text) {
            tags.push(tag);
        }

        // Check for email addresses
        if let Some(tag) = classify_email(&string.text) {
            tags.push(tag);
        }

        // Check for format strings
        if let Some(tag) = classify_format_string(&string.text) {
            tags.push(tag);
        }

        // Check for user agent strings
        if let Some(tag) = classify_user_agent(&string.text) {
            tags.push(tag);
        }

        // Check for Base64 (broad tag - checked last as it has more false positives)
        if let Some(tag) = classify_base64(&string.text) {
            tags.push(tag);
        }

        tags
    }

    /// Validates a TLD against the known list
    #[must_use]
    pub fn has_valid_tld(&self, domain: &str) -> bool {
        has_valid_tld(domain)
    }

    /// Strips port suffix from an IP address string
    #[must_use]
    pub fn strip_port<'a>(&self, text: &'a str) -> &'a str {
        strip_port(text)
    }

    /// Strips brackets from IPv6 address
    #[must_use]
    pub fn strip_ipv6_brackets<'a>(&self, text: &'a str) -> &'a str {
        strip_ipv6_brackets(text)
    }

    /// Checks if text is a valid IPv4 address
    #[must_use]
    pub fn is_ipv4_address(&self, text: &str) -> bool {
        is_ipv4_address(text)
    }

    /// Checks if text is a valid IPv6 address
    #[must_use]
    pub fn is_ipv6_address(&self, text: &str) -> bool {
        is_ipv6_address(text)
    }

    /// Classifies IP addresses in text
    #[must_use]
    pub fn classify_ip_addresses(&self, text: &str) -> Vec<Tag> {
        classify_ip_addresses(text)
    }

    /// Classifies POSIX paths
    #[must_use]
    pub fn classify_posix_path(&self, text: &str) -> Option<Tag> {
        classify_posix_path(text)
    }

    /// Classifies Windows paths
    #[must_use]
    pub fn classify_windows_path(&self, text: &str) -> Option<Tag> {
        classify_windows_path(text)
    }

    /// Classifies UNC paths
    #[must_use]
    pub fn classify_unc_path(&self, text: &str) -> Option<Tag> {
        classify_unc_path(text)
    }

    /// Classifies registry paths
    #[must_use]
    pub fn classify_registry_path(&self, text: &str) -> Option<Tag> {
        classify_registry_path(text)
    }

    /// Checks if POSIX path is suspicious
    #[must_use]
    pub fn is_suspicious_posix_path(&self, text: &str) -> bool {
        is_suspicious_posix_path(text)
    }

    /// Checks if Windows path is suspicious
    #[must_use]
    pub fn is_suspicious_windows_path(&self, text: &str) -> bool {
        is_suspicious_windows_path(text)
    }

    /// Checks if registry path is suspicious
    #[must_use]
    pub fn is_suspicious_registry_path(&self, text: &str) -> bool {
        is_suspicious_registry_path(text)
    }

    /// Validates POSIX path
    #[must_use]
    pub fn is_valid_posix_path(&self, text: &str) -> bool {
        is_valid_posix_path(text)
    }

    /// Validates Windows path
    #[must_use]
    pub fn is_valid_windows_path(&self, text: &str) -> bool {
        is_valid_windows_path(text)
    }

    /// Validates registry path
    #[must_use]
    pub fn is_valid_registry_path(&self, text: &str) -> bool {
        is_valid_registry_path(text)
    }

    /// Classifies GUIDs
    #[must_use]
    pub fn classify_guid(&self, text: &str) -> Option<Tag> {
        classify_guid(text)
    }

    /// Classifies email addresses
    #[must_use]
    pub fn classify_email(&self, text: &str) -> Option<Tag> {
        classify_email(text)
    }

    /// Classifies Base64-encoded data
    #[must_use]
    pub fn classify_base64(&self, text: &str) -> Option<Tag> {
        classify_base64(text)
    }

    /// Classifies format strings
    #[must_use]
    pub fn classify_format_string(&self, text: &str) -> Option<Tag> {
        classify_format_string(text)
    }

    /// Classifies user agent strings
    #[must_use]
    pub fn classify_user_agent(&self, text: &str) -> Option<Tag> {
        classify_user_agent(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Encoding, StringSource};

    fn create_test_string(text: &str) -> FoundString {
        FoundString {
            text: text.to_string(),
            original_text: None,
            encoding: Encoding::Ascii,
            offset: 0,
            rva: None,
            section: None,
            length: text.len() as u32,
            tags: Vec::new(),
            score: 0,
            section_weight: None,
            semantic_boost: None,
            noise_penalty: None,
            source: StringSource::SectionData,
            confidence: 1.0,
        }
    }

    #[test]
    fn test_classify_mixed_strings() {
        let classifier = SemanticClassifier::new();

        // URL
        let url_string = create_test_string("https://example.com/api");
        let tags = classifier.classify(&url_string);
        assert!(tags.contains(&Tag::Url));

        // Domain
        let domain_string = create_test_string("api.example.com");
        let tags = classifier.classify(&domain_string);
        assert!(tags.contains(&Tag::Domain));

        // IPv4
        let ipv4_string = create_test_string("192.168.1.1");
        let tags = classifier.classify(&ipv4_string);
        assert!(tags.contains(&Tag::IPv4));

        // Windows path
        let path_string = create_test_string("C:\\Windows\\System32\\cmd.exe");
        let tags = classifier.classify(&path_string);
        assert!(tags.contains(&Tag::FilePath));
    }

    #[test]
    fn test_classify_posix_path_in_found_string() {
        let classifier = SemanticClassifier::new();
        let found_string = create_test_string("/usr/local/bin/app");

        let tags = classifier.classify(&found_string);
        assert!(tags.contains(&Tag::FilePath));
    }

    #[test]
    fn test_classify_windows_path_in_found_string() {
        let classifier = SemanticClassifier::new();
        let found_string = create_test_string("C:\\Program Files\\Application\\app.exe");

        let tags = classifier.classify(&found_string);
        assert!(tags.contains(&Tag::FilePath));
    }

    #[test]
    fn test_classify_registry_path_in_found_string() {
        let classifier = SemanticClassifier::new();
        let found_string =
            create_test_string("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion");

        let tags = classifier.classify(&found_string);
        assert!(tags.contains(&Tag::RegistryPath));
    }

    #[test]
    fn test_no_false_positives_on_random_data() {
        let classifier = SemanticClassifier::new();
        let found_string = create_test_string("x9qz1p0t8v7w6r5y4u3i2o1p");

        let tags = classifier.classify(&found_string);
        assert!(tags.is_empty());
    }

    #[test]
    fn test_guid_in_found_string() {
        let classifier = SemanticClassifier::new();
        let found_string = create_test_string("{12345678-1234-1234-1234-123456789ABC}");

        let tags = classifier.classify(&found_string);
        assert!(tags.contains(&Tag::Guid));
    }

    #[test]
    fn test_email_in_found_string() {
        let classifier = SemanticClassifier::new();
        let found_string = create_test_string("user@example.com");

        let tags = classifier.classify(&found_string);
        assert!(tags.contains(&Tag::Email));
    }

    #[test]
    fn test_base64_in_found_string() {
        let classifier = SemanticClassifier::new();
        let found_string = create_test_string("SGVsbG8gV29ybGQh");

        let tags = classifier.classify(&found_string);
        assert!(tags.contains(&Tag::Base64));
    }

    #[test]
    fn test_format_string_in_found_string() {
        let classifier = SemanticClassifier::new();
        let found_string = create_test_string("Error: %s at line %d");

        let tags = classifier.classify(&found_string);
        assert!(tags.contains(&Tag::FormatString));
    }

    #[test]
    fn test_user_agent_in_found_string() {
        let classifier = SemanticClassifier::new();
        let found_string =
            create_test_string("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");

        let tags = classifier.classify(&found_string);
        assert!(tags.contains(&Tag::UserAgent));
    }

    #[test]
    fn test_multiple_tags_format_and_base64_not_both() {
        let classifier = SemanticClassifier::new();

        // Format string should get FormatString tag
        let format = create_test_string("Hello %s, your score is %d");
        let tags = classifier.classify(&format);
        assert!(tags.contains(&Tag::FormatString));

        // Pure Base64 should get Base64 tag
        let base64 = create_test_string("VGhpcyBpcyBhIHRlc3Q=");
        let tags = classifier.classify(&base64);
        assert!(tags.contains(&Tag::Base64));
    }
}
