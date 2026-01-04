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
    /// (which automatically excludes URLs to prevent double-tagging).
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
}
