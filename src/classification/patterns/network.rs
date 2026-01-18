//! Network indicator classification patterns
//!
//! This module provides URL and domain name detection functionality.

use crate::types::Tag;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

/// Regular expression for matching HTTP/HTTPS URLs
///
/// Pattern matches URLs starting with http:// or https:// and excludes
/// problematic characters that could cause false positives.
pub(crate) static URL_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"https?://[^\s<>"{}|\\\^\[\]\`]+"#).unwrap());

/// Regular expression for matching domain names
///
/// Pattern matches domain names with proper DNS format compliance (RFC 1035).
/// It ensures domains start and end with alphanumeric characters, allows hyphens
/// in the middle, and requires at least a 2-character TLD.
pub(crate) static DOMAIN_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b").unwrap()
});

/// List of common TLDs for validation
static COMMON_TLDS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    HashSet::from([
        "com", "org", "net", "edu", "gov", "mil", "int", "io", "co", "uk", "de", "fr", "jp", "cn",
        "ru", "br", "in", "au", "ca", "es", "it", "nl", "pl", "se", "ch", "at", "be", "dk", "fi",
        "no", "pt", "cz", "hu", "ro", "bg", "hr", "sk", "si", "ee", "lt", "lv", "ie", "gr", "cy",
        "mt", "lu", "info", "biz", "name", "pro", "aero", "coop", "museum", "travel", "jobs",
        "mobi", "tel", "asia", "cat", "xxx", "app", "dev", "page", "blog", "shop", "store",
        "online", "site", "website", "tech", "cloud", "ai", "ml", "tv", "me", "cc", "ws", "bz",
        "nu", "tk", "ga", "cf", "gq",
    ])
});

/// Checks if the domain has a valid TLD
///
/// # Arguments
/// * `domain` - The domain name to validate
///
/// # Returns
/// Returns `true` if the domain has a known TLD.
pub fn has_valid_tld(domain: &str) -> bool {
    if let Some(dot_pos) = domain.rfind('.') {
        let tld = &domain[dot_pos + 1..];
        let tld_lower = tld.to_lowercase();
        COMMON_TLDS.contains(tld_lower.as_str())
    } else {
        false
    }
}

/// Detects HTTP/HTTPS URLs in the given text
///
/// This method identifies URLs that start with `http://` or `https://`
/// and contain valid URL characters.
///
/// # Arguments
/// * `text` - The text to search for URLs
///
/// # Returns
/// Returns `Some(Tag::Url)` if a URL is found, `None` otherwise.
pub fn classify_url(text: &str) -> Option<Tag> {
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
/// * `text` - The text to search for domain names
///
/// # Returns
/// Returns `Some(Tag::Domain)` if a valid domain is found (and it's not
/// a URL), `None` otherwise.
pub fn classify_domain(text: &str) -> Option<Tag> {
    // First check if it's NOT a URL to prevent double-tagging
    if URL_REGEX.is_match(text) {
        return None;
    }

    // Check if it matches the domain pattern
    if DOMAIN_REGEX.is_match(text) {
        // Validate TLD to reduce false positives
        if has_valid_tld(text) {
            return Some(Tag::Domain);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_detection() {
        assert!(classify_url("https://example.com").is_some());
        assert!(classify_url("http://test.org/path").is_some());
        assert!(classify_url("https://sub.domain.com:8080/api").is_some());
        assert!(classify_url("not a url").is_none());
        assert!(classify_url("ftp://example.com").is_none());
    }

    #[test]
    fn test_domain_detection() {
        assert!(classify_domain("example.com").is_some());
        assert!(classify_domain("sub.example.org").is_some());
        assert!(classify_domain("test.co.uk").is_some());
        assert!(classify_domain("https://example.com").is_none()); // URLs excluded
        assert!(classify_domain("notadomain").is_none());
        assert!(classify_domain("invalid.xyz123").is_none()); // Invalid TLD
    }

    #[test]
    fn test_url_classification() {
        assert_eq!(classify_url("https://example.com"), Some(Tag::Url));
        assert_eq!(classify_url("http://test.org"), Some(Tag::Url));
    }

    #[test]
    fn test_domain_classification() {
        assert_eq!(classify_domain("example.com"), Some(Tag::Domain));
        assert_eq!(classify_domain("test.org"), Some(Tag::Domain));
    }

    #[test]
    fn test_url_not_double_tagged() {
        // URLs should not be tagged as domains
        assert!(classify_url("https://example.com").is_some());
        assert!(classify_domain("https://example.com").is_none());
    }

    #[test]
    fn test_tld_validation() {
        assert!(has_valid_tld("example.com"));
        assert!(has_valid_tld("test.org"));
        assert!(has_valid_tld("website.io"));
        assert!(has_valid_tld("app.dev"));
        assert!(!has_valid_tld("example.invalidtld"));
        assert!(!has_valid_tld("nodot"));
    }

    #[test]
    fn test_edge_cases() {
        // Empty strings
        assert!(classify_url("").is_none());
        assert!(classify_domain("").is_none());

        // Single characters
        assert!(classify_url("a").is_none());
        assert!(classify_domain("a").is_none());

        // Just TLD
        assert!(classify_domain(".com").is_none());

        // IP-like domains (should be handled by IP classifier)
        assert!(classify_domain("192.168.1.1").is_none());
    }

    #[test]
    fn test_file_extensions_not_domains() {
        // File extensions should NOT be treated as valid TLDs
        assert!(classify_domain("cmd.exe").is_none());
        assert!(classify_domain("kernel32.dll").is_none());
        assert!(classify_domain("ntoskrnl.sys").is_none());
        assert!(classify_domain("program.bin").is_none());
        assert!(classify_domain("data.dat").is_none());
        assert!(classify_domain("debug.log").is_none());
        assert!(classify_domain("temp.tmp").is_none());
        assert!(classify_domain("backup.bak").is_none());
    }
}
