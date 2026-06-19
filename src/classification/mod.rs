//! String analysis and tagging
//!
//! This module provides semantic analysis capabilities to identify and tag
//! extracted strings based on their content patterns. The classification system
//! uses pattern matching combined with validation to reduce false positives.
//!
//! ## Current Capabilities
//!
//! - URL detection (HTTP/HTTPS)
//! - Domain name detection
//! - IPv4 and IPv6 address detection
//! - File path detection (POSIX, Windows, UNC)
//! - Windows registry path detection
//! - GUID detection
//! - Email detection
//! - Base64 detection
//! - Printf-style format string detection
//! - User agent detection
//!
//! ## Usage
//!
//! ```rust
//! use stringy::classification::SemanticClassifier;
//! use stringy::types::{BinaryFormat, Encoding, SectionType, StringContext, StringSource, Tag};
//!
//! let classifier = SemanticClassifier::new();
//! let text = "{12345678-1234-1234-1234-123456789abc}";
//! let context = StringContext::new(
//!     SectionType::StringData,
//!     BinaryFormat::Elf,
//!     Encoding::Ascii,
//!     StringSource::SectionData,
//! )
//! .with_section_name(".rodata".to_string());
//!
//! let tags = classifier.classify(text, &context);
//! assert!(tags.contains(&Tag::Guid));
//! ```

use regex::Regex;
use std::sync::LazyLock;

use crate::types::{BinaryFormat, SectionType, StringContext, StringSource, Tag};

pub mod imports;
pub mod patterns;
pub mod ranking;
pub mod symbols;

pub use imports::{ImportClassifier, extract_symbol_strings};
pub use ranking::{RankingConfig, RankingEngine};
pub use symbols::SymbolDemangler;

// Import pattern classification functions
use patterns::{
    classify_domain, classify_ip_addresses, classify_posix_path, classify_registry_path,
    classify_unc_path, classify_url, classify_windows_path,
};

static GUID_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$")
        .expect("Invalid GUID regex")
});

static EMAIL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").expect("Invalid email regex")
});

static BASE64_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9+/]{20,}={0,2}$").expect("Invalid base64 regex"));

static FORMAT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"%[sdxofcpn]|%\d+[sdxofcpn]|\{\d+\}").expect("Invalid format regex")
});

static USER_AGENT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(Mozilla/[0-9.]+|Chrome/[0-9.]+|Safari/[0-9.]+|AppleWebKit/[0-9.]+)")
        .expect("Invalid user agent regex")
});

#[derive(Debug, Default)]
pub struct SemanticClassifier;

/// Internal struct for testing regex caching - not part of public API
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RegexCacheAddresses {
    pub(crate) guid: usize,
    pub(crate) email: usize,
    pub(crate) base64: usize,
    pub(crate) format: usize,
    pub(crate) user_agent: usize,
}

#[derive(Debug, Clone, Copy)]
enum PatternKind {
    Guid,
    Email,
    Base64,
    FormatString,
    UserAgent,
}

impl SemanticClassifier {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn classify(&self, text: &str, context: &StringContext) -> Vec<Tag> {
        let mut tags = Vec::new();

        // Check for URLs first
        if let Some(tag) = classify_url(text) {
            tags.push(tag);
        }

        // Check for domains (automatically excludes URLs)
        if let Some(tag) = classify_domain(text) {
            tags.push(tag);
        }

        // Check for IP addresses (IPv4 and IPv6)
        let ip_tags = classify_ip_addresses(text);
        tags.extend(ip_tags);

        // Check for file paths (POSIX, Windows, UNC) - only add FilePath tag once
        if classify_posix_path(text).is_some()
            || classify_windows_path(text).is_some()
            || classify_unc_path(text).is_some()
        {
            tags.push(Tag::FilePath);
        }

        // Check for registry paths
        if let Some(tag) = classify_registry_path(text) {
            tags.push(tag);
        }

        if self.matches_guid(text, context) {
            tags.push(Tag::Guid);
        }

        if self.matches_email(text, context) {
            tags.push(Tag::Email);
        }

        if self.matches_format_string(text, context) {
            tags.push(Tag::FormatString);
        }

        if self.matches_user_agent(text, context) {
            tags.push(Tag::UserAgent);
        }

        if self.matches_base64(text, context) {
            tags.push(Tag::Base64);
        }

        tags
    }

    /// Backward-compatible entry point for classifying a FoundString
    ///
    /// This method constructs a StringContext from the FoundString metadata
    /// and delegates to the context-aware classify method. Use this when you
    /// have a FoundString but don't have access to the full container context.
    ///
    /// Note: This uses placeholder values for section_type and binary_format
    /// since they're not available in FoundString. For best results, use the
    /// classify method with a properly constructed StringContext.
    #[must_use]
    pub fn classify_found_string(&self, found: &crate::types::FoundString) -> Vec<Tag> {
        let context = StringContext::new(
            SectionType::Other,
            BinaryFormat::Unknown,
            found.encoding,
            found.source,
        );
        let context = match &found.section {
            Some(name) => context.with_section_name(name.clone()),
            None => context,
        };
        self.classify(&found.text, &context)
    }

    fn matches_guid(&self, text: &str, context: &StringContext) -> bool {
        let min_len = calculate_min_length(PatternKind::Guid, context);
        if text.len() < min_len {
            return false;
        }
        // GUID regex is comprehensive - no additional validation needed
        GUID_REGEX.is_match(text)
    }

    fn matches_email(&self, text: &str, context: &StringContext) -> bool {
        let min_len = calculate_min_length(PatternKind::Email, context);
        if text.len() < min_len {
            return false;
        }
        if !EMAIL_REGEX.is_match(text) {
            return false;
        }
        is_valid_email(text)
    }

    fn matches_base64(&self, text: &str, context: &StringContext) -> bool {
        let min_len = calculate_min_length(PatternKind::Base64, context);
        if text.len() < min_len {
            return false;
        }
        if !BASE64_REGEX.is_match(text) {
            return false;
        }
        is_valid_base64(text)
    }

    fn matches_format_string(&self, text: &str, context: &StringContext) -> bool {
        let min_len = calculate_min_length(PatternKind::FormatString, context);
        if text.len() < min_len {
            return false;
        }
        if !FORMAT_REGEX.is_match(text) {
            return false;
        }
        is_valid_format_string(text, context)
    }

    fn matches_user_agent(&self, text: &str, context: &StringContext) -> bool {
        let min_len = calculate_min_length(PatternKind::UserAgent, context);
        if text.len() < min_len {
            return false;
        }
        if !USER_AGENT_REGEX.is_match(text) {
            return false;
        }
        is_valid_user_agent(text)
    }
}

fn is_valid_email(text: &str) -> bool {
    let mut parts = text.split('@');
    let local = match parts.next() {
        Some(value) if !value.is_empty() => value,
        _ => return false,
    };
    let domain = match parts.next() {
        Some(value) if !value.is_empty() => value,
        _ => return false,
    };
    if parts.next().is_some() {
        return false;
    }

    if local.starts_with('.') || local.ends_with('.') {
        return false;
    }

    if domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }

    if domain.contains("..") {
        return false;
    }

    let tld = match domain.rsplit('.').next() {
        Some(value) => value,
        None => return false,
    };
    if tld.len() < 2 || tld.len() > 24 {
        return false;
    }
    if !tld.chars().all(|c| c.is_ascii_alphabetic()) {
        return false;
    }

    true
}

fn is_valid_base64(text: &str) -> bool {
    let len = text.len();
    if len < 20 {
        return false;
    }
    if !len.is_multiple_of(4) {
        return false;
    }

    let padding = text.chars().rev().take_while(|c| *c == '=').count();
    if padding > 2 {
        return false;
    }
    if padding > 0 {
        let body_len = len - padding;
        if text[..body_len].contains('=') {
            return false;
        }
    }

    if looks_like_hex(text) {
        return false;
    }

    let entropy = shannon_entropy(text.as_bytes());
    entropy >= 3.0
}

fn is_valid_format_string(text: &str, context: &StringContext) -> bool {
    let specifier_count = FORMAT_REGEX.find_iter(text).count();
    if specifier_count == 0 || specifier_count > 25 {
        return false;
    }

    if !should_boost_confidence(context) && specifier_count < 2 && text.len() < 12 {
        return false;
    }

    true
}

fn is_valid_user_agent(text: &str) -> bool {
    if text.len() < 10 {
        return false;
    }

    USER_AGENT_REGEX.is_match(text)
}

fn should_boost_confidence(context: &StringContext) -> bool {
    matches!(
        context.section_type,
        SectionType::StringData | SectionType::ReadOnlyData | SectionType::Resources
    ) || matches!(
        context.source,
        StringSource::ImportName
            | StringSource::ExportName
            | StringSource::ResourceString
            | StringSource::LoadCommand
    )
}

fn calculate_min_length(kind: PatternKind, context: &StringContext) -> usize {
    let boosted = should_boost_confidence(context);
    match kind {
        PatternKind::Guid => 38,
        PatternKind::Email => {
            if boosted {
                6
            } else {
                8
            }
        }
        PatternKind::Base64 => {
            if boosted {
                20
            } else {
                24
            }
        }
        PatternKind::FormatString => {
            if boosted {
                3
            } else {
                8
            }
        }
        PatternKind::UserAgent => {
            if boosted {
                10
            } else {
                14
            }
        }
    }
}

fn looks_like_hex(text: &str) -> bool {
    text.chars().all(|c| c.is_ascii_hexdigit())
}

fn shannon_entropy(data: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0f64;
    for count in counts {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

#[cfg(test)]
impl SemanticClassifier {
    /// Returns memory addresses of cached regex patterns for testing
    #[must_use]
    pub(crate) fn regex_cache_addresses(&self) -> RegexCacheAddresses {
        RegexCacheAddresses {
            guid: &*GUID_REGEX as *const Regex as usize,
            email: &*EMAIL_REGEX as *const Regex as usize,
            base64: &*BASE64_REGEX as *const Regex as usize,
            format: &*FORMAT_REGEX as *const Regex as usize,
            user_agent: &*USER_AGENT_REGEX as *const Regex as usize,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regex_caching() {
        // Verify that regex patterns are cached via std::sync::LazyLock
        let first = SemanticClassifier::new().regex_cache_addresses();
        let second = SemanticClassifier::new().regex_cache_addresses();
        assert_eq!(
            first, second,
            "Regex addresses should be stable across instances"
        );
    }
}
