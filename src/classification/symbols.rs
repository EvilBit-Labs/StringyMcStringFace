//! Symbol demangling for Rust and C++ symbols
//!
//! This module provides functionality to detect and demangle mangled symbols
//! from compiled Rust binaries. When a mangled symbol is detected, the original
//! mangled form is preserved in `FoundString.original_text` while the demangled
//! human-readable form replaces `FoundString.text`.
//!
//! # Supported Symbol Formats
//!
//! - **Rust legacy mangling**: Symbols starting with `_ZN` (uses Itanium ABI-like encoding)
//! - **Rust v0 mangling**: Symbols starting with `_R` (new Rust-specific encoding)
//!
//! # Usage
//!
//! ```rust
//! use stringy::classification::SymbolDemangler;
//! use stringy::types::{FoundString, Encoding, StringSource, Tag};
//!
//! let demangler = SymbolDemangler::new();
//! let mut found_string = FoundString {
//!     text: "_ZN4core3fmt5Write9write_str17h1234567890abcdefE".to_string(),
//!     original_text: None,
//!     encoding: Encoding::Ascii,
//!     offset: 0,
//!     rva: None,
//!     section: None,
//!     length: 47,
//!     tags: Vec::new(),
//!     score: 0,
//!     section_weight: None,
//!     semantic_boost: None,
//!     noise_penalty: None,
//!     source: StringSource::ImportName,
//!     confidence: 1.0,
//! };
//!
//! demangler.demangle(&mut found_string);
//! // found_string.text now contains the demangled symbol
//! // found_string.original_text contains the original mangled form
//! // found_string.tags contains Tag::DemangledSymbol
//! ```

use crate::types::{FoundString, Tag};

/// Symbol demangler for Rust symbols
///
/// Uses the `rustc-demangle` crate to convert mangled Rust symbols into
/// human-readable form while preserving the original mangled text.
#[derive(Debug, Default, Clone)]
pub struct SymbolDemangler;

impl SymbolDemangler {
    /// Create a new instance of the symbol demangler
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Check if a symbol appears to be a mangled Rust symbol
    ///
    /// Returns `true` if the symbol starts with known Rust mangling prefixes:
    /// - `_ZN` - Rust legacy mangling (Itanium ABI-like)
    /// - `_R` - Rust v0 mangling scheme
    ///
    /// # Arguments
    ///
    /// * `symbol` - The symbol string to check
    ///
    /// # Returns
    ///
    /// Returns `true` if the symbol appears to be mangled, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use stringy::classification::SymbolDemangler;
    ///
    /// let demangler = SymbolDemangler::new();
    /// assert!(demangler.is_mangled("_ZN4core3fmt5Write9write_str17h1234567890abcdefE"));
    /// assert!(demangler.is_mangled("_RNvNtCs123_4core3fmt5write"));
    /// assert!(!demangler.is_mangled("printf"));
    /// ```
    #[must_use]
    pub fn is_mangled(&self, symbol: &str) -> bool {
        // Rust legacy mangling (Itanium ABI-like)
        if symbol.starts_with("_ZN") {
            return true;
        }

        // Rust v0 mangling scheme
        if symbol.starts_with("_R") {
            return true;
        }

        false
    }

    /// Attempt to demangle a symbol in a `FoundString`
    ///
    /// If the string appears to be a mangled Rust symbol and can be successfully
    /// demangled:
    /// - The original mangled form is stored in `original_text`
    /// - The demangled form replaces `text`
    /// - `Tag::DemangledSymbol` is added to the tags
    ///
    /// If demangling fails or the symbol is not mangled, the `FoundString` is
    /// left unchanged.
    ///
    /// # Arguments
    ///
    /// * `string` - The `FoundString` to process (modified in-place)
    ///
    /// # Examples
    ///
    /// ```
    /// use stringy::classification::SymbolDemangler;
    /// use stringy::types::{FoundString, Encoding, StringSource, Tag};
    ///
    /// let demangler = SymbolDemangler::new();
    /// let mut found_string = FoundString {
    ///     text: "_ZN4core3fmt5Write9write_str17h1234567890abcdefE".to_string(),
    ///     original_text: None,
    ///     encoding: Encoding::Ascii,
    ///     offset: 0,
    ///     rva: None,
    ///     section: None,
    ///     length: 47,
    ///     tags: Vec::new(),
    ///     score: 0,
    ///     section_weight: None,
    ///     semantic_boost: None,
    ///     noise_penalty: None,
    ///     source: StringSource::ImportName,
    ///     confidence: 1.0,
    /// };
    ///
    /// demangler.demangle(&mut found_string);
    /// assert!(found_string.tags.contains(&Tag::DemangledSymbol));
    /// assert!(found_string.original_text.is_some());
    /// ```
    pub fn demangle(&self, string: &mut FoundString) {
        // Only attempt demangling if it looks like a mangled symbol
        if !self.is_mangled(&string.text) {
            return;
        }

        // Attempt to demangle using rustc-demangle
        let demangled = rustc_demangle::demangle(&string.text);
        let demangled_str = demangled.to_string();

        // Check if demangling actually produced a different result
        // If the demangled form equals the original, demangling failed
        if demangled_str == string.text {
            return;
        }

        // Store original mangled form and replace with demangled
        string.original_text = Some(string.text.clone());
        string.text = demangled_str;

        // Add the DemangledSymbol tag if not already present
        if !string.tags.contains(&Tag::DemangledSymbol) {
            string.tags.push(Tag::DemangledSymbol);
        }
    }

    /// Try to demangle a symbol string directly
    ///
    /// This is a convenience method for demangling without a `FoundString`.
    ///
    /// # Arguments
    ///
    /// * `symbol` - The mangled symbol string
    ///
    /// # Returns
    ///
    /// Returns `Some(demangled)` if demangling succeeded and produced a different
    /// result, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use stringy::classification::SymbolDemangler;
    ///
    /// let demangler = SymbolDemangler::new();
    /// let result = demangler.try_demangle("_ZN4core3fmt5Write9write_str17h1234567890abcdefE");
    /// assert!(result.is_some());
    ///
    /// let result = demangler.try_demangle("printf");
    /// assert!(result.is_none());
    /// ```
    #[must_use]
    pub fn try_demangle(&self, symbol: &str) -> Option<String> {
        if !self.is_mangled(symbol) {
            return None;
        }

        let demangled = rustc_demangle::demangle(symbol);
        let demangled_str = demangled.to_string();

        // Check if demangling actually worked
        if demangled_str == symbol {
            return None;
        }

        Some(demangled_str)
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
            source: StringSource::ImportName,
            confidence: 1.0,
        }
    }

    #[test]
    fn test_is_mangled_rust_legacy() {
        let demangler = SymbolDemangler::new();

        // Legacy Rust mangling (_ZN prefix)
        assert!(demangler.is_mangled("_ZN4core3fmt5Write9write_str17h1234567890abcdefE"));
        assert!(demangler.is_mangled("_ZN3std2io5stdio6_print17h1234567890abcdefE"));
    }

    #[test]
    fn test_is_mangled_rust_v0() {
        let demangler = SymbolDemangler::new();

        // Rust v0 mangling (_R prefix)
        assert!(demangler.is_mangled("_RNvNtCs123_4core3fmt5write"));
        assert!(demangler.is_mangled("_RNvCs123_5hello4main"));
    }

    #[test]
    fn test_is_mangled_not_mangled() {
        let demangler = SymbolDemangler::new();

        // Regular symbols should not be detected as mangled
        assert!(!demangler.is_mangled("printf"));
        assert!(!demangler.is_mangled("malloc"));
        assert!(!demangler.is_mangled("main"));
        assert!(!demangler.is_mangled("CreateFileW"));
        assert!(!demangler.is_mangled(""));
    }

    #[test]
    fn test_demangle_rust_symbol() {
        let demangler = SymbolDemangler::new();
        let mut found_string =
            create_test_string("_ZN4core3fmt5Write9write_str17h1234567890abcdefE");

        demangler.demangle(&mut found_string);

        // Should have been demangled
        assert!(found_string.original_text.is_some());
        assert_eq!(
            found_string.original_text.as_ref().unwrap(),
            "_ZN4core3fmt5Write9write_str17h1234567890abcdefE"
        );
        assert!(found_string.tags.contains(&Tag::DemangledSymbol));
        // Demangled text should be different from original
        assert_ne!(
            found_string.text,
            "_ZN4core3fmt5Write9write_str17h1234567890abcdefE"
        );
    }

    #[test]
    fn test_demangle_non_mangled() {
        let demangler = SymbolDemangler::new();
        let mut found_string = create_test_string("printf");

        demangler.demangle(&mut found_string);

        // Should not have been modified
        assert_eq!(found_string.text, "printf");
        assert!(found_string.original_text.is_none());
        assert!(!found_string.tags.contains(&Tag::DemangledSymbol));
    }

    #[test]
    fn test_try_demangle_success() {
        let demangler = SymbolDemangler::new();
        let result = demangler.try_demangle("_ZN4core3fmt5Write9write_str17h1234567890abcdefE");

        assert!(result.is_some());
        let demangled = result.unwrap();
        assert!(!demangled.is_empty());
        assert_ne!(
            demangled,
            "_ZN4core3fmt5Write9write_str17h1234567890abcdefE"
        );
    }

    #[test]
    fn test_try_demangle_failure() {
        let demangler = SymbolDemangler::new();

        assert!(demangler.try_demangle("printf").is_none());
        assert!(demangler.try_demangle("").is_none());
        assert!(demangler.try_demangle("main").is_none());
    }

    #[test]
    fn test_demangle_preserves_existing_tags() {
        let demangler = SymbolDemangler::new();
        let mut found_string =
            create_test_string("_ZN4core3fmt5Write9write_str17h1234567890abcdefE");
        found_string.tags.push(Tag::Import);

        demangler.demangle(&mut found_string);

        // Should have both the original tag and the new demangled tag
        assert!(found_string.tags.contains(&Tag::Import));
        assert!(found_string.tags.contains(&Tag::DemangledSymbol));
    }

    #[test]
    fn test_demangle_idempotent() {
        let demangler = SymbolDemangler::new();
        let mut found_string =
            create_test_string("_ZN4core3fmt5Write9write_str17h1234567890abcdefE");

        demangler.demangle(&mut found_string);
        let first_text = found_string.text.clone();
        let first_original = found_string.original_text.clone();

        // Calling demangle again should not change anything
        demangler.demangle(&mut found_string);

        assert_eq!(found_string.text, first_text);
        assert_eq!(found_string.original_text, first_original);
        // Should only have one DemangledSymbol tag
        assert_eq!(
            found_string
                .tags
                .iter()
                .filter(|t| matches!(t, Tag::DemangledSymbol))
                .count(),
            1
        );
    }
}
