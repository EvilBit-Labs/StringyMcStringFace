//! Symbol demangling for Rust, C++, and MSVC symbols
//!
//! This module provides functionality to detect and demangle mangled symbols
//! from compiled Rust, C++, and MSVC binaries. When a mangled symbol is
//! detected, the original mangled form is preserved in
//! `FoundString.original_text` while the demangled human-readable form replaces
//! `FoundString.text`.
//!
//! # Supported Symbol Formats
//!
//! - **Rust legacy mangling**: Symbols starting with `_ZN` (uses Itanium ABI-like encoding)
//! - **Rust v0 mangling**: Symbols starting with `_R` (new Rust-specific encoding)
//! - **C++ Itanium ABI**: Symbols starting with `_Z` (used by GCC, Clang, and others)
//! - **MSVC mangling**: Symbols starting with `?` (used by MSVC on Windows PE binaries)
//!
//! # Usage
//!
//! ```rust
//! use stringy::classification::SymbolDemangler;
//! use stringy::types::{FoundString, Encoding, StringSource, Tag};
//!
//! let demangler = SymbolDemangler::new();
//! let text = "_ZN4core3fmt5Write9write_str17h1234567890abcdefE";
//! let mut found_string = FoundString::new(
//!     text.to_string(),
//!     Encoding::Ascii,
//!     0,
//!     text.len() as u32,
//!     StringSource::ImportName,
//! );
//!
//! demangler.demangle(&mut found_string);
//! assert!(found_string.tags.contains(&Tag::DemangledSymbol));
//! // found_string.text now contains the demangled symbol
//! // found_string.original_text contains the original mangled form
//! // found_string.tags contains Tag::DemangledSymbol
//! ```

use crate::types::{FoundString, Tag};
use cpp_demangle::Symbol as CppSymbol;
use msvc_demangler::DemangleFlags;

/// Symbol demangler for Rust, C++, and MSVC symbols
///
/// Uses the `rustc-demangle` crate for Rust symbols, the `cpp_demangle` crate
/// for C++ Itanium ABI symbols, and the `msvc-demangler` crate for MSVC
/// symbols. Converts mangled symbols into human-readable form while preserving
/// the original mangled text.
#[derive(Debug, Default, Clone)]
pub struct SymbolDemangler;

impl SymbolDemangler {
    /// Create a new instance of the symbol demangler
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Check if a symbol appears to be a mangled Rust, C++, or MSVC symbol
    ///
    /// Returns `true` if the symbol starts with known mangling prefixes:
    /// - `_ZN` - Rust legacy mangling or C++ nested names (Itanium ABI)
    /// - `_R` - Rust v0 mangling scheme
    /// - `_Z` - C++ Itanium ABI mangling (used by GCC, Clang)
    /// - `?` - MSVC mangling (used by MSVC on Windows)
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
    /// // Rust symbols
    /// assert!(demangler.is_mangled("_ZN4core3fmt5Write9write_str17h1234567890abcdefE"));
    /// assert!(demangler.is_mangled("_RNvNtCs123_4core3fmt5write"));
    /// // C++ symbols
    /// assert!(demangler.is_mangled("_ZN3foo3barEv"));
    /// assert!(demangler.is_mangled("_Z3foov"));
    /// // MSVC symbols
    /// assert!(demangler.is_mangled("?printf@@YAHPEBDZZ"));
    /// assert!(!demangler.is_mangled("printf"));
    /// ```
    #[must_use]
    pub fn is_mangled(&self, symbol: &str) -> bool {
        // Rust v0 mangling scheme (Rust-specific, check first)
        if symbol.starts_with("_R") {
            return true;
        }

        // Itanium ABI mangling (used by both Rust legacy and C++)
        // This includes _ZN (nested names), _ZL (local), _ZTV (vtable), etc.
        if symbol.starts_with("_Z") {
            return true;
        }

        // MSVC mangling (used by MSVC on Windows PE binaries)
        if symbol.starts_with('?') {
            return true;
        }

        false
    }

    /// Attempt to demangle a symbol in a `FoundString`
    ///
    /// If the string appears to be a mangled Rust, C++, or MSVC symbol and can
    /// be successfully demangled:
    /// - The original mangled form is stored in `original_text`
    /// - The demangled form replaces `text`
    /// - `Tag::DemangledSymbol` is added to the tags
    ///
    /// The demangler tries Rust demangling first (for `_R` and `_ZN` prefixes),
    /// falls back to C++ demangling for `_Z` prefixes, and uses MSVC demangling
    /// for `?` prefixes.
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
    /// let text = "_ZN4core3fmt5Write9write_str17h1234567890abcdefE";
    /// let mut found_string = FoundString::new(
    ///     text.to_string(),
    ///     Encoding::Ascii,
    ///     0,
    ///     text.len() as u32,
    ///     StringSource::ImportName,
    /// );
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

        // Try to demangle
        let demangled_str = match self.try_demangle_internal(&string.text) {
            Some(s) => s,
            None => return,
        };

        // Store original mangled form and replace with demangled
        string.original_text = Some(string.text.clone());
        string.text = demangled_str;

        // Add the DemangledSymbol tag if not already present
        if !string.tags.contains(&Tag::DemangledSymbol) {
            string.tags.push(Tag::DemangledSymbol);
        }
    }

    /// Internal demangling logic that tries Rust then C++
    fn try_demangle_internal(&self, symbol: &str) -> Option<String> {
        // For Rust v0 symbols (_R prefix), only try Rust demangling
        if symbol.starts_with("_R") {
            return self.try_rust_demangle(symbol);
        }

        // For _Z prefixed symbols, try Rust first (for legacy Rust symbols),
        // then fall back to C++ if Rust demangling doesn't work
        if symbol.starts_with("_Z") {
            // Try Rust first (handles _ZN Rust legacy symbols)
            if let Some(demangled) = self.try_rust_demangle(symbol) {
                return Some(demangled);
            }

            // Fall back to C++ demangling
            return self.try_cpp_demangle(symbol);
        }

        // For ?-prefixed symbols, use MSVC demangling
        if symbol.starts_with('?') {
            return self.try_msvc_demangle(symbol);
        }

        None
    }

    /// Try to demangle as a Rust symbol
    fn try_rust_demangle(&self, symbol: &str) -> Option<String> {
        let demangled = rustc_demangle::demangle(symbol);
        let demangled_str = demangled.to_string();

        // Check if demangling actually produced a different result
        if demangled_str != symbol {
            Some(demangled_str)
        } else {
            None
        }
    }

    /// Try to demangle as a C++ symbol
    fn try_cpp_demangle(&self, symbol: &str) -> Option<String> {
        // Parse the symbol using cpp_demangle
        let parsed = CppSymbol::new(symbol).ok()?;
        let demangled_str = parsed.demangle().ok()?;

        // Check if demangling actually produced a different result
        if demangled_str != symbol {
            Some(demangled_str)
        } else {
            None
        }
    }

    /// Try to demangle as an MSVC symbol
    fn try_msvc_demangle(&self, symbol: &str) -> Option<String> {
        // Demangle using the msvc-demangler crate with LLVM-style output
        let demangled_str = msvc_demangler::demangle(symbol, DemangleFlags::llvm()).ok()?;

        // Check if demangling actually produced a different result
        if demangled_str != symbol {
            Some(demangled_str)
        } else {
            None
        }
    }

    /// Try to demangle a symbol string directly
    ///
    /// This is a convenience method for demangling without a `FoundString`.
    /// Supports Rust, C++, and MSVC mangled symbols.
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
    ///
    /// // Rust symbol
    /// let result = demangler.try_demangle("_ZN4core3fmt5Write9write_str17h1234567890abcdefE");
    /// assert!(result.is_some());
    ///
    /// // C++ symbol
    /// let result = demangler.try_demangle("_ZN3foo3barEv");
    /// assert!(result.is_some());
    ///
    /// // MSVC symbol
    /// let result = demangler.try_demangle("?printf@@YAHPEBDZZ");
    /// assert!(result.is_some());
    ///
    /// // Not mangled
    /// let result = demangler.try_demangle("printf");
    /// assert!(result.is_none());
    /// ```
    #[must_use]
    pub fn try_demangle(&self, symbol: &str) -> Option<String> {
        if !self.is_mangled(symbol) {
            return None;
        }

        self.try_demangle_internal(symbol)
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
            display_score: None,
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

    // C++ demangling tests

    #[test]
    fn test_is_mangled_cpp_symbols() {
        let demangler = SymbolDemangler::new();

        // C++ Itanium ABI mangled symbols
        assert!(demangler.is_mangled("_ZN3foo3barEv")); // foo::bar()
        assert!(demangler.is_mangled("_Z3foov")); // foo()
        assert!(demangler.is_mangled("_ZN9__gnu_cxx13new_allocatorIcE10deallocateEPcm"));
        assert!(demangler.is_mangled("_ZNSt6vectorIiSaIiEE9push_backERKi"));
        assert!(demangler.is_mangled("_ZTV5MyClass")); // vtable for MyClass
        assert!(demangler.is_mangled("_ZTI5MyClass")); // typeinfo for MyClass
    }

    #[test]
    fn test_demangle_cpp_symbol() {
        let demangler = SymbolDemangler::new();
        let mut found_string = create_test_string("_ZN3foo3barEv");

        demangler.demangle(&mut found_string);

        // Should have been demangled
        assert!(found_string.original_text.is_some());
        assert_eq!(
            found_string.original_text.as_ref().unwrap(),
            "_ZN3foo3barEv"
        );
        assert!(found_string.tags.contains(&Tag::DemangledSymbol));
        // Demangled text should contain "foo" and "bar"
        assert!(found_string.text.contains("foo"));
        assert!(found_string.text.contains("bar"));
    }

    #[test]
    fn test_try_demangle_cpp_success() {
        let demangler = SymbolDemangler::new();

        // Simple C++ function
        let result = demangler.try_demangle("_Z3foov");
        assert!(result.is_some());
        let demangled = result.unwrap();
        assert!(demangled.contains("foo"));

        // Namespaced C++ function
        let result = demangler.try_demangle("_ZN3foo3barEv");
        assert!(result.is_some());
        let demangled = result.unwrap();
        assert!(demangled.contains("foo"));
        assert!(demangled.contains("bar"));
    }

    #[test]
    fn test_demangle_cpp_with_parameters() {
        let demangler = SymbolDemangler::new();

        // C++ function with int parameter: void foo(int)
        let result = demangler.try_demangle("_Z3fooi");
        assert!(result.is_some());
        let demangled = result.unwrap();
        assert!(demangled.contains("foo"));
        assert!(demangled.contains("int"));
    }

    #[test]
    fn test_demangle_cpp_template() {
        let demangler = SymbolDemangler::new();

        // C++ template: std::vector<int>
        let result = demangler.try_demangle("_ZNSt6vectorIiSaIiEEC1Ev");
        assert!(result.is_some());
        let demangled = result.unwrap();
        assert!(demangled.contains("vector"));
    }

    #[test]
    fn test_cpp_symbol_in_found_string() {
        let demangler = SymbolDemangler::new();
        let mut found_string = create_test_string("_Z3fooi");
        found_string.tags.push(Tag::Export);

        demangler.demangle(&mut found_string);

        // Should have been demangled and preserved existing tags
        assert!(found_string.original_text.is_some());
        assert!(found_string.tags.contains(&Tag::Export));
        assert!(found_string.tags.contains(&Tag::DemangledSymbol));
        assert!(found_string.text.contains("foo"));
    }

    // MSVC demangling tests

    #[test]
    fn test_is_mangled_msvc_symbols() {
        let demangler = SymbolDemangler::new();

        // MSVC-mangled symbols (?-prefixed)
        assert!(demangler.is_mangled("?printf@@YAHPEBDZZ")); // int __cdecl printf(...)
        assert!(demangler.is_mangled("??0MyClass@@QEAA@XZ")); // MyClass::MyClass(void)
        assert!(demangler.is_mangled("??HMyClass@@QEAAHH@Z")); // MyClass::operator+(int)
    }

    #[test]
    fn test_is_mangled_msvc_not_triggered_for_plain() {
        let demangler = SymbolDemangler::new();

        // Plain Windows API names and empty input must not be treated as MSVC mangled
        assert!(!demangler.is_mangled("printf"));
        assert!(!demangler.is_mangled("CreateFileW"));
        assert!(!demangler.is_mangled(""));
    }

    #[test]
    fn test_demangle_msvc_plain_function() {
        let demangler = SymbolDemangler::new();
        let mut found_string = create_test_string("?printf@@YAHPEBDZZ");

        demangler.demangle(&mut found_string);

        // Should have been demangled with original preserved and tag applied
        assert_eq!(
            found_string.original_text.as_ref().unwrap(),
            "?printf@@YAHPEBDZZ"
        );
        assert!(found_string.tags.contains(&Tag::DemangledSymbol));
        assert!(found_string.text.contains("printf"));
        assert_ne!(found_string.text, "?printf@@YAHPEBDZZ");
    }

    #[test]
    fn test_demangle_msvc_constructor() {
        let demangler = SymbolDemangler::new();
        let mut found_string = create_test_string("??0MyClass@@QEAA@XZ");

        demangler.demangle(&mut found_string);

        // Constructor symbol should demangle and reference the class name
        assert!(found_string.original_text.is_some());
        assert!(found_string.tags.contains(&Tag::DemangledSymbol));
        assert!(found_string.text.contains("MyClass"));
    }

    #[test]
    fn test_demangle_msvc_operator() {
        let demangler = SymbolDemangler::new();
        let mut found_string = create_test_string("??HMyClass@@QEAAHH@Z");

        demangler.demangle(&mut found_string);

        // Operator-overload symbol should demangle to a readable operator form
        assert!(found_string.original_text.is_some());
        assert!(found_string.tags.contains(&Tag::DemangledSymbol));
        assert!(found_string.text.contains("operator+"));
    }

    #[test]
    fn test_demangle_msvc_invalid_fallback() {
        let demangler = SymbolDemangler::new();
        let mut found_string = create_test_string("?notvalid");

        demangler.demangle(&mut found_string);

        // Invalid MSVC input should leave the FoundString unchanged
        assert_eq!(found_string.text, "?notvalid");
        assert!(found_string.original_text.is_none());
        assert!(!found_string.tags.contains(&Tag::DemangledSymbol));
    }

    #[test]
    fn test_try_demangle_msvc_success() {
        let demangler = SymbolDemangler::new();

        let result = demangler.try_demangle("?printf@@YAHPEBDZZ");
        assert!(result.is_some());
        assert!(result.unwrap().contains("printf"));
    }

    #[test]
    fn test_try_demangle_msvc_failure() {
        let demangler = SymbolDemangler::new();

        // A bare "?" is detected as mangled but cannot be demangled
        assert!(demangler.try_demangle("?").is_none());
    }

    #[test]
    fn test_msvc_symbol_preserves_existing_tags() {
        let demangler = SymbolDemangler::new();
        let mut found_string = create_test_string("?printf@@YAHPEBDZZ");
        found_string.tags.push(Tag::Import);

        demangler.demangle(&mut found_string);

        // Existing tags should survive alongside the new demangled tag
        assert!(found_string.tags.contains(&Tag::Import));
        assert!(found_string.tags.contains(&Tag::DemangledSymbol));
    }
}
