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

/// Maximum length of an MSVC symbol we will attempt to demangle.
///
/// `msvc-demangler` uses recursive-descent parsing with no depth limit, so a
/// crafted `?`-prefixed string with deeply nested type modifiers (pointers,
/// arrays, function pointers) can overflow the stack and abort the process --
/// and a stack overflow aborts rather than unwinds, so `catch_unwind` in the
/// pipeline cannot contain it. Real MSVC symbols are far shorter than this
/// bound even when heavily templated; rejecting anything longer is cheap
/// defense-in-depth against malicious binaries (see issue #19 review).
const MSVC_MAX_SYMBOL_LEN: usize = 4096;

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

    /// Internal demangling logic that tries Rust, C++, then MSVC
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
        // Reject pathologically long symbols before parsing: the demangler
        // recurses without a depth limit, and a crafted symbol can overflow the
        // stack (which aborts, uncaught by catch_unwind). See MSVC_MAX_SYMBOL_LEN.
        if symbol.len() > MSVC_MAX_SYMBOL_LEN {
            return None;
        }

        // LLVM-style flags keep demangled output consistent with the C++/Itanium path
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
mod tests;
