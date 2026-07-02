//! ASCII String Extraction Module
//!
//! This module provides foundational ASCII string extraction for Stringy.
//! It implements byte-level scanning for contiguous printable ASCII sequences and serves
//! as the reference implementation for future UTF-8, UTF-16LE, and UTF-16BE extractors.
//!
//! # Examples
//!
//! ```rust
//! use stringy::extraction::ascii::{extract_ascii_strings, extract_from_section, AsciiExtractionConfig};
//! use stringy::types::{SectionInfo, SectionType};
//!
//! // Basic extraction from raw data
//! let data = b"Hello\0World\0Test123";
//! let config = AsciiExtractionConfig::default();
//! let strings = extract_ascii_strings(data, &config);
//!
//! // Section-aware extraction
//! let section = SectionInfo::new(
//!     ".rodata".to_string(),
//!     0,
//!     20,
//!     SectionType::StringData,
//!     1.0,
//! )
//! .with_rva(0x1000);
//! let strings = extract_from_section(&section, data, &config, None, false, 0.5);
//! ```

mod extraction;

#[cfg(test)]
mod tests;

pub(crate) use extraction::termination_confidence;
pub use extraction::{extract_ascii_strings, extract_from_section};

/// Configuration for ASCII string extraction
///
/// Controls minimum and maximum string length filtering. This structure serves as the
/// foundation for future configuration expansion, including encoding preferences and
/// tag filters as mentioned in the issue.
///
/// # Default Values
///
/// - `min_length`: 4 (standard minimum to reduce noise)
/// - `max_length`: None (no upper limit by default)
///
/// # Examples
///
/// ```rust
/// use stringy::extraction::ascii::AsciiExtractionConfig;
///
/// // Use default configuration
/// let config = AsciiExtractionConfig::default();
///
/// // Custom minimum length
/// let config = AsciiExtractionConfig::new(8);
///
/// // Custom minimum and maximum length
/// let mut config = AsciiExtractionConfig::default();
/// config.max_length = Some(256);
/// ```
#[derive(Debug, Clone)]
pub struct AsciiExtractionConfig {
    /// Minimum string length in bytes (default: 4)
    pub min_length: usize,
    /// Maximum string length in bytes (default: None, no limit)
    pub max_length: Option<usize>,
}

impl Default for AsciiExtractionConfig {
    fn default() -> Self {
        Self {
            min_length: 4,
            max_length: None,
        }
    }
}

impl AsciiExtractionConfig {
    /// Create a new AsciiExtractionConfig with custom minimum length
    ///
    /// # Arguments
    ///
    /// * `min_length` - Minimum string length in bytes
    ///
    /// # Returns
    ///
    /// New AsciiExtractionConfig with specified minimum length and default max_length (None)
    ///
    /// # Example
    ///
    /// ```rust
    /// use stringy::extraction::ascii::AsciiExtractionConfig;
    ///
    /// let config = AsciiExtractionConfig::new(8);
    /// assert_eq!(config.min_length, 8);
    /// assert_eq!(config.max_length, None);
    /// ```
    pub fn new(min_length: usize) -> Self {
        Self {
            min_length,
            max_length: None,
        }
    }
}

/// Check if a byte is in the printable ASCII range
///
/// Printable ASCII includes characters from 0x20 (space) through 0x7E (tilde).
/// This range covers all standard printable ASCII characters.
///
/// **Note on printable character definitions**: This function uses a strict definition
/// of printable ASCII (0x20-0x7E only), excluding whitespace control characters like
/// tab, newline, and carriage return. This differs from `is_printable_text_byte` in
/// `extraction::helpers`, which includes common whitespace characters (0x09, 0x0A, 0x0D)
/// to handle formatted text. This strict definition ensures ASCII-only extraction
/// produces predictable, consistent results.
///
/// # Arguments
///
/// * `byte` - Byte to check
///
/// # Returns
///
/// `true` if the byte is printable ASCII, `false` otherwise
///
/// # Example
///
/// ```rust
/// use stringy::extraction::ascii::is_printable_ascii;
///
/// assert!(is_printable_ascii(b' '));
/// assert!(is_printable_ascii(b'A'));
/// assert!(is_printable_ascii(b'z'));
/// assert!(is_printable_ascii(b'0'));
/// assert!(is_printable_ascii(b'~'));
/// assert!(!is_printable_ascii(0x00));
/// assert!(!is_printable_ascii(0x1F));
/// assert!(!is_printable_ascii(0x7F));
/// ```
#[inline]
pub fn is_printable_ascii(byte: u8) -> bool {
    (0x20..=0x7E).contains(&byte)
}
