//! UTF-16 extraction configuration
//!
//! Contains the `Utf16ExtractionConfig` struct and its constructors for controlling
//! UTF-16 string extraction behavior.

use super::ByteOrder;

/// Configuration for UTF-16 string extraction
///
/// Controls minimum and maximum character count filtering, byte order selection,
/// and confidence thresholds. Character count refers to the number of UTF-16 code units
/// (characters), not bytes.
///
/// # Default Values
///
/// - `min_length`: 3 (minimum character count = 6 bytes)
/// - `max_length`: None (no upper limit by default)
/// - `byte_order`: Auto (detect both LE and BE)
/// - `confidence_threshold`: 0.5 (minimum UTF-16-specific confidence)
///
/// # Examples
///
/// ```rust
/// use stringy::extraction::utf16::{Utf16ExtractionConfig, ByteOrder};
///
/// // Use default configuration
/// let config = Utf16ExtractionConfig::default();
///
/// // Custom minimum character length
/// let config = Utf16ExtractionConfig::new(5);
///
/// // Custom configuration
/// let mut config = Utf16ExtractionConfig::default();
/// config.max_length = Some(256);
/// config.byte_order = ByteOrder::LE;
/// config.confidence_threshold = 0.6;
/// ```
#[derive(Debug, Clone)]
pub struct Utf16ExtractionConfig {
    /// Minimum string length in UTF-16 code units (default: 3)
    pub min_length: usize,
    /// Maximum string length in UTF-16 code units (default: None, no limit)
    pub max_length: Option<usize>,
    /// Which byte order(s) to scan (default: Auto)
    pub byte_order: ByteOrder,
    /// Minimum UTF-16-specific confidence threshold (default: 0.5)
    pub confidence_threshold: f32,
    /// Whether to scan both even and odd alignments (default: false)
    ///
    /// When enabled, performs two passes: first starting at index 0 (even), then at index 1 (odd).
    /// This can find UTF-16 strings that start at unaligned positions within the section slice,
    /// but doubles the scanning time.
    pub scan_both_alignments: bool,
}

impl Default for Utf16ExtractionConfig {
    fn default() -> Self {
        Self {
            min_length: 3,
            max_length: None,
            byte_order: ByteOrder::Auto,
            confidence_threshold: 0.5,
            scan_both_alignments: false,
        }
    }
}

impl Utf16ExtractionConfig {
    /// Create a new Utf16ExtractionConfig with custom minimum character length
    ///
    /// # Arguments
    ///
    /// * `min_length` - Minimum character count
    ///
    /// # Returns
    ///
    /// New Utf16ExtractionConfig with specified minimum length and default values for other fields
    ///
    /// # Example
    ///
    /// ```rust
    /// use stringy::extraction::utf16::Utf16ExtractionConfig;
    ///
    /// let config = Utf16ExtractionConfig::new(5);
    /// assert_eq!(config.min_length, 5);
    /// assert_eq!(config.max_length, None);
    /// ```
    pub fn new(min_length: usize) -> Self {
        Self {
            min_length,
            max_length: None,
            byte_order: ByteOrder::Auto,
            confidence_threshold: 0.5,
            scan_both_alignments: false,
        }
    }
}
