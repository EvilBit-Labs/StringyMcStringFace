//! Core extraction traits and configuration types
//!
//! This module contains the trait-based architecture for string extraction:
//!
//! - [`ExtractionConfig`]: Configuration for controlling extraction behavior
//! - [`StringExtractor`]: Trait defining extraction methods
//! - [`BasicExtractor`]: Sequential ASCII/UTF-8 string scanner implementation

use crate::types::{
    ContainerInfo, Encoding, FoundString, Result, SectionInfo, SectionType, StringyError,
};

use super::dedup::CanonicalString;
use super::utf16::ByteOrder;

/// Configuration for string extraction
///
/// Controls various aspects of the extraction process including minimum/maximum
/// string lengths, encoding selection, section filtering, and noise filtering.
///
/// # Example
///
/// ```rust
/// use stringy::extraction::ExtractionConfig;
///
/// // Use default configuration
/// let config = ExtractionConfig::default();
///
/// // Customize configuration
/// let mut config = ExtractionConfig::default();
/// config.min_length = 8;
/// config.max_length = 2048;
/// config.scan_code_sections = false;
/// config.noise_filtering_enabled = true;
/// config.min_confidence_threshold = 0.6;
/// ```
#[derive(Debug, Clone)]
pub struct ExtractionConfig {
    /// Minimum string length in bytes (default: 4)
    pub min_length: usize,
    /// Maximum string length in bytes (default: 4096)
    pub max_length: usize,
    /// Whether to scan executable sections (default: true)
    pub scan_code_sections: bool,
    /// Whether to include debug sections (default: false)
    pub include_debug: bool,
    /// Section types to prioritize (default: StringData, ReadOnlyData, Resources)
    pub section_priority: Vec<SectionType>,
    /// Whether to include import/export names (default: true)
    pub include_symbols: bool,
    /// Minimum length for ASCII strings (default: 4, same as min_length)
    pub min_ascii_length: usize,
    /// Minimum length for UTF-16 strings (default: 3, for future use)
    pub min_wide_length: usize,
    /// Which encodings to extract (default: ASCII, UTF-8)
    pub enabled_encodings: Vec<Encoding>,
    /// Enable/disable noise filtering (default: true)
    pub noise_filtering_enabled: bool,
    /// Minimum confidence threshold to include string (default: 0.5)
    ///
    /// Strings with confidence below this threshold will be filtered out.
    pub min_confidence_threshold: f32,
    /// Minimum confidence threshold for UTF-16LE strings (default: 0.7)
    ///
    /// UTF-16LE strings with confidence below this threshold will be filtered out.
    pub utf16_min_confidence: f32,
    /// Which UTF-16 byte order(s) to scan (default: Auto)
    pub utf16_byte_order: ByteOrder,
    /// Minimum UTF-16-specific confidence threshold (default: 0.5)
    ///
    /// UTF-16 strings with UTF-16-specific confidence below this threshold will be filtered out.
    pub utf16_confidence_threshold: f32,
    /// Enable/disable deduplication (default: true)
    ///
    /// When enabled, strings are grouped by (text, encoding) and all occurrence metadata is preserved.
    pub enable_deduplication: bool,
    /// Deduplication threshold - only deduplicate strings appearing N+ times (default: None)
    ///
    /// If set, only strings appearing at least this many times will be deduplicated.
    /// Other strings will be passed through unchanged.
    pub dedup_threshold: Option<usize>,
}

impl Default for ExtractionConfig {
    fn default() -> Self {
        Self {
            min_length: 4,
            max_length: 4096,
            scan_code_sections: true,
            include_debug: false,
            section_priority: vec![
                SectionType::StringData,
                SectionType::ReadOnlyData,
                SectionType::Resources,
            ],
            include_symbols: true,
            min_ascii_length: 4,
            min_wide_length: 3,
            enabled_encodings: vec![Encoding::Ascii, Encoding::Utf8],
            noise_filtering_enabled: true,
            min_confidence_threshold: 0.5,
            utf16_min_confidence: 0.7,
            utf16_byte_order: ByteOrder::Auto,
            utf16_confidence_threshold: 0.5,
            enable_deduplication: true,
            dedup_threshold: None,
        }
    }
}

impl ExtractionConfig {
    /// Validate the configuration
    ///
    /// Returns an error if any thresholds are invalid.
    pub fn validate(&self) -> Result<()> {
        if self.min_length == 0 {
            return Err(StringyError::ConfigError(
                "min_length must be greater than 0".to_string(),
            ));
        }
        if self.min_ascii_length == 0 {
            return Err(StringyError::ConfigError(
                "min_ascii_length must be greater than 0".to_string(),
            ));
        }
        if self.min_wide_length == 0 {
            return Err(StringyError::ConfigError(
                "min_wide_length must be greater than 0".to_string(),
            ));
        }
        if self.max_length == 0 {
            return Err(StringyError::ConfigError(
                "max_length must be greater than 0".to_string(),
            ));
        }
        if self.max_length < self.min_length {
            return Err(StringyError::ConfigError(format!(
                "max_length ({}) must be >= min_length ({})",
                self.max_length, self.min_length
            )));
        }
        if self.max_length < self.min_ascii_length {
            return Err(StringyError::ConfigError(format!(
                "max_length ({}) must be >= min_ascii_length ({})",
                self.max_length, self.min_ascii_length
            )));
        }
        if self.max_length < self.min_wide_length {
            return Err(StringyError::ConfigError(format!(
                "max_length ({}) must be >= min_wide_length ({})",
                self.max_length, self.min_wide_length
            )));
        }
        if !(0.0..=1.0).contains(&self.min_confidence_threshold) {
            return Err(StringyError::ConfigError(
                "min_confidence_threshold must be between 0.0 and 1.0".to_string(),
            ));
        }
        if !(0.0..=1.0).contains(&self.utf16_min_confidence) {
            return Err(StringyError::ConfigError(
                "utf16_min_confidence must be between 0.0 and 1.0".to_string(),
            ));
        }
        if !(0.0..=1.0).contains(&self.utf16_confidence_threshold) {
            return Err(StringyError::ConfigError(
                "utf16_confidence_threshold must be between 0.0 and 1.0".to_string(),
            ));
        }
        Ok(())
    }
}

/// Trait for extracting strings from binary data
///
/// Implementations of this trait provide different strategies for extracting
/// strings from binary files, ranging from simple sequential scanning to
/// format-specific extraction algorithms.
///
/// # Example
///
/// ```rust,no_run
/// use stringy::extraction::{BasicExtractor, ExtractionConfig, StringExtractor};
/// use stringy::container::{detect_format, create_parser};
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let data = std::fs::read("binary_file")?;
///     let format = detect_format(&data);
///     let parser = create_parser(format)?;
///     let container_info = parser.parse(&data)?;
///
///     let extractor = BasicExtractor::new();
///     let config = ExtractionConfig::default();
///     let strings = extractor.extract(&data, &container_info, &config)?;
///     Ok(())
/// }
/// ```
pub trait StringExtractor {
    /// Extract strings from entire binary using container metadata
    ///
    /// This method iterates through all sections in the container and extracts
    /// strings from each section based on the provided configuration.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw binary data
    /// * `container_info` - Container metadata including sections
    /// * `config` - Extraction configuration
    ///
    /// # Returns
    ///
    /// Vector of found strings with metadata. When deduplication is enabled,
    /// this returns deduplicated strings but loses occurrence metadata.
    /// Use `extract_canonical()` to preserve full occurrence information.
    fn extract(
        &self,
        data: &[u8],
        container_info: &ContainerInfo,
        config: &ExtractionConfig,
    ) -> Result<Vec<FoundString>>;

    /// Extract strings from a specific section
    ///
    /// This method extracts strings from a single section, useful for targeted
    /// extraction or when working with individual sections.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw binary data
    /// * `section` - Section metadata
    /// * `config` - Extraction configuration
    ///
    /// # Returns
    ///
    /// Vector of found strings from the section
    fn extract_from_section(
        &self,
        data: &[u8],
        section: &SectionInfo,
        config: &ExtractionConfig,
    ) -> Result<Vec<FoundString>>;

    /// Extract strings and return canonical strings with full occurrence metadata
    ///
    /// Similar to `extract()`, but returns `CanonicalString` entries that preserve
    /// all occurrence metadata when deduplication is enabled. This allows consumers
    /// to see all offsets, sections, and sources where each string appears.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw binary data
    /// * `container_info` - Container metadata including sections
    /// * `config` - Extraction configuration
    ///
    /// # Returns
    ///
    /// Vector of canonical strings with full occurrence metadata. If deduplication
    /// is disabled, each string will have a single occurrence.
    fn extract_canonical(
        &self,
        data: &[u8],
        container_info: &ContainerInfo,
        config: &ExtractionConfig,
    ) -> Result<Vec<CanonicalString>>;
}

/// Basic sequential string extractor
///
/// Implements a simple sequential scanning algorithm for extracting ASCII and
/// UTF-8 strings from binary data. This extractor scans byte sequences looking
/// for printable characters and validates UTF-8 encoding.
///
/// # Example
///
/// ```rust
/// use stringy::extraction::{BasicExtractor, ExtractionConfig, StringExtractor};
/// use stringy::types::{ContainerInfo, SectionInfo, SectionType, BinaryFormat};
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let extractor = BasicExtractor::new();
///     let config = ExtractionConfig::default();
///
///     // Create a simple container info for testing
///     let section = SectionInfo {
///         name: ".rodata".to_string(),
///         offset: 0,
///         size: 100,
///         rva: Some(0x1000),
///         section_type: SectionType::StringData,
///         is_executable: false,
///         is_writable: false,
///         weight: 1.0,
///     };
///
///     let container_info = ContainerInfo::new(
///         BinaryFormat::Elf,
///         vec![section],
///         vec![],
///         vec![],
///         None,
///     );
///
///     let data = b"Hello World\0Test String\0";
///     let strings = extractor.extract(data, &container_info, &config)?;
///     Ok(())
/// }
/// ```
#[derive(Debug, Clone)]
pub struct BasicExtractor;

impl BasicExtractor {
    /// Create a new BasicExtractor instance
    pub fn new() -> Self {
        Self
    }
}

impl Default for BasicExtractor {
    fn default() -> Self {
        Self::new()
    }
}
