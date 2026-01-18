//! String extraction logic
//!
//! This module contains string extraction algorithms and format-specific extractors.
//! Each extractor is designed to work with a specific binary format and leverage
//! format-specific knowledge to extract meaningful strings.
//!
//! ## Core String Extraction Framework
//!
//! The core extraction framework provides a trait-based architecture for extracting
//! strings from binary data:
//!
//! - `StringExtractor`: Trait defining extraction methods
//! - `ExtractionConfig`: Configuration for controlling extraction behavior
//! - `BasicExtractor`: Sequential ASCII/UTF-8 string scanner implementation
//!
//! **Note**: These types (`StringExtractor`, `ExtractionConfig`, `BasicExtractor`) are
//! defined locally in this module and should not be imported within `extraction/mod.rs`.
//! Downstream code should import them from `stringy::extraction` or `stringy` (via re-exports).
//!
//! ## PE Resource String Extraction (Phase 2 Complete)
//!
//! The PE resource extraction module now provides comprehensive string extraction:
//!
//! - `extract_resources()`: Returns resource metadata (Phase 1)
//! - `extract_resource_strings()`: Returns actual strings from resources (Phase 2)
//!
//! ## ASCII String Extraction
//!
//! The ASCII extraction module provides foundational encoding extraction for Stringy.
//! It implements byte-level scanning for contiguous printable ASCII sequences and serves as the
//! reference implementation for UTF-8, UTF-16LE, and UTF-16BE extractors.
//!
//! - `extract_ascii_strings()`: Basic byte-level ASCII string scanning
//! - `extract_from_section()`: Section-aware extraction with proper metadata population
//! - `AsciiExtractionConfig`: Configuration for minimum/maximum length filtering
//!
//! ## UTF-16LE String Extraction
//!
//! The UTF-16LE extraction module provides UTF-16LE string extraction with confidence scoring
//! and noise filtering. It implements byte-level scanning for contiguous UTF-16LE character
//! sequences, following the pattern established in the ASCII extractor.
//!
//! - `extract_utf16_strings()`: Basic byte-level UTF-16 string scanning
//! - `extract_from_section()`: Section-aware extraction with proper metadata population
//! - `Utf16ExtractionConfig`: Configuration for minimum/maximum character count and confidence thresholds
//!
//! ## String Deduplication
//!
//! The deduplication module provides functionality to group duplicate strings while preserving
//! complete metadata about all occurrences. Strings are grouped by (text, encoding) keys, ensuring
//! UTF-8 and UTF-16 versions are kept separate.
//!
//! - `deduplicate()`: Groups strings by (text, encoding) and creates `CanonicalString` entries
//! - `CanonicalString`: Represents a deduplicated string with all occurrence metadata
//! - `StringOccurrence`: Preserves location and context for each string instance
//!
//! The deduplication process:
//! - Groups strings by (text, encoding) tuple
//! - Preserves all occurrence metadata (offset, RVA, section, source, tags, score, confidence)
//! - Merges tags using set union semantics
//! - Calculates combined scores with occurrence-based bonuses
//! - Sorts results by combined_score descending
//!
//! # ASCII Extraction Example
//!
//! ```rust
//! use stringy::extraction::ascii::{extract_ascii_strings, AsciiExtractionConfig};
//!
//! let data = b"Hello\0World\0Test123";
//! let config = AsciiExtractionConfig::default();
//! let strings = extract_ascii_strings(data, &config);
//!
//! for string in strings {
//!     println!("Found: {} at offset {}", string.text, string.offset);
//! }
//! ```
//!
//! ## Mach-O Load Command String Extraction
//!
//! The Mach-O load command extraction module extracts library dependencies and runtime
//! search paths from Mach-O binaries:
//!
//! - `extract_load_command_strings()`: Extracts library paths (LC_LOAD_DYLIB) and
//!   runtime search paths (LC_RPATH) from Mach-O load commands
//!
//! # Example
//!
//! ```rust
//! use stringy::extraction::{BasicExtractor, ExtractionConfig, StringExtractor};
//! use stringy::container::{detect_format, create_parser};
//!
//! # fn example() -> stringy::Result<()> {
//! let data = std::fs::read("example.exe")?;
//! let format = detect_format(&data);
//! let parser = create_parser(format)?;
//! let container_info = parser.parse(&data)?;
//!
//! let extractor = BasicExtractor::new();
//! let config = ExtractionConfig::default();
//! let strings = extractor.extract(&data, &container_info, &config)?;
//!
//! // Format-specific extractors
//! use stringy::extraction::{
//!     extract_ascii_strings, extract_utf16_strings, extract_load_command_strings, extract_resources,
//!     extract_resource_strings, AsciiExtractionConfig, Utf16ExtractionConfig,
//! };
//!
//! // ASCII extraction
//! let ascii_config = AsciiExtractionConfig::default();
//! let ascii_strings = extract_ascii_strings(&data, &ascii_config);
//!
//! // UTF-16 extraction
//! let utf16_config = Utf16ExtractionConfig::default();
//! let utf16_strings = extract_utf16_strings(&data, &utf16_config);
//!
//! // Phase 1: Get resource metadata
//! let metadata = extract_resources(&data);
//!
//! // Phase 2: Extract actual strings from resources
//! let resource_strings = extract_resource_strings(&data);
//!
//! // Mach-O load command extraction
//! let macho_data = std::fs::read("example.dylib")?;
//! let load_command_strings = extract_load_command_strings(&macho_data);
//! # Ok(())
//! # }
//! ```

use crate::classification::{SemanticClassifier, SymbolDemangler};
use crate::types::{
    ContainerInfo, Encoding, FoundString, Result, SectionInfo, SectionType, StringSource,
};

pub mod ascii;
pub mod config;
pub mod dedup;
pub mod filters;
pub mod macho_load_commands;
pub mod pe_resources;
pub mod utf16;
pub mod util;

pub use ascii::{AsciiExtractionConfig, extract_ascii_strings, extract_from_section};
pub use config::{FilterWeights, NoiseFilterConfig};
pub use dedup::{CanonicalString, StringOccurrence, deduplicate, found_string_to_occurrence};
pub use filters::{CompositeNoiseFilter, FilterContext, NoiseFilter};
pub use macho_load_commands::extract_load_command_strings;
pub use pe_resources::{extract_resource_strings, extract_resources};
pub use utf16::{
    ByteOrder, Utf16ExtractionConfig, extract_from_section as extract_utf16_from_section,
    extract_utf16_strings,
};

fn apply_semantic_enrichment(strings: &mut [FoundString]) {
    let classifier = SemanticClassifier::new();
    let demangler = SymbolDemangler::new();
    for string in strings {
        demangler.demangle(string);
        let tags = classifier.classify(string);
        for tag in tags {
            if !string.tags.contains(&tag) {
                string.tags.push(tag);
            }
        }
    }
}

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
    /// Encodings to search for (default: ASCII, UTF-8)
    pub encodings: Vec<Encoding>,
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
    /// Whether to preserve all occurrence metadata (default: true)
    ///
    /// When true, full occurrence lists are kept. When false, only occurrence count is preserved.
    pub preserve_all_occurrences: bool,
}

impl Default for ExtractionConfig {
    fn default() -> Self {
        Self {
            min_length: 4,
            max_length: 4096,
            encodings: vec![Encoding::Ascii, Encoding::Utf8],
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
            preserve_all_occurrences: true,
        }
    }
}

impl ExtractionConfig {
    /// Validate the configuration
    ///
    /// Returns an error if any thresholds are invalid.
    pub fn validate(&self) -> Result<()> {
        if self.min_length == 0 {
            return Err(crate::types::StringyError::ConfigError(
                "min_length must be greater than 0".to_string(),
            ));
        }
        if self.min_ascii_length == 0 {
            return Err(crate::types::StringyError::ConfigError(
                "min_ascii_length must be greater than 0".to_string(),
            ));
        }
        if self.min_wide_length == 0 {
            return Err(crate::types::StringyError::ConfigError(
                "min_wide_length must be greater than 0".to_string(),
            ));
        }
        if !(0.0..=1.0).contains(&self.min_confidence_threshold) {
            return Err(crate::types::StringyError::ConfigError(
                "min_confidence_threshold must be between 0.0 and 1.0".to_string(),
            ));
        }
        if !(0.0..=1.0).contains(&self.utf16_min_confidence) {
            return Err(crate::types::StringyError::ConfigError(
                "utf16_min_confidence must be between 0.0 and 1.0".to_string(),
            ));
        }
        if !(0.0..=1.0).contains(&self.utf16_confidence_threshold) {
            return Err(crate::types::StringyError::ConfigError(
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
/// ```rust
/// use stringy::extraction::{BasicExtractor, ExtractionConfig, StringExtractor};
/// use stringy::container::{detect_format, create_parser};
///
/// let data = std::fs::read("binary_file")?;
/// let format = detect_format(&data);
/// let parser = create_parser(format)?;
/// let container_info = parser.parse(&data)?;
///
/// let extractor = BasicExtractor::new();
/// let config = ExtractionConfig::default();
/// let strings = extractor.extract(&data, &container_info, &config)?;
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
/// let extractor = BasicExtractor::new();
/// let config = ExtractionConfig::default();
///
/// // Create a simple container info for testing
/// let section = SectionInfo {
///     name: ".rodata".to_string(),
///     offset: 0,
///     size: 100,
///     rva: Some(0x1000),
///     section_type: SectionType::StringData,
///     is_executable: false,
///     is_writable: false,
///     weight: 1.0,
/// };
///
/// let container_info = ContainerInfo::new(
///     BinaryFormat::Elf,
///     vec![section],
///     vec![],
///     vec![],
///     None,
/// );
///
/// let data = b"Hello World\0Test String\0";
/// let strings = extractor.extract(data, &container_info, &config)?;
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

impl StringExtractor for BasicExtractor {
    fn extract(
        &self,
        data: &[u8],
        container_info: &ContainerInfo,
        config: &ExtractionConfig,
    ) -> Result<Vec<FoundString>> {
        let mut all_strings = Vec::new();

        // Sort sections by priority from config.section_priority
        let mut sections: Vec<_> = container_info.sections.iter().collect();
        sections.sort_by_key(|section| {
            config
                .section_priority
                .iter()
                .position(|&st| st == section.section_type)
                .unwrap_or_else(|| {
                    // Fallback to section weight (higher weight = higher priority)
                    // Convert weight to usize for consistent key type
                    // Use a large offset to ensure fallback sections sort after prioritized ones
                    let weight_int = (section.weight * 1000.0) as usize;
                    config.section_priority.len() + (10000 - weight_int.min(10000))
                })
        });

        for section in sections {
            // Filter sections based on config
            if section.section_type == SectionType::Debug && !config.include_debug {
                continue;
            }

            // Filter code sections by both type and executable flag
            if (section.section_type == SectionType::Code || section.is_executable)
                && !config.scan_code_sections
            {
                continue;
            }

            // Extract strings from this section
            let section_strings = self.extract_from_section(data, section, config)?;
            all_strings.extend(section_strings);
        }

        // Include import/export symbols if configured
        if config.include_symbols {
            // Add import names
            for import in &container_info.imports {
                let length = import.name.len() as u32;
                all_strings.push(FoundString {
                    text: import.name.clone(),
                    original_text: None,
                    encoding: Encoding::Utf8,
                    offset: 0,
                    rva: None,
                    section: None,
                    length,
                    tags: Vec::new(),
                    score: 0,
                    section_weight: None,
                    semantic_boost: None,
                    noise_penalty: None,
                    source: StringSource::ImportName,
                    confidence: 1.0,
                });
            }

            // Add export names
            for export in &container_info.exports {
                let length = export.name.len() as u32;
                all_strings.push(FoundString {
                    text: export.name.clone(),
                    original_text: None,
                    encoding: Encoding::Utf8,
                    offset: 0,
                    rva: None,
                    section: None,
                    length,
                    tags: Vec::new(),
                    score: 0,
                    section_weight: None,
                    semantic_boost: None,
                    noise_penalty: None,
                    source: StringSource::ExportName,
                    confidence: 1.0,
                });
            }
        }

        // Apply demangling and semantic classification before deduplication
        apply_semantic_enrichment(&mut all_strings);

        // Apply deduplication if enabled
        if config.enable_deduplication {
            let canonical_strings = deduplicate(
                all_strings,
                config.dedup_threshold,
                config.preserve_all_occurrences,
            );
            // Convert canonical strings back to FoundString for backward compatibility
            Ok(canonical_strings
                .into_iter()
                .map(|cs| cs.to_found_string())
                .collect())
        } else {
            Ok(all_strings)
        }
    }

    fn extract_canonical(
        &self,
        data: &[u8],
        container_info: &ContainerInfo,
        config: &ExtractionConfig,
    ) -> Result<Vec<CanonicalString>> {
        let mut all_strings = Vec::new();

        // Sort sections by priority from config.section_priority
        let mut sections: Vec<_> = container_info.sections.iter().collect();
        sections.sort_by_key(|section| {
            config
                .section_priority
                .iter()
                .position(|&st| st == section.section_type)
                .unwrap_or_else(|| {
                    // Fallback to section weight (higher weight = higher priority)
                    // Convert weight to usize for consistent key type
                    // Use a large offset to ensure fallback sections sort after prioritized ones
                    let weight_int = (section.weight * 1000.0) as usize;
                    config.section_priority.len() + (10000 - weight_int.min(10000))
                })
        });

        for section in sections {
            // Filter sections based on config
            if section.section_type == SectionType::Debug && !config.include_debug {
                continue;
            }

            // Filter code sections by both type and executable flag
            if (section.section_type == SectionType::Code || section.is_executable)
                && !config.scan_code_sections
            {
                continue;
            }

            // Extract strings from this section
            let section_strings = self.extract_from_section(data, section, config)?;
            all_strings.extend(section_strings);
        }

        // Include import/export symbols if configured
        if config.include_symbols {
            // Add import names
            for import in &container_info.imports {
                let length = import.name.len() as u32;
                all_strings.push(FoundString {
                    text: import.name.clone(),
                    original_text: None,
                    encoding: Encoding::Utf8,
                    offset: 0,
                    rva: None,
                    section: None,
                    length,
                    tags: Vec::new(),
                    score: 0,
                    section_weight: None,
                    semantic_boost: None,
                    noise_penalty: None,
                    source: StringSource::ImportName,
                    confidence: 1.0,
                });
            }

            // Add export names
            for export in &container_info.exports {
                let length = export.name.len() as u32;
                all_strings.push(FoundString {
                    text: export.name.clone(),
                    original_text: None,
                    encoding: Encoding::Utf8,
                    offset: 0,
                    rva: None,
                    section: None,
                    length,
                    tags: Vec::new(),
                    score: 0,
                    section_weight: None,
                    semantic_boost: None,
                    noise_penalty: None,
                    source: StringSource::ExportName,
                    confidence: 1.0,
                });
            }
        }

        // Apply demangling and semantic classification before deduplication
        apply_semantic_enrichment(&mut all_strings);

        // Apply deduplication if enabled, otherwise convert each string to a canonical form
        if config.enable_deduplication {
            Ok(deduplicate(
                all_strings,
                config.dedup_threshold,
                config.preserve_all_occurrences,
            ))
        } else {
            // Convert each FoundString to a CanonicalString with a single occurrence
            Ok(all_strings
                .into_iter()
                .map(|fs| {
                    let occurrence = found_string_to_occurrence(fs.clone());
                    CanonicalString {
                        text: fs.text,
                        encoding: fs.encoding,
                        occurrences: vec![occurrence],
                        merged_tags: fs.tags,
                        combined_score: fs.score,
                    }
                })
                .collect())
        }
    }

    fn extract_from_section(
        &self,
        data: &[u8],
        section: &SectionInfo,
        config: &ExtractionConfig,
    ) -> Result<Vec<FoundString>> {
        // Early return for zero-sized sections
        if section.size == 0 {
            return Ok(Vec::new());
        }

        // Validate section bounds
        let section_offset = section.offset as usize;
        let section_size = section.size as usize;

        if section_offset >= data.len() {
            return Ok(Vec::new());
        }

        let end_offset = section_offset
            .checked_add(section_size)
            .unwrap_or(data.len())
            .min(data.len());

        let section_data = &data[section_offset..end_offset];

        // Build noise filter config from extraction config
        let noise_filter_config = if config.noise_filtering_enabled {
            Some(crate::extraction::config::NoiseFilterConfig::default())
        } else {
            None
        };

        // Extract ASCII strings only if ASCII encoding is enabled
        // Check both encodings and enabled_encodings fields
        let ascii_enabled = config.encodings.contains(&Encoding::Ascii)
            || config.enabled_encodings.contains(&Encoding::Ascii);

        let mut found_strings = Vec::new();

        if ascii_enabled {
            // Use ASCII extractor for ASCII strings
            let ascii_config = ascii::AsciiExtractionConfig {
                min_length: config.min_ascii_length.max(config.min_length),
                max_length: Some(config.max_length),
            };

            // Extract ASCII strings using the dedicated ASCII extractor with filtering
            found_strings = ascii::extract_from_section(
                section,
                data,
                &ascii_config,
                noise_filter_config.as_ref(),
                config.noise_filtering_enabled,
                config.min_confidence_threshold,
            );
        }

        // For UTF-8 strings, use the existing helper (only if UTF-8 is enabled)
        // Check both encodings and enabled_encodings fields
        let utf8_enabled = config.encodings.contains(&Encoding::Utf8)
            || config.enabled_encodings.contains(&Encoding::Utf8);
        if utf8_enabled {
            let raw_strings =
                extract_ascii_utf8_strings(section_data, config.min_length, config.max_length);

            // Build filter context for UTF-8 strings
            let filter_context = crate::extraction::filters::FilterContext::from_section(section);
            let filter = if config.noise_filtering_enabled {
                noise_filter_config
                    .as_ref()
                    .map(crate::extraction::filters::CompositeNoiseFilter::new)
            } else {
                None
            };

            for (text, relative_offset, length) in raw_strings {
                // Skip if already extracted as ASCII (only if ASCII extraction is enabled)
                if ascii_enabled && text.is_ascii() {
                    continue;
                }

                // Determine encoding
                let encoding = Encoding::Utf8;

                // Filter by configured encodings (check both fields)
                let encoding_allowed = config.encodings.contains(&encoding)
                    || config.enabled_encodings.contains(&encoding);
                if !encoding_allowed {
                    continue;
                }

                // Compute confidence if filtering is enabled
                let confidence = if let Some(ref noise_filter) = filter {
                    noise_filter.calculate_confidence(&text, &filter_context)
                } else {
                    1.0
                };

                // Apply threshold filtering
                if config.noise_filtering_enabled && confidence < config.min_confidence_threshold {
                    continue;
                }

                // Calculate absolute offset
                let absolute_offset = section.offset + relative_offset as u64;

                // Calculate RVA if available
                let rva = section
                    .rva
                    .map(|base_rva| base_rva + relative_offset as u64);

                let found_string = FoundString {
                    text,
                    original_text: None,
                    encoding,
                    offset: absolute_offset,
                    rva,
                    section: Some(section.name.clone()),
                    length: length as u32,
                    tags: Vec::new(),
                    score: 0,
                    section_weight: None,
                    semantic_boost: None,
                    noise_penalty: None,
                    source: StringSource::SectionData,
                    confidence,
                };

                found_strings.push(found_string);
            }
        }

        // For UTF-16 strings, use the UTF-16 extractor (only if UTF-16LE or UTF-16BE is enabled)
        // Check both encodings and enabled_encodings fields
        let utf16le_enabled = config.encodings.contains(&Encoding::Utf16Le)
            || config.enabled_encodings.contains(&Encoding::Utf16Le);
        let utf16be_enabled = config.encodings.contains(&Encoding::Utf16Be)
            || config.enabled_encodings.contains(&Encoding::Utf16Be);

        if utf16le_enabled || utf16be_enabled {
            // Determine which byte order(s) to scan based on enabled encodings and config
            let byte_order = if utf16le_enabled && utf16be_enabled {
                // Both enabled - use config setting (usually Auto)
                config.utf16_byte_order
            } else if utf16le_enabled {
                ByteOrder::LE
            } else {
                ByteOrder::BE
            };

            // Create UTF-16 extraction config
            // Convert max_length from bytes to UTF-16 character count (divide by 2)
            let utf16_max_chars = if config.max_length < 2 {
                Some(0)
            } else {
                Some(config.max_length / 2)
            };
            let utf16_config = utf16::Utf16ExtractionConfig {
                min_length: config.min_wide_length,
                max_length: utf16_max_chars,
                byte_order,
                confidence_threshold: config.utf16_confidence_threshold,
                scan_both_alignments: false, // Default to false to avoid performance degradation
            };

            // Extract UTF-16 strings using the dedicated UTF-16 extractor
            let utf16_strings = utf16::extract_from_section(
                section,
                data,
                &utf16_config,
                noise_filter_config.as_ref(),
                config.noise_filtering_enabled,
                config.utf16_min_confidence,
            );

            found_strings.extend(utf16_strings);
        }

        Ok(found_strings)
    }
}

/// Check if a byte is printable text (ASCII or common whitespace)
///
/// Printable text includes characters from 0x20 (space) to 0x7E (~),
/// plus common whitespace characters: tab (0x09), newline (0x0A), and
/// carriage return (0x0D).
///
/// **Note on printable character definitions**: This function is used by the UTF-8-capable
/// extraction helpers and includes common whitespace characters (tab, newline, carriage return)
/// to handle text files and formatted data. This differs from the ASCII-only `is_printable_ascii`
/// function in `extraction::ascii`, which only considers the strict printable range (0x20-0x7E)
/// without whitespace control characters. This difference ensures that:
/// - ASCII-only extraction (`extraction::ascii`) produces strict, predictable results
/// - UTF-8-capable extraction (this module) can handle formatted text with line breaks
///
/// When using both extractors on the same data, be aware that they may produce different
/// results due to this definitional difference.
fn is_printable_text_byte(byte: u8) -> bool {
    matches!(byte, 0x09 | 0x0A | 0x0D | 0x20..=0x7E)
}

/// Check if a byte could be part of a valid UTF-8 sequence
///
/// This includes printable ASCII, UTF-8 continuation bytes (0x80-0xBF),
/// and UTF-8 start bytes (0xC2-0xF4 for valid UTF-8 sequences).
fn could_be_utf8_byte(byte: u8) -> bool {
    is_printable_text_byte(byte) || matches!(byte, 0x80..=0xBF | 0xC2..=0xF4)
}

/// Extract ASCII and UTF-8 strings from byte data
///
/// Scans through the byte data looking for sequences of printable characters
/// and valid UTF-8 sequences. When a byte that cannot be part of a valid
/// string is encountered, checks if the accumulated sequence meets the minimum
/// length requirement and validates it as UTF-8. Strings exceeding max_length
/// are skipped during extraction.
///
/// # Arguments
///
/// * `data` - Byte slice to scan
/// * `min_length` - Minimum string length in bytes
/// * `max_length` - Maximum string length in bytes
///
/// # Returns
///
/// Vector of tuples containing (text, relative_offset, length)
fn extract_ascii_utf8_strings(
    data: &[u8],
    min_length: usize,
    max_length: usize,
) -> Vec<(String, usize, usize)> {
    let mut strings = Vec::new();
    let mut current_string_start: Option<usize> = None;
    let mut current_string_bytes = Vec::new();

    for (i, &byte) in data.iter().enumerate() {
        if could_be_utf8_byte(byte) {
            if current_string_start.is_none() {
                current_string_start = Some(i);
            }
            current_string_bytes.push(byte);
        } else {
            // End of current string candidate
            // Check length conditions first, then extract start to avoid borrow checker issues
            #[allow(clippy::collapsible_if)]
            if current_string_bytes.len() >= min_length && current_string_bytes.len() <= max_length
            {
                if let Some(start) = current_string_start {
                    // Store length before moving
                    let len = current_string_bytes.len();
                    // Move buffer out to avoid cloning
                    let bytes = std::mem::take(&mut current_string_bytes);
                    // Try to convert to UTF-8 string
                    match String::from_utf8(bytes) {
                        Ok(text) => {
                            // Create entry tuple to move text into it explicitly
                            let entry = (text, start, len);
                            strings.push(entry);
                        }
                        Err(_) => {
                            // Invalid UTF-8, skip this candidate
                        }
                    }
                }
            }
            current_string_start = None;
            current_string_bytes.clear();
        }
    }

    // Handle string at end of data
    // Check length conditions first, then extract start to avoid borrow checker issues
    #[allow(clippy::collapsible_if)]
    if current_string_bytes.len() >= min_length && current_string_bytes.len() <= max_length {
        if let Some(start) = current_string_start {
            // Store length before moving
            let len = current_string_bytes.len();
            // Move buffer out to avoid cloning
            let bytes = std::mem::take(&mut current_string_bytes);
            match String::from_utf8(bytes) {
                Ok(text) => {
                    // Create entry tuple to move text into it explicitly
                    let entry = (text, start, len);
                    strings.push(entry);
                }
                Err(_) => {
                    // Invalid UTF-8, skip
                }
            }
        }
    }

    strings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BinaryFormat, ExportInfo, ImportInfo, SectionType};

    #[test]
    fn test_is_printable_text_byte() {
        // Printable ASCII
        assert!(is_printable_text_byte(b' '));
        assert!(is_printable_text_byte(b'A'));
        assert!(is_printable_text_byte(b'z'));
        assert!(is_printable_text_byte(b'0'));
        assert!(is_printable_text_byte(b'9'));
        assert!(is_printable_text_byte(b'~'));

        // Common whitespace
        assert!(is_printable_text_byte(b'\t'));
        assert!(is_printable_text_byte(b'\n'));
        assert!(is_printable_text_byte(b'\r'));

        // Non-printable
        assert!(!is_printable_text_byte(0x00));
        assert!(!is_printable_text_byte(0x1F));
        assert!(!is_printable_text_byte(0x7F));
        assert!(!is_printable_text_byte(0xFF));
    }

    #[test]
    fn test_extract_ascii_utf8_strings() {
        // Test with ASCII strings
        let data = b"Hello\0World\0Test123";
        let strings = extract_ascii_utf8_strings(data, 4, 4096);
        assert_eq!(strings.len(), 3);
        assert_eq!(strings[0].0, "Hello");
        assert_eq!(strings[0].1, 0);
        assert_eq!(strings[1].0, "World");
        assert_eq!(strings[1].1, 6);
        assert_eq!(strings[2].0, "Test123");
        assert_eq!(strings[2].1, 12);
    }

    #[test]
    fn test_extract_ascii_utf8_strings_utf8() {
        // Test with UTF-8 strings
        let data = "Hello 世界\0Test".as_bytes();
        let strings = extract_ascii_utf8_strings(data, 4, 4096);
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].0, "Hello 世界");
        assert_eq!(strings[1].0, "Test");
    }

    #[test]
    fn test_extract_ascii_utf8_strings_min_length() {
        // Test minimum length filtering
        let data = b"Hi\0Test\0AB\0LongString";
        let strings = extract_ascii_utf8_strings(data, 4, 4096);
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].0, "Test");
        assert_eq!(strings[1].0, "LongString");
    }

    #[test]
    fn test_extract_ascii_utf8_strings_empty() {
        // Test with empty data
        let data = b"";
        let strings = extract_ascii_utf8_strings(data, 4, 4096);
        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_ascii_utf8_strings_binary() {
        // Test with binary data
        let data = &[0x00, 0xFF, 0x01, 0x02, 0x03];
        let strings = extract_ascii_utf8_strings(data, 4, 4096);
        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_ascii_utf8_strings_at_boundaries() {
        // Test strings at start and end
        let data = b"Start\0Middle\0EndTest";
        let strings = extract_ascii_utf8_strings(data, 4, 4096);
        assert_eq!(strings.len(), 3);
        assert_eq!(strings[0].0, "Start");
        assert_eq!(strings[0].1, 0);
        assert_eq!(strings[2].0, "EndTest");
    }

    #[test]
    fn test_extract_ascii_utf8_strings_max_length() {
        // Test maximum length filtering in helper
        let data = b"Short\0VeryLongStringHere";
        let strings = extract_ascii_utf8_strings(data, 4, 10);
        // Only "Short" should pass max_length filter
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].0, "Short");
        assert!(!strings.iter().any(|s| s.0 == "VeryLongStringHere"));
    }

    #[test]
    fn test_extraction_config_default() {
        let config = ExtractionConfig::default();
        assert_eq!(config.min_length, 4);
        assert_eq!(config.max_length, 4096);
        assert_eq!(config.encodings.len(), 2);
        assert!(config.encodings.contains(&Encoding::Ascii));
        assert!(config.encodings.contains(&Encoding::Utf8));
        assert!(config.scan_code_sections);
        assert!(!config.include_debug);
        assert_eq!(config.section_priority.len(), 3);
        assert!(config.include_symbols);
    }

    #[test]
    fn test_basic_extractor_extract_from_section() {
        let extractor = BasicExtractor::new();
        let config = ExtractionConfig::default();

        let section = SectionInfo {
            name: ".rodata".to_string(),
            offset: 0,
            size: 20,
            rva: Some(0x1000),
            section_type: SectionType::StringData,
            is_executable: false,
            is_writable: false,
            weight: 1.0,
        };

        let data = b"Hello World\0Test";
        let strings = extractor
            .extract_from_section(data, &section, &config)
            .unwrap();

        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].text, "Hello World");
        assert_eq!(strings[0].offset, 0);
        assert_eq!(strings[0].rva, Some(0x1000));
        assert_eq!(strings[0].section, Some(".rodata".to_string()));
        assert_eq!(strings[0].encoding, Encoding::Ascii);
        assert_eq!(strings[1].text, "Test");
        assert_eq!(strings[1].offset, 12);
        assert_eq!(strings[1].rva, Some(0x100C));
    }

    #[test]
    fn test_basic_extractor_max_length_filtering() {
        let extractor = BasicExtractor::new();
        let config = ExtractionConfig {
            max_length: 10,
            ..Default::default()
        };

        let section = SectionInfo {
            name: ".data".to_string(),
            offset: 0,
            size: 30,
            rva: None,
            section_type: SectionType::WritableData,
            is_executable: false,
            is_writable: true,
            weight: 0.5,
        };

        let data = b"Short\0VeryLongStringHere";
        let strings = extractor
            .extract_from_section(data, &section, &config)
            .unwrap();

        // Only "Short" should pass max_length filter
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].text, "Short");
    }

    #[test]
    fn test_basic_extractor_section_bounds() {
        let extractor = BasicExtractor::new();
        let config = ExtractionConfig::default();

        let section = SectionInfo {
            name: ".text".to_string(),
            offset: 7, // Start after "prefix\0"
            size: 12,  // "Hello World" is 11 bytes + null terminator
            rva: Some(0x2000),
            section_type: SectionType::Code,
            is_executable: true,
            is_writable: false,
            weight: 0.1,
        };

        let data = b"prefix\0Hello World\0suffix";
        let strings = extractor
            .extract_from_section(data, &section, &config)
            .unwrap();

        // Should find "Hello World" in the section
        assert!(!strings.is_empty());
        let hello_world = strings.iter().find(|s| s.text == "Hello World");
        assert!(hello_world.is_some(), "Should find 'Hello World' string");
        if let Some(s) = hello_world {
            assert_eq!(s.offset, 7);
            assert_eq!(s.rva, Some(0x2000));
        }
    }

    #[test]
    fn test_basic_extractor_empty_section() {
        let extractor = BasicExtractor::new();
        let config = ExtractionConfig::default();

        let section = SectionInfo {
            name: ".empty".to_string(),
            offset: 0,
            size: 0,
            rva: None,
            section_type: SectionType::Other,
            is_executable: false,
            is_writable: false,
            weight: 0.0,
        };

        let data = b"";
        let strings = extractor
            .extract_from_section(data, &section, &config)
            .unwrap();

        assert!(strings.is_empty());
    }

    #[test]
    fn test_basic_extractor_section_out_of_bounds() {
        let extractor = BasicExtractor::new();
        let config = ExtractionConfig::default();

        let section = SectionInfo {
            name: ".invalid".to_string(),
            offset: 1000,
            size: 100,
            rva: None,
            section_type: SectionType::Other,
            is_executable: false,
            is_writable: false,
            weight: 0.0,
        };

        let data = b"small data";
        let strings = extractor
            .extract_from_section(data, &section, &config)
            .unwrap();

        assert!(strings.is_empty());
    }

    #[test]
    fn test_basic_extractor_utf8_encoding() {
        let extractor = BasicExtractor::new();
        let config = ExtractionConfig::default();

        let section = SectionInfo {
            name: ".rodata".to_string(),
            offset: 0,
            size: 20,
            rva: None,
            section_type: SectionType::StringData,
            is_executable: false,
            is_writable: false,
            weight: 1.0,
        };

        let data = "Hello 世界".as_bytes();
        let strings = extractor
            .extract_from_section(data, &section, &config)
            .unwrap();

        // Should extract UTF-8 string "Hello 世界"
        // Note: ASCII extractor may also extract "Hello " as a prefix, but UTF-8 extractor
        // will extract the full "Hello 世界" string. We check for the UTF-8 string.
        let utf8_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.encoding == Encoding::Utf8 && s.text == "Hello 世界")
            .collect();
        assert_eq!(
            utf8_strings.len(),
            1,
            "Should find UTF-8 string 'Hello 世界', found {} strings total",
            strings.len()
        );
        assert_eq!(utf8_strings[0].text, "Hello 世界");
        assert_eq!(utf8_strings[0].encoding, Encoding::Utf8);
    }

    #[test]
    fn test_basic_extractor_encoding_filtering() {
        let extractor = BasicExtractor::new();
        // Only allow ASCII, exclude UTF-8
        let config = ExtractionConfig {
            encodings: vec![Encoding::Ascii],
            enabled_encodings: vec![Encoding::Ascii],
            ..Default::default()
        };

        let section = SectionInfo {
            name: ".rodata".to_string(),
            offset: 0,
            size: 30,
            rva: None,
            section_type: SectionType::StringData,
            is_executable: false,
            is_writable: false,
            weight: 1.0,
        };

        let data = "Hello\0世界\0Test".as_bytes();
        let strings = extractor
            .extract_from_section(data, &section, &config)
            .unwrap();

        // Should only find ASCII strings, not UTF-8
        // Note: "Hello" and "Test" are ASCII, "世界" is UTF-8 and should be filtered
        let ascii_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.encoding == Encoding::Ascii)
            .collect();
        assert_eq!(ascii_strings.len(), 2, "Should find 2 ASCII strings");
        assert!(ascii_strings.iter().any(|s| s.text == "Hello"));
        assert!(ascii_strings.iter().any(|s| s.text == "Test"));
        // UTF-8 string "世界" should be filtered out
        assert!(!strings.iter().any(|s| s.text.contains("世界")));
    }

    #[test]
    fn test_basic_extractor_ascii_disabled() {
        let extractor = BasicExtractor::new();
        // Exclude ASCII, only allow UTF-8
        let config = ExtractionConfig {
            encodings: vec![Encoding::Utf8],
            enabled_encodings: vec![Encoding::Utf8],
            ..Default::default()
        };

        let section = SectionInfo {
            name: ".rodata".to_string(),
            offset: 0,
            size: 30,
            rva: None,
            section_type: SectionType::StringData,
            is_executable: false,
            is_writable: false,
            weight: 1.0,
        };

        let data = b"Hello\0World\0Test";
        let strings = extractor
            .extract_from_section(data, &section, &config)
            .unwrap();

        // Should not find ASCII strings when ASCII is disabled
        // Note: "Hello", "World", and "Test" are ASCII-only, so they should be extracted as UTF-8
        // but ASCII extractor should not run
        let ascii_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.encoding == Encoding::Ascii)
            .collect();
        assert_eq!(
            ascii_strings.len(),
            0,
            "Should not find any ASCII strings when ASCII is disabled"
        );

        // UTF-8 extractor may still find these strings since they're valid UTF-8
        let utf8_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.encoding == Encoding::Utf8)
            .collect();
        // UTF-8 extractor should find the strings
        assert!(!utf8_strings.is_empty(), "Should find UTF-8 strings");
    }

    #[test]
    fn test_basic_extractor_include_symbols() {
        let extractor = BasicExtractor::new();
        let config = ExtractionConfig {
            include_symbols: true,
            ..Default::default()
        };

        let section = SectionInfo {
            name: ".text".to_string(),
            offset: 0,
            size: 10,
            rva: None,
            section_type: SectionType::Code,
            is_executable: true,
            is_writable: false,
            weight: 0.1,
        };

        let container_info = ContainerInfo::new(
            BinaryFormat::Elf,
            vec![section],
            vec![
                ImportInfo {
                    name: "printf".to_string(),
                    library: Some("libc.so.6".to_string()),
                    address: Some(0x1000),
                    ordinal: None,
                },
                ImportInfo {
                    name: "malloc".to_string(),
                    library: Some("libc.so.6".to_string()),
                    address: Some(0x2000),
                    ordinal: None,
                },
            ],
            vec![
                ExportInfo {
                    name: "main".to_string(),
                    address: 0x3000,
                    ordinal: None,
                },
                ExportInfo {
                    name: "exported_function".to_string(),
                    address: 0x4000,
                    ordinal: None,
                },
            ],
            None,
        );

        let data = b"test data";
        let strings = extractor.extract(data, &container_info, &config).unwrap();

        // Should include import and export names
        let import_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.source == StringSource::ImportName)
            .collect();
        let export_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.source == StringSource::ExportName)
            .collect();

        assert_eq!(import_strings.len(), 2);
        assert!(import_strings.iter().any(|s| s.text == "printf"));
        assert!(import_strings.iter().any(|s| s.text == "malloc"));

        assert_eq!(export_strings.len(), 2);
        assert!(export_strings.iter().any(|s| s.text == "main"));
        assert!(export_strings.iter().any(|s| s.text == "exported_function"));

        // Verify import string properties
        let printf_str = import_strings.iter().find(|s| s.text == "printf").unwrap();
        assert_eq!(printf_str.encoding, Encoding::Utf8);
        assert_eq!(printf_str.offset, 0);
        assert_eq!(printf_str.rva, None);
        assert_eq!(printf_str.section, None);
        assert_eq!(printf_str.length, 6);

        // Verify export string properties
        let main_str = export_strings.iter().find(|s| s.text == "main").unwrap();
        assert_eq!(main_str.encoding, Encoding::Utf8);
        assert_eq!(main_str.offset, 0);
        assert_eq!(main_str.rva, None);
        assert_eq!(main_str.section, None);
        assert_eq!(main_str.length, 4);
    }

    #[test]
    fn test_basic_extractor_exclude_symbols() {
        let extractor = BasicExtractor::new();
        let config = ExtractionConfig {
            include_symbols: false,
            ..Default::default()
        };

        let section = SectionInfo {
            name: ".text".to_string(),
            offset: 0,
            size: 10,
            rva: None,
            section_type: SectionType::Code,
            is_executable: true,
            is_writable: false,
            weight: 0.1,
        };

        let container_info = ContainerInfo::new(
            BinaryFormat::Elf,
            vec![section],
            vec![ImportInfo {
                name: "printf".to_string(),
                library: Some("libc.so.6".to_string()),
                address: Some(0x1000),
                ordinal: None,
            }],
            vec![ExportInfo {
                name: "main".to_string(),
                address: 0x3000,
                ordinal: None,
            }],
            None,
        );

        let data = b"test data";
        let strings = extractor.extract(data, &container_info, &config).unwrap();

        // Should not include import/export names
        assert!(!strings.iter().any(|s| s.source == StringSource::ImportName));
        assert!(!strings.iter().any(|s| s.source == StringSource::ExportName));
    }

    #[test]
    fn test_basic_extractor_section_filtering() {
        let extractor = BasicExtractor::new();
        let config = ExtractionConfig {
            scan_code_sections: false,
            include_debug: false,
            ..Default::default()
        };

        let code_section = SectionInfo {
            name: ".text".to_string(),
            offset: 0,
            size: 9,
            rva: None,
            section_type: SectionType::Code,
            is_executable: true,
            is_writable: false,
            weight: 0.1,
        };

        let debug_section = SectionInfo {
            name: ".debug_info".to_string(),
            offset: 9,
            size: 10,
            rva: None,
            section_type: SectionType::Debug,
            is_executable: false,
            is_writable: false,
            weight: 0.0,
        };

        let data_section = SectionInfo {
            name: ".rodata".to_string(),
            offset: 19,
            size: 11,
            rva: None,
            section_type: SectionType::StringData,
            is_executable: false,
            is_writable: false,
            weight: 1.0,
        };

        let data = b"CodeData\0DebugData\0RoDataTest";
        let container_info = ContainerInfo::new(
            BinaryFormat::Elf,
            vec![code_section, debug_section, data_section],
            vec![],
            vec![],
            None,
        );

        let strings = extractor.extract(data, &container_info, &config).unwrap();

        // Should only extract from data section, not code or debug
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].text, "RoDataTest");
    }
}
