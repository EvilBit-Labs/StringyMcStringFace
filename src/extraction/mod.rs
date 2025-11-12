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
//! use stringy::extraction::{extract_resources, extract_resource_strings, extract_load_command_strings};
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
//! ```

use crate::types::{
    ContainerInfo, Encoding, FoundString, Result, SectionInfo, SectionType, StringSource,
};

pub mod macho_load_commands;
pub mod pe_resources;

pub use macho_load_commands::extract_load_command_strings;
pub use pe_resources::{extract_resource_strings, extract_resources};

/// Configuration for string extraction
///
/// Controls various aspects of the extraction process including minimum/maximum
/// string lengths, encoding selection, and section filtering.
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
        }
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
    /// Vector of found strings with metadata
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
                    encoding: Encoding::Utf8,
                    offset: 0,
                    rva: None,
                    section: None,
                    length,
                    tags: Vec::new(),
                    score: 0,
                    source: StringSource::ImportName,
                });
            }

            // Add export names
            for export in &container_info.exports {
                let length = export.name.len() as u32;
                all_strings.push(FoundString {
                    text: export.name.clone(),
                    encoding: Encoding::Utf8,
                    offset: 0,
                    rva: None,
                    section: None,
                    length,
                    tags: Vec::new(),
                    score: 0,
                    source: StringSource::ExportName,
                });
            }
        }

        Ok(all_strings)
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

        // Extract strings from section data (filtering by min/max length in helper)
        let raw_strings =
            extract_ascii_utf8_strings(section_data, config.min_length, config.max_length);

        let mut found_strings = Vec::new();

        for (text, relative_offset, length) in raw_strings {
            // Determine encoding
            let encoding = if text.is_ascii() {
                Encoding::Ascii
            } else {
                Encoding::Utf8
            };

            // Filter by configured encodings
            if !config.encodings.contains(&encoding) {
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
                encoding,
                offset: absolute_offset,
                rva,
                section: Some(section.name.clone()),
                length: length as u32,
                tags: Vec::new(),
                score: 0,
                source: StringSource::SectionData,
            };

            found_strings.push(found_string);
        }

        Ok(found_strings)
    }
}

/// Check if a byte is printable ASCII or common whitespace
///
/// Printable ASCII includes characters from 0x20 (space) to 0x7E (~),
/// plus common whitespace characters: tab (0x09), newline (0x0A), and
/// carriage return (0x0D).
fn is_printable_ascii(byte: u8) -> bool {
    matches!(byte, 0x09 | 0x0A | 0x0D | 0x20..=0x7E)
}

/// Check if a byte could be part of a valid UTF-8 sequence
///
/// This includes printable ASCII, UTF-8 continuation bytes (0x80-0xBF),
/// and UTF-8 start bytes (0xC2-0xF4 for valid UTF-8 sequences).
fn could_be_utf8_byte(byte: u8) -> bool {
    is_printable_ascii(byte) || matches!(byte, 0x80..=0xBF | 0xC2..=0xF4)
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
    fn test_is_printable_ascii() {
        // Printable ASCII
        assert!(is_printable_ascii(b' '));
        assert!(is_printable_ascii(b'A'));
        assert!(is_printable_ascii(b'z'));
        assert!(is_printable_ascii(b'0'));
        assert!(is_printable_ascii(b'9'));
        assert!(is_printable_ascii(b'~'));

        // Common whitespace
        assert!(is_printable_ascii(b'\t'));
        assert!(is_printable_ascii(b'\n'));
        assert!(is_printable_ascii(b'\r'));

        // Non-printable
        assert!(!is_printable_ascii(0x00));
        assert!(!is_printable_ascii(0x1F));
        assert!(!is_printable_ascii(0x7F));
        assert!(!is_printable_ascii(0xFF));
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

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].text, "Hello 世界");
        assert_eq!(strings[0].encoding, Encoding::Utf8);
    }

    #[test]
    fn test_basic_extractor_encoding_filtering() {
        let extractor = BasicExtractor::new();
        // Only allow ASCII, exclude UTF-8
        let config = ExtractionConfig {
            encodings: vec![Encoding::Ascii],
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
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].text, "Hello");
        assert_eq!(strings[0].encoding, Encoding::Ascii);
        assert_eq!(strings[1].text, "Test");
        assert_eq!(strings[1].encoding, Encoding::Ascii);
        // UTF-8 string "世界" should be filtered out
        assert!(!strings.iter().any(|s| s.text.contains("世界")));
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
