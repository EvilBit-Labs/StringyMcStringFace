//! Stringy - A smarter alternative to the strings command
//!
//! Stringy leverages format-specific knowledge to distinguish meaningful strings
//! from random garbage data in binary files.
//!
//! ## Current Implementation Status
//!
//! The core infrastructure is complete and robust:
//!
//! - **Binary Format Detection**: Automatic ELF, PE, Mach-O detection via `goblin`
//! - **Container Parsing**: Full section analysis with intelligent classification
//! - **Import/Export Extraction**: Symbol processing from all supported formats
//! - **Section Weighting**: Priority-based scoring for string extraction
//! - **Type Safety**: Comprehensive error handling and data structures
//!
//! ## Basic Usage
//!
//! ```rust
//! use stringy::container::{detect_format, create_parser};
//! use stringy::extraction::{BasicExtractor, ExtractionConfig, StringExtractor};
//!
//! # fn example() -> stringy::Result<()> {
//! let data = std::fs::read("binary_file")?;
//! let format = detect_format(&data);
//! let parser = create_parser(format)?;
//! let container_info = parser.parse(&data)?;
//!
//! println!("Format: {:?}", container_info.format);
//! println!("Sections: {}", container_info.sections.len());
//! println!("Imports: {}", container_info.imports.len());
//!
//! // Extract strings using the basic extractor
//! let extractor = BasicExtractor::new();
//! let config = ExtractionConfig::default();
//! let strings = extractor.extract(&data, &container_info, &config)?;
//! println!("Found {} strings", strings.len());
//!
//! // ASCII string extraction (foundational encoding type)
//! use stringy::extraction::{extract_ascii_strings, AsciiExtractionConfig};
//! let ascii_config = AsciiExtractionConfig::default();
//! let ascii_strings = extract_ascii_strings(&data, &ascii_config);
//! println!("Found {} ASCII strings", ascii_strings.len());
//!
//! // UTF-16LE string extraction (Windows PE binaries)
//! use stringy::extraction::{extract_utf16_strings, Utf16ExtractionConfig};
//! let utf16_config = Utf16ExtractionConfig::default();
//! let utf16_strings = extract_utf16_strings(&data, &utf16_config);
//! println!("Found {} UTF-16 strings", utf16_strings.len());
//! # Ok(())
//! # }
//! ```
//!
//! ## Architecture
//!
//! The library is organized into focused modules:
//!
//! - [`container`]: Binary format detection and parsing (✅ Complete)
//! - [`extraction`]: String extraction algorithms (✅ ASCII, UTF-16LE extraction and PE resources complete)
//!   - ASCII extraction provides foundational encoding extraction as the reference implementation
//!   - UTF-16LE extraction provides Windows PE binary string extraction with confidence scoring
//! - [`classification`]: Semantic analysis and tagging (🚧 Types defined)
//! - [`output`]: Result formatting (🚧 Interfaces ready)
//! - [`types`]: Core data structures and error handling (✅ Complete)
//!
//! ## PE Resource String Extraction
//!
//! - **PE Resource Strings**: VERSIONINFO, STRINGTABLE, and MANIFEST extraction (✅ Complete)

pub mod classification;
pub mod container;
pub mod extraction;
pub mod output;
pub mod types;

// Re-export commonly used types
pub use types::{
    BinaryFormat, ContainerInfo, Encoding, ExportInfo, FoundString, ImportInfo, ResourceMetadata,
    ResourceStringEntry, ResourceStringTable, ResourceType, Result, SectionInfo, SectionType,
    StringSource, StringyError, Tag,
};

// Re-export extraction framework types
pub use extraction::{
    AsciiExtractionConfig, BasicExtractor, CanonicalString, ExtractionConfig, StringExtractor,
    StringOccurrence, Utf16ExtractionConfig, deduplicate,
};

// Re-export output infrastructure types
pub use output::{
    OutputFormat, OutputFormatter, OutputMetadata, format_json, format_output,
    format_table_with_mode, format_yara,
};
