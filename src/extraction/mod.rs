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

pub mod ascii;
mod basic_extractor;
pub mod config;
pub mod dedup;
pub mod filters;
mod helpers;
pub mod macho_load_commands;
pub mod pe_resources;
pub mod traits;
pub mod utf16;
pub mod util;

pub use ascii::{AsciiExtractionConfig, extract_ascii_strings, extract_from_section};
pub use config::{FilterWeights, NoiseFilterConfig};
pub use dedup::{CanonicalString, StringOccurrence, deduplicate, found_string_to_occurrence};
pub use filters::{CompositeNoiseFilter, FilterContext, NoiseFilter};
pub use macho_load_commands::extract_load_command_strings;
pub use pe_resources::{extract_resource_strings, extract_resources};
pub use traits::{BasicExtractor, ExtractionConfig, StringExtractor};
pub use utf16::{
    ByteOrder, Utf16ExtractionConfig, extract_from_section as extract_utf16_from_section,
    extract_utf16_strings,
};

#[cfg(test)]
mod tests;
