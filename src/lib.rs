#![forbid(unsafe_code)]

//! Stringy - A smarter alternative to the strings command
//!
//! Stringy leverages format-specific knowledge to distinguish meaningful strings
//! from random garbage data in binary files. It is section-aware and semantically
//! intelligent, extracting strings from ELF, PE, and Mach-O binaries with
//! classification, ranking, and multiple output formats.
//!
//! ## Features
//!
//! - **Binary Format Detection**: Automatic ELF, PE, Mach-O detection via `goblin`
//! - **Container Parsing**: Full section analysis with weighted scoring
//! - **String Extraction**: ASCII, UTF-8, UTF-16LE/BE with noise filtering and deduplication
//! - **PE Resources**: VERSIONINFO, STRINGTABLE, and MANIFEST extraction
//! - **Mach-O Load Commands**: Dylib paths, rpaths, framework paths
//! - **Semantic Classification**: URLs, IPs, domains, paths, GUIDs, emails, and more
//! - **Ranking**: Section-weight, semantic-boost, and noise-penalty scoring
//! - **Output Formats**: Table (TTY-aware), JSONL, and YARA rule generation
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use stringy::pipeline::{Pipeline, PipelineConfig};
//! use std::path::Path;
//!
//! let config = PipelineConfig::default();
//! let pipeline = Pipeline::new(config);
//! pipeline.run(Path::new("binary")).expect("pipeline failed");
//! ```
//!
//! ## Architecture
//!
//! The library is organized into focused modules:
//!
//! - [`container`]: Binary format detection and parsing
//! - [`extraction`]: Encoding-aware string extraction with noise filtering
//! - [`classification`]: Semantic analysis, tagging, and ranking
//! - [`output`]: Result formatting (table, JSON, YARA)
//! - [`pipeline`]: Orchestration from file loading through output
//! - [`types`]: Core data structures and error handling

pub mod classification;
pub mod container;
pub mod extraction;
pub mod output;
pub mod pipeline;
pub mod types;

// Re-export commonly used types
pub use types::{
    BinaryFormat, ContainerInfo, Encoding, ExportInfo, FoundString, ImportInfo, ResourceMetadata,
    ResourceStringEntry, ResourceStringTable, ResourceType, Result, SectionInfo, SectionType,
    StringContext, StringSource, StringyError, Tag,
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

// Re-export pipeline types
pub use pipeline::{EncodingFilter, FilterConfig, FilterEngine, Pipeline, PipelineConfig};
