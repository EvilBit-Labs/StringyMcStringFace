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
//! # Ok(())
//! # }
//! ```
//!
//! ## Architecture
//!
//! The library is organized into focused modules:
//!
//! - [`container`]: Binary format detection and parsing (✅ Complete)
//! - [`extraction`]: String extraction algorithms (🚧 Framework ready)
//! - [`classification`]: Semantic analysis and tagging (🚧 Types defined)
//! - [`output`]: Result formatting (🚧 Interfaces ready)
//! - [`types`]: Core data structures and error handling (✅ Complete)

pub mod classification;
pub mod container;
pub mod extraction;
pub mod output;
pub mod types;

// Re-export commonly used types
pub use types::{
    BinaryFormat, ContainerInfo, Encoding, ExportInfo, FoundString, ImportInfo, Result,
    SectionInfo, SectionType, StringSource, StringyError, Tag,
};
