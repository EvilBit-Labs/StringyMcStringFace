//! Stringy - A smarter alternative to the strings command
//!
//! Stringy leverages format-specific knowledge to distinguish meaningful strings
//! from random garbage data in binary files.

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
