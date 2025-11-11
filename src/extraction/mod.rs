//! String extraction logic
//!
//! This module contains string extraction algorithms and format-specific extractors.
//! Each extractor is designed to work with a specific binary format and leverage
//! format-specific knowledge to extract meaningful strings.
//!
//! ## PE Resource String Extraction (Phase 2 Complete)
//!
//! The PE resource extraction module now provides comprehensive string extraction:
//!
//! - `extract_resources()`: Returns resource metadata (Phase 1)
//! - `extract_resource_strings()`: Returns actual strings from resources (Phase 2)
//!
//! # Example
//!
//! ```rust
//! use stringy::extraction::{extract_resources, extract_resource_strings};
//!
//! let pe_data = std::fs::read("example.exe")?;
//!
//! // Phase 1: Get resource metadata
//! let metadata = extract_resources(&pe_data);
//!
//! // Phase 2: Extract actual strings from resources
//! let strings = extract_resource_strings(&pe_data);
//! ```

pub mod pe_resources;

pub use pe_resources::{extract_resource_strings, extract_resources};
