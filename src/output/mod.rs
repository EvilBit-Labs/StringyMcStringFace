//! Output formatting infrastructure for Stringy.
//!
//! This module provides the core dispatch logic and shared metadata for output
//! formatters. Concrete formatters live in submodules and are selected via the
//! `OutputFormat` enum.
//!
//! Supported formats:
//! - Table (human-readable, TTY-friendly)
//! - JSON (JSONL, one object per line)
//! - YARA (rule template output)
//!
//! ## Example
//!
//! ```rust
//! use stringy::{format_output, FoundString, OutputFormat, OutputMetadata};
//! use stringy::types::{Encoding, StringSource};
//!
//! let strings = vec![FoundString::new(
//!     "example".to_string(),
//!     Encoding::Ascii,
//!     0,
//!     7,
//!     StringSource::SectionData,
//! )];
//!
//! let metadata = OutputMetadata::new(
//!     "sample.bin".to_string(),
//!     OutputFormat::Table,
//!     strings.len(),
//!     strings.len(),
//! );
//!
//! let output = format_output(&strings, &metadata)?;
//! # Ok::<(), stringy::StringyError>(())
//! ```

use crate::types::{FoundString, Result};

pub mod json;
pub mod table;
pub mod yara;

pub use json::format_json;
pub use table::{format_table, format_table_with_mode};
pub use yara::format_yara;

/// Output format selection for Stringy formatters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Human-readable table format with TTY detection.
    Table,
    /// JSONL output, one JSON object per line.
    Json,
    /// YARA rule template output.
    Yara,
}

/// Metadata describing the output context.
///
/// This struct is marked `#[non_exhaustive]` to allow adding new fields without
/// breaking downstream code. Use `OutputMetadata::new()` to construct instances.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputMetadata {
    /// Name of the analyzed binary file.
    pub binary_name: String,
    /// Output format to be used.
    pub format: OutputFormat,
    /// Total number of strings extracted.
    pub total_strings: usize,
    /// Number of strings after filtering.
    pub filtered_strings: usize,
    /// Optional generated-at timestamp for deterministic outputs.
    ///
    /// When set, formatters may use this value instead of runtime timestamps.
    pub generated_at: Option<String>,
}

impl OutputMetadata {
    /// Create a new `OutputMetadata` instance.
    #[must_use]
    pub fn new(
        binary_name: String,
        format: OutputFormat,
        total_strings: usize,
        filtered_strings: usize,
    ) -> Self {
        Self {
            binary_name,
            format,
            total_strings,
            filtered_strings,
            generated_at: None,
        }
    }

    /// Set an explicit generated-at timestamp for deterministic outputs.
    #[must_use]
    pub fn with_generated_at(mut self, generated_at: String) -> Self {
        self.generated_at = Some(generated_at);
        self
    }
}

/// Format output strings using the requested output format.
///
/// # Arguments
///
/// * `strings` - The extracted strings to format.
/// * `metadata` - Output context and format selection.
///
/// # Returns
///
/// A formatted output string on success.
pub fn format_output(strings: &[FoundString], metadata: &OutputMetadata) -> Result<String> {
    format_output_with(strings, metadata, format_table, format_json, format_yara)
}

fn format_output_with<
    FTable: Fn(&[FoundString], &OutputMetadata) -> Result<String>,
    FJson: Fn(&[FoundString], &OutputMetadata) -> Result<String>,
    FYara: Fn(&[FoundString], &OutputMetadata) -> Result<String>,
>(
    strings: &[FoundString],
    metadata: &OutputMetadata,
    table_formatter: FTable,
    json_formatter: FJson,
    yara_formatter: FYara,
) -> Result<String> {
    match metadata.format {
        OutputFormat::Table => table_formatter(strings, metadata),
        OutputFormat::Json => json_formatter(strings, metadata),
        OutputFormat::Yara => yara_formatter(strings, metadata),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Encoding, StringSource, StringyError};

    fn build_found_string(text: &str) -> FoundString {
        FoundString::new(
            text.to_string(),
            Encoding::Ascii,
            0,
            text.len() as u32,
            StringSource::SectionData,
        )
    }

    #[test]
    fn test_output_format_enum_properties() {
        let table = OutputFormat::Table;
        let json = OutputFormat::Json;
        let yara = OutputFormat::Yara;

        let copied = table;
        let cloned = json;

        assert_eq!(copied, OutputFormat::Table);
        assert_eq!(cloned, OutputFormat::Json);
        assert_ne!(table, json);
        assert_ne!(json, yara);
        assert_ne!(table, yara);

        let debug = format!("{:?}", OutputFormat::Yara);
        assert!(!debug.is_empty(), "Debug output should not be empty");
    }

    #[test]
    fn test_output_metadata_construction() {
        let metadata = OutputMetadata::new("sample.bin".to_string(), OutputFormat::Table, 12, 9);

        assert_eq!(metadata.binary_name, "sample.bin");
        assert_eq!(metadata.format, OutputFormat::Table);
        assert_eq!(metadata.total_strings, 12);
        assert_eq!(metadata.filtered_strings, 9);

        let other = OutputMetadata::new("other.exe".to_string(), OutputFormat::Json, 1, 1);

        assert_eq!(other.binary_name, "other.exe");
        assert_eq!(other.format, OutputFormat::Json);
        assert_eq!(other.total_strings, 1);
        assert_eq!(other.filtered_strings, 1);
    }

    #[test]
    fn test_with_generated_at_builder() {
        let metadata = OutputMetadata::new("test.bin".to_string(), OutputFormat::Yara, 0, 0);
        assert!(metadata.generated_at.is_none());

        let with_timestamp = metadata.with_generated_at("12345".to_string());
        assert_eq!(with_timestamp.generated_at, Some("12345".to_string()));
    }

    #[test]
    fn test_dispatch_logic_for_each_format() {
        let strings = vec![build_found_string("alpha")];
        let metadata = OutputMetadata::new(
            "sample.bin".to_string(),
            OutputFormat::Table,
            strings.len(),
            strings.len(),
        );

        let result = format_output_with(
            &strings,
            &metadata,
            |_, _| Ok("table".to_string()),
            |_, _| Ok("json".to_string()),
            |_, _| Ok("yara".to_string()),
        )
        .expect("Dispatch should succeed");

        assert_eq!(result, "table");

        let json_metadata = OutputMetadata::new(
            "sample.bin".to_string(),
            OutputFormat::Json,
            strings.len(),
            strings.len(),
        );

        let json_result = format_output_with(
            &strings,
            &json_metadata,
            |_, _| Ok("table".to_string()),
            |_, _| Ok("json".to_string()),
            |_, _| Ok("yara".to_string()),
        )
        .expect("Dispatch should succeed");

        assert_eq!(json_result, "json");

        let yara_metadata = OutputMetadata::new(
            "sample.bin".to_string(),
            OutputFormat::Yara,
            strings.len(),
            strings.len(),
        );

        let yara_result = format_output_with(
            &strings,
            &yara_metadata,
            |_, _| Ok("table".to_string()),
            |_, _| Ok("json".to_string()),
            |_, _| Ok("yara".to_string()),
        )
        .expect("Dispatch should succeed");

        assert_eq!(yara_result, "yara");
    }

    #[test]
    fn test_edge_cases() {
        // Use injected stubs to validate dispatch on edge-case metadata without
        // depending on placeholder formatter output.
        let empty: Vec<FoundString> = Vec::new();
        let metadata = OutputMetadata::new("empty.bin".to_string(), OutputFormat::Table, 0, 0);

        let output = format_output_with(
            &empty,
            &metadata,
            |_, _| Ok("table".to_string()),
            |_, _| Ok("json".to_string()),
            |_, _| Ok("yara".to_string()),
        )
        .expect("Formatting should succeed");
        assert_eq!(output, "table");

        let single = vec![build_found_string("x")];
        let single_metadata =
            OutputMetadata::new("single.bin".to_string(), OutputFormat::Json, 1, 1);

        let single_output = format_output_with(
            &single,
            &single_metadata,
            |_, _| Ok("table".to_string()),
            |_, _| Ok("json".to_string()),
            |_, _| Ok("yara".to_string()),
        )
        .expect("Formatting should succeed");
        assert_eq!(single_output, "json");

        let long_name = "a".repeat(512);
        let long_metadata = OutputMetadata::new(long_name, OutputFormat::Yara, 1, 0);
        let long_output = format_output_with(
            &single,
            &long_metadata,
            |_, _| Ok("table".to_string()),
            |_, _| Ok("json".to_string()),
            |_, _| Ok("yara".to_string()),
        )
        .expect("Formatting should succeed");
        assert_eq!(long_output, "yara");
    }

    #[test]
    fn test_error_propagation() {
        let strings = vec![build_found_string("err")];
        let metadata = OutputMetadata::new(
            "sample.bin".to_string(),
            OutputFormat::Json,
            strings.len(),
            strings.len(),
        );

        let error = format_output_with(
            &strings,
            &metadata,
            |_, _| Ok("table".to_string()),
            |_, _| Err(StringyError::ConfigError("formatter failed".to_string())),
            |_, _| Ok("yara".to_string()),
        )
        .expect_err("Formatter errors should propagate");

        match error {
            StringyError::ConfigError(message) => {
                assert_eq!(message, "formatter failed");
            }
            _ => panic!("Unexpected error type"),
        }
    }
}
