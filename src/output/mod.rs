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

use std::collections::HashMap;
use std::time::Duration;

use crate::types::{BinaryFormat, FoundString, Result, Tag};

pub mod json;
pub mod table;
pub mod yara;

pub use json::format_json;
pub use table::{format_table, format_table_with_mode};
pub use yara::format_yara;

/// Trait for output formatters.
///
/// Implementations of this trait provide different output formats for extracted
/// strings. This trait enables extensibility by allowing custom formatters to be
/// added without modifying the core dispatch logic.
///
/// # Example
///
/// ```rust
/// use stringy::output::{OutputFormatter, OutputMetadata};
/// use stringy::types::{FoundString, Result};
///
/// struct CustomFormatter;
///
/// impl OutputFormatter for CustomFormatter {
///     fn format(&self, strings: &[FoundString], metadata: &OutputMetadata) -> Result<String> {
///         Ok(format!("Custom: {} strings from {}", strings.len(), metadata.binary_name))
///     }
///
///     fn name(&self) -> &'static str {
///         "custom"
///     }
/// }
/// ```
pub trait OutputFormatter {
    /// Format the extracted strings into the output representation.
    ///
    /// # Arguments
    ///
    /// * `strings` - The extracted strings to format.
    /// * `metadata` - Output context including binary name and format settings.
    ///
    /// # Returns
    ///
    /// A formatted string on success, or an error if formatting fails.
    fn format(&self, strings: &[FoundString], metadata: &OutputMetadata) -> Result<String>;

    /// Returns the name of this formatter for identification purposes.
    fn name(&self) -> &'static str;
}

/// Output format selection for Stringy formatters.
#[non_exhaustive]
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
    /// Whether to append a summary block after the table output.
    pub show_summary: bool,
    /// The detected binary format of the analyzed file.
    pub binary_format: BinaryFormat,
    /// Top tag distribution (tag -> count), populated when summary is enabled.
    pub top_tags: Vec<(Tag, usize)>,
    /// Total analysis duration, populated when summary is enabled.
    pub analysis_duration: Option<Duration>,
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
            show_summary: false,
            binary_format: BinaryFormat::Unknown,
            top_tags: Vec::new(),
            analysis_duration: None,
        }
    }

    /// Set an explicit generated-at timestamp for deterministic outputs.
    #[must_use]
    pub fn with_generated_at(mut self, generated_at: String) -> Self {
        self.generated_at = Some(generated_at);
        self
    }

    /// Enable or disable the summary block after table output.
    #[must_use]
    pub fn with_show_summary(mut self, show_summary: bool) -> Self {
        self.show_summary = show_summary;
        self
    }

    /// Set the binary format of the analyzed file.
    #[must_use]
    pub fn with_binary_format(mut self, binary_format: BinaryFormat) -> Self {
        self.binary_format = binary_format;
        self
    }

    /// Set the top tag distribution.
    #[must_use]
    pub fn with_top_tags(mut self, top_tags: Vec<(Tag, usize)>) -> Self {
        self.top_tags = top_tags;
        self
    }

    /// Set the analysis duration.
    #[must_use]
    pub fn with_analysis_duration(mut self, duration: Duration) -> Self {
        self.analysis_duration = Some(duration);
        self
    }

    /// Compute top tag distribution from the given strings.
    ///
    /// Returns a sorted `Vec<(Tag, usize)>` of the most frequent tags, limited
    /// to `limit` entries.
    #[must_use]
    pub fn compute_top_tags(strings: &[FoundString], limit: usize) -> Vec<(Tag, usize)> {
        let mut counts: HashMap<Tag, usize> = HashMap::new();
        for s in strings {
            for tag in &s.tags {
                *counts.entry(tag.clone()).or_insert(0) += 1;
            }
        }
        let mut sorted: Vec<(Tag, usize)> = counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(limit);
        sorted
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
    use crate::types::{BinaryFormat, Encoding, StringSource, StringyError, Tag};

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

        // New fields default correctly
        assert!(!metadata.show_summary);
        assert_eq!(metadata.binary_format, BinaryFormat::Unknown);
        assert!(metadata.top_tags.is_empty());
        assert!(metadata.analysis_duration.is_none());
    }

    #[test]
    fn test_with_generated_at_builder() {
        let metadata = OutputMetadata::new("test.bin".to_string(), OutputFormat::Yara, 0, 0);
        assert!(metadata.generated_at.is_none());

        let with_timestamp = metadata.with_generated_at("12345".to_string());
        assert_eq!(with_timestamp.generated_at, Some("12345".to_string()));

        let metadata = OutputMetadata::new("test.bin".to_string(), OutputFormat::Yara, 0, 0);
        let with_summary = metadata.with_show_summary(true);
        assert!(with_summary.show_summary);

        let metadata = OutputMetadata::new("test.bin".to_string(), OutputFormat::Table, 0, 0);
        let with_format = metadata.with_binary_format(BinaryFormat::Elf);
        assert_eq!(with_format.binary_format, BinaryFormat::Elf);

        let metadata = OutputMetadata::new("test.bin".to_string(), OutputFormat::Table, 0, 0);
        let with_tags = metadata.with_top_tags(vec![(Tag::Url, 5), (Tag::Domain, 3)]);
        assert_eq!(with_tags.top_tags.len(), 2);
        assert_eq!(with_tags.top_tags[0], (Tag::Url, 5));

        let metadata = OutputMetadata::new("test.bin".to_string(), OutputFormat::Table, 0, 0);
        let with_duration = metadata.with_analysis_duration(Duration::from_millis(42));
        assert_eq!(
            with_duration.analysis_duration,
            Some(Duration::from_millis(42))
        );
    }

    #[test]
    fn test_compute_top_tags() {
        let mut s1 = build_found_string("http://example.com");
        s1.tags = vec![Tag::Url, Tag::Domain];
        let mut s2 = build_found_string("http://other.com");
        s2.tags = vec![Tag::Url];
        let mut s3 = build_found_string("10.0.0.1");
        s3.tags = vec![Tag::IPv4];

        let top = OutputMetadata::compute_top_tags(&[s1, s2, s3], 2);
        assert_eq!(top.len(), 2);
        // Url should be first (count 2)
        assert_eq!(top[0].0, Tag::Url);
        assert_eq!(top[0].1, 2);
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
