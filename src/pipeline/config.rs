//! Configuration types for the Stringy pipeline.
//!
//! This module defines the configuration structs used to control pipeline
//! behavior: encoding filters, string filters, and overall pipeline settings.

use crate::extraction::ExtractionConfig;
use crate::output::OutputFormat;
use crate::types::{Encoding, Tag};

/// Encoding filter for restricting extracted strings by encoding type.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodingFilter {
    /// Match a single specific encoding variant.
    Exact(Encoding),
    /// Match both `Encoding::Utf16Le` and `Encoding::Utf16Be`.
    Utf16Any,
}

/// Configuration for post-extraction string filtering.
///
/// Controls which strings survive the filter pipeline based on length,
/// encoding, semantic tags, and ranking limits.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct FilterConfig {
    /// Minimum string length in bytes (default: None, no minimum).
    pub min_length: Option<usize>,
    /// Restrict to a specific encoding (default: None, all encodings).
    pub encoding: Option<EncodingFilter>,
    /// Only include strings with at least one of these tags (from `--only-tags`).
    pub include_tags: Vec<Tag>,
    /// Exclude strings with any of these tags (from `--no-tags`).
    pub exclude_tags: Vec<Tag>,
    /// Keep only the top N strings by score (from `--top`).
    pub top_n: Option<usize>,
}

impl FilterConfig {
    /// Create a new `FilterConfig` with all-permissive defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            min_length: None,
            encoding: None,
            include_tags: Vec::new(),
            exclude_tags: Vec::new(),
            top_n: None,
        }
    }

    /// Set the minimum string length.
    #[must_use]
    pub fn with_min_length(mut self, min_length: usize) -> Self {
        self.min_length = Some(min_length);
        self
    }

    /// Set the encoding filter.
    #[must_use]
    pub fn with_encoding(mut self, encoding: EncodingFilter) -> Self {
        self.encoding = Some(encoding);
        self
    }

    /// Set the include-tags filter.
    #[must_use]
    pub fn with_include_tags(mut self, tags: Vec<Tag>) -> Self {
        self.include_tags = tags;
        self
    }

    /// Set the exclude-tags filter.
    #[must_use]
    pub fn with_exclude_tags(mut self, tags: Vec<Tag>) -> Self {
        self.exclude_tags = tags;
        self
    }

    /// Set the top-N limit.
    #[must_use]
    pub fn with_top_n(mut self, n: usize) -> Self {
        self.top_n = Some(n);
        self
    }
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Top-level pipeline configuration.
///
/// Aggregates extraction settings, filter settings, and output options
/// into a single config stored on a `Pipeline` instance.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Configuration for the extraction stage.
    pub extraction_config: ExtractionConfig,
    /// Configuration for post-extraction filtering.
    pub filter_config: FilterConfig,
    /// Enable debug metadata in output.
    pub debug_mode: bool,
    /// Raw output mode (no tags, no scores, no headers).
    pub raw_mode: bool,
    /// Append a summary banner after output.
    pub show_summary: bool,
    /// Output format selection.
    pub output_format: OutputFormat,
    /// Display name of the binary being analyzed.
    pub binary_name: String,
}

impl PipelineConfig {
    /// Create a new `PipelineConfig` with sensible defaults.
    #[must_use]
    pub fn new(binary_name: String) -> Self {
        Self {
            extraction_config: ExtractionConfig::default(),
            filter_config: FilterConfig::new(),
            debug_mode: false,
            raw_mode: false,
            show_summary: false,
            output_format: OutputFormat::Table,
            binary_name,
        }
    }

    /// Set the extraction configuration.
    #[must_use]
    pub fn with_extraction_config(mut self, config: ExtractionConfig) -> Self {
        self.extraction_config = config;
        self
    }

    /// Set the filter configuration.
    #[must_use]
    pub fn with_filter_config(mut self, config: FilterConfig) -> Self {
        self.filter_config = config;
        self
    }

    /// Enable or disable debug mode.
    #[must_use]
    pub fn with_debug_mode(mut self, debug: bool) -> Self {
        self.debug_mode = debug;
        self
    }

    /// Enable or disable raw output mode.
    #[must_use]
    pub fn with_raw_mode(mut self, raw: bool) -> Self {
        self.raw_mode = raw;
        self
    }

    /// Enable or disable the summary banner.
    #[must_use]
    pub fn with_show_summary(mut self, show: bool) -> Self {
        self.show_summary = show;
        self
    }

    /// Set the output format.
    #[must_use]
    pub fn with_output_format(mut self, format: OutputFormat) -> Self {
        self.output_format = format;
        self
    }
}
