# API Documentation

This page provides an overview of Stringy's public API. For complete API documentation, run `cargo doc --open` in the project directory.

## Core Types

### FoundString

The primary data structure representing an extracted string with metadata.

```text
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundString {
    /// The extracted string text
    pub text: String,
    /// Pre-demangled form (if symbol was demangled)
    pub original_text: Option<String>,
    /// The encoding used for this string
    pub encoding: Encoding,
    /// File offset where the string was found
    pub offset: u64,
    /// Relative Virtual Address (if available)
    pub rva: Option<u64>,
    /// Section name where the string was found
    pub section: Option<String>,
    /// Length of the string in bytes
    pub length: u32,
    /// Semantic tags applied to this string
    pub tags: Vec<Tag>,
    /// Relevance score for ranking
    pub score: i32,
    /// Section weight component of score (debug only)
    pub section_weight: Option<i32>,
    /// Semantic boost component of score (debug only)
    pub semantic_boost: Option<i32>,
    /// Noise penalty component of score (debug only)
    pub noise_penalty: Option<i32>,
    /// Display score 0-100, populated by ScoreNormalizer in all non-raw executions
    pub display_score: Option<i32>,
    /// Source of the string (section data, import, etc.)
    pub source: StringSource,
    /// UTF-16 confidence score
    pub confidence: f32,
}
```

### Encoding

Supported string encodings.

```text
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Encoding {
    Ascii,
    Utf8,
    Utf16Le,
    Utf16Be,
}
```

### Tag

Semantic classification tags.

```text
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tag {
    Url,
    Domain,
    IPv4,
    IPv6,
    FilePath,
    RegistryPath,
    Guid,
    Email,
    Base64,
    FormatString,
    UserAgent,
    DemangledSymbol,
    Import,
    Export,
    Version,
    Manifest,
    Resource,
    DylibPath,
    Rpath,
    RpathVariable,
    FrameworkPath,
}
```

### EncodingFilter

Filter for restricting output by string encoding, corresponding to the `--enc` CLI flag.

```text
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodingFilter {
    /// Match a specific encoding exactly
    Exact(Encoding),
    /// Match any UTF-16 variant (UTF-16LE or UTF-16BE)
    Utf16Any,
}
```

Used with `FilterConfig` to limit results to a specific encoding. `Utf16Any` matches both `Utf16Le` and `Utf16Be`.

### FilterConfig

Post-extraction filtering configuration. All fields have sensible defaults; empty tag vectors are no-ops.

```text
pub struct FilterConfig {
    /// Minimum string length to include (default: 4)
    pub min_length: usize,          // --min-len
    /// Restrict to a specific encoding
    pub encoding: Option<EncodingFilter>, // --enc
    /// Only include strings with these tags (empty = no filter)
    pub include_tags: Vec<Tag>,     // --only-tags
    /// Exclude strings with these tags (empty = no filter)
    pub exclude_tags: Vec<Tag>,     // --no-tags
    /// Limit output to top N strings by score
    pub top_n: Option<usize>,      // --top
}
```

Builder-style construction:

```text
let config = FilterConfig::new()
    .with_min_length(6)
    .with_encoding(EncodingFilter::Exact(Encoding::Utf8))
    .with_include_tags(vec![Tag::Url, Tag::Domain])
    .with_top_n(20);
```

## Main API Functions

### BasicExtractor::extract

Extract strings from binary data using the `BasicExtractor`, which implements the `StringExtractor` trait.

```text
pub trait StringExtractor {
    fn extract(
        &self,
        data: &[u8],
        container_info: &ContainerInfo,
        config: &ExtractionConfig,
    ) -> Result<Vec<FoundString>>;
}
```

**Parameters:**

- `data`: Binary data to analyze
- `container_info`: Parsed container metadata (sections, imports, exports)
- `config`: Extraction configuration options

**Returns:**

- `Result<Vec<FoundString>>`: Extracted strings with metadata

**Example:**

```text
use stringy::{BasicExtractor, ExtractionConfig, StringExtractor};
use stringy::container::{detect_format, create_parser};

let data = std::fs::read("binary.exe")?;
let format = detect_format(&data);
let parser = create_parser(format)?;
let container_info = parser.parse(&data)?;

let extractor = BasicExtractor::new();
let config = ExtractionConfig::default();
let strings = extractor.extract(&data, &container_info, &config)?;

for string in strings {
    println!("{}: {}", string.score, string.text);
}
```

### detect_format

Detect the binary format of the given data.

```text
pub fn detect_format(data: &[u8]) -> BinaryFormat
```

**Parameters:**

- `data`: Binary data to analyze

**Returns:**

- `BinaryFormat`: Detected format (ELF, PE, MachO, or Unknown)

**Example:**

```text
use stringy::detect_format;

let data = std::fs::read("binary")?;
let format = detect_format(&data);
println!("Detected format: {:?}", format);
```

## Configuration

### ExtractionConfig

Configuration options for string extraction. The struct has 16 fields with sensible defaults.

```text
pub struct ExtractionConfig {
    /// Minimum string length in bytes (default: 1)
    pub min_length: usize,
    /// Maximum string length in bytes (default: 4096)
    pub max_length: usize,
    /// Whether to scan executable sections (default: true)
    pub scan_code_sections: bool,
    /// Whether to include debug sections (default: false)
    pub include_debug: bool,
    /// Section types to prioritize (default: StringData, ReadOnlyData, Resources)
    pub section_priority: Vec<SectionType>,
    /// Whether to include import/export names (default: true)
    pub include_symbols: bool,
    /// Minimum length for ASCII strings (default: 1)
    pub min_ascii_length: usize,
    /// Minimum length for UTF-16 strings (default: 1)
    pub min_wide_length: usize,
    /// Which encodings to extract (default: ASCII, UTF-8)
    pub enabled_encodings: Vec<Encoding>,
    /// Enable/disable noise filtering (default: true)
    pub noise_filtering_enabled: bool,
    /// Minimum confidence threshold (default: 0.5)
    pub min_confidence_threshold: f32,
    /// Minimum UTF-16LE confidence threshold (default: 0.7)
    pub utf16_min_confidence: f32,
    /// Which UTF-16 byte order(s) to scan (default: Auto)
    pub utf16_byte_order: ByteOrder,
    /// Minimum UTF-16-specific confidence threshold (default: 0.5)
    pub utf16_confidence_threshold: f32,
    /// Enable/disable deduplication (default: true)
    pub enable_deduplication: bool,
    /// Deduplication threshold (default: None)
    pub dedup_threshold: Option<usize>,
}

impl Default for ExtractionConfig {
    fn default() -> Self {
        Self {
            min_length: 1,
            max_length: 4096,
            scan_code_sections: true,
            include_debug: false,
            section_priority: vec![
                SectionType::StringData,
                SectionType::ReadOnlyData,
                SectionType::Resources,
            ],
            include_symbols: true,
            min_ascii_length: 1,
            min_wide_length: 1,
            enabled_encodings: vec![Encoding::Ascii, Encoding::Utf8],
            noise_filtering_enabled: true,
            min_confidence_threshold: 0.5,
            utf16_min_confidence: 0.7,
            utf16_byte_order: ByteOrder::Auto,
            utf16_confidence_threshold: 0.5,
            enable_deduplication: true,
            dedup_threshold: None,
        }
    }
}
```

### SemanticClassifier

The `SemanticClassifier` is constructed via `SemanticClassifier::new()` and currently has no configuration options. Classification patterns are built-in.

## Pipeline Components

### ScoreNormalizer

Maps internal relevance scores to a 0-100 display scale using band mapping.

```text
let normalizer = ScoreNormalizer::new();
normalizer.normalize(&mut strings);
// Each FoundString now has display_score populated
```

Invoked unconditionally by the pipeline in all non-raw executions. Negative internal scores map to `display_score = 0`. See [Ranking](./ranking.md) for the full band-mapping table.

### FilterEngine

Applies post-extraction filtering and sorting. Consumes the input vector and returns a filtered, sorted result.

```text
let engine = FilterEngine::new();
let filtered = engine.apply(strings, &filter_config);
```

Filter order:

1. Minimum length (`min_length`)
2. Encoding match (`encoding`)
3. Include tags (`include_tags` -- keep only strings with at least one matching tag)
4. Exclude tags (`exclude_tags` -- remove strings with any matching tag)
5. Stable sort by score (descending), then offset (ascending), then text (ascending)
6. Top-N truncation (`top_n`)

**Example: FilterConfig + FilterEngine**

```text
use stringy::{FilterConfig, FilterEngine, EncodingFilter, Encoding, Tag};

let config = FilterConfig::new()
    .with_min_length(6)
    .with_include_tags(vec![Tag::Url, Tag::Domain])
    .with_top_n(10);

let engine = FilterEngine::new();
let results = engine.apply(strings, &config);
// results contains at most 10 strings, all >= 6 chars,
// all tagged Url or Domain, sorted by score descending
```

## Container Parsing

### ContainerParser Trait

Trait for implementing binary format parsers.

```text
pub trait ContainerParser {
    /// Detect if this parser can handle the given data
    fn detect(data: &[u8]) -> bool
    where
        Self: Sized;

    /// Parse the container and extract metadata
    fn parse(&self, data: &[u8]) -> Result<ContainerInfo>;
}
```

### ContainerInfo

Information about a parsed binary container.

```text
pub struct ContainerInfo {
    /// The binary format detected
    pub format: BinaryFormat,
    /// List of sections in the binary
    pub sections: Vec<SectionInfo>,
    /// Import information
    pub imports: Vec<ImportInfo>,
    /// Export information
    pub exports: Vec<ExportInfo>,
    /// Resource metadata (PE format only)
    pub resources: Option<Vec<ResourceMetadata>>,
}
```

### SectionInfo

Information about a section within the binary.

```text
pub struct SectionInfo {
    /// Section name
    pub name: String,
    /// File offset of the section
    pub offset: u64,
    /// Size of the section in bytes
    pub size: u64,
    /// Relative Virtual Address (if available)
    pub rva: Option<u64>,
    /// Classification of the section type
    pub section_type: SectionType,
    /// Whether the section is executable
    pub is_executable: bool,
    /// Whether the section is writable
    pub is_writable: bool,
    /// Weight indicating likelihood of containing meaningful strings (1.0-10.0)
    pub weight: f32,
}
```

## Output Formatting

### OutputFormatter Trait

Trait for implementing output formatters.

```text
pub trait OutputFormatter {
    /// Returns the name of this formatter
    fn name(&self) -> &'static str;

    /// Format the strings for output
    fn format(&self, strings: &[FoundString], metadata: &OutputMetadata) -> Result<String>;
}
```

### Built-in Formatters

The library provides free functions rather than formatter structs:

- `format_table(strings, metadata)` - Human-readable table format (TTY-aware)
- `format_json(strings, metadata)` - JSONL format
- `format_yara(strings, metadata)` - YARA rule format
- `format_output(strings, metadata)` - Dispatches based on `metadata.output_format`

**Example:**

```text
use stringy::output::{format_json, OutputMetadata};

let metadata = OutputMetadata::new("binary.exe".to_string());
let output = format_json(&strings, &metadata)?;
println!("{}", output);
```

## Error Handling

### StringyError

Comprehensive error type for the library.

```text
#[derive(Debug, thiserror::Error)]
pub enum StringyError {
    #[error("Unsupported file format (supported: ELF, PE, Mach-O)")]
    UnsupportedFormat,

    #[error("File I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Binary parsing error: {0}")]
    ParseError(String),

    #[error("Invalid encoding in string at offset {offset}")]
    EncodingError { offset: u64 },

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Memory mapping error: {0}")]
    MemoryMapError(String),
}
```

### Result Type

Convenient result type alias.

```text
pub type Result<T> = std::result::Result<T, StringyError>;
```

## Advanced Usage

### Custom Classification

Implement custom semantic classifiers:

```text
use stringy::classification::{ClassificationResult, Classifier};

pub struct CustomClassifier {
    // Custom implementation
}

impl Classifier for CustomClassifier {
    fn classify(&self, text: &str, context: &StringContext) -> Vec<ClassificationResult> {
        // Custom classification logic
        vec![]
    }
}
```

### Memory-Mapped Files

For large files, use memory mapping via `mmap-guard`:

```text
let data = mmap_guard::map_file(path)?;
// data implements Deref<Target = [u8]>
```

Note: The `Pipeline::run` API handles memory mapping automatically. Direct use of `mmap_guard` is only needed when using lower-level APIs.

### Parallel Processing

Parallel processing is not yet implemented. Stringy currently processes files sequentially. The `Pipeline` API processes one file at a time.

## Feature Flags

Stringy currently has no optional feature flags. All functionality is included by default.

## Examples

### Basic String Extraction (Pipeline API)

```text
use stringy::pipeline::{Pipeline, PipelineConfig};
use std::path::Path;

fn main() -> stringy::Result<()> {
    let config = PipelineConfig::default();
    let pipeline = Pipeline::new(config);
    pipeline.run(Path::new("binary.exe"))?;
    Ok(())
}
```

### Filtered Extraction

```text
use stringy::{BasicExtractor, ExtractionConfig, StringExtractor, Tag};
use stringy::container::{detect_format, create_parser};

fn extract_network_indicators(data: &[u8]) -> stringy::Result<Vec<String>> {
    let format = detect_format(data);
    let parser = create_parser(format)?;
    let container_info = parser.parse(data)?;

    let extractor = BasicExtractor::new();
    let config = ExtractionConfig::default();
    let strings = extractor.extract(data, &container_info, &config)?;

    let network_strings: Vec<String> = strings
        .into_iter()
        .filter(|s| {
            s.tags
                .iter()
                .any(|tag| matches!(tag, Tag::Url | Tag::Domain | Tag::IPv4 | Tag::IPv6))
        })
        .filter(|s| s.score >= 70)
        .map(|s| s.text)
        .collect();

    Ok(network_strings)
}
```

### Custom Output Format

```text
use serde_json::json;
use stringy::output::{OutputMetadata, OutputFormatter};
use stringy::FoundString;

pub struct CustomFormatter;

impl OutputFormatter for CustomFormatter {
    fn name(&self) -> &'static str {
        "custom"
    }

    fn format(&self, strings: &[FoundString], _metadata: &OutputMetadata) -> stringy::Result<String> {
        let output = json!({
            "total_strings": strings.len(),
            "high_confidence": strings.iter().filter(|s| s.score >= 80).count(),
            "strings": strings.iter().take(20).collect::<Vec<_>>()
        });

        Ok(serde_json::to_string_pretty(&output)?)
    }
}
```

For complete API documentation with all methods and implementation details, run:

```bash
cargo doc --open
```
