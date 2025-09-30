# API Documentation

This page provides an overview of Stringy's public API. For complete API documentation, run `cargo doc --open` in the project directory.

## Core Types

### FoundString

The primary data structure representing an extracted string with metadata.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundString {
    /// The extracted string text
    pub text: String,
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
    /// Source of the string (section data, import, etc.)
    pub source: StringSource,
}
```

### Encoding

Supported string encodings.

```rust
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

```rust
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
    Import,
    Export,
    Version,
    Manifest,
    Resource,
}
```

## Main API Functions

### extract_strings

Extract strings from binary data.

```rust
pub fn extract_strings(
    data: &[u8], 
    config: &ExtractionConfig
) -> Result<Vec<FoundString>>
```

**Parameters:**

- `data`: Binary data to analyze
- `config`: Extraction configuration options

**Returns:**

- `Result<Vec<FoundString>>`: Extracted strings with metadata

**Example:**

```rust
use stringy::{extract_strings, ExtractionConfig};

let data = std::fs::read("binary.exe")?;
let config = ExtractionConfig::default();
let strings = extract_strings(&data, &config)?;

for string in strings {
    println!("{}: {}", string.score, string.text);
}
```

### detect_format

Detect the binary format of the given data.

```rust
pub fn detect_format(data: &[u8]) -> BinaryFormat
```

**Parameters:**

- `data`: Binary data to analyze

**Returns:**

- `BinaryFormat`: Detected format (ELF, PE, MachO, or Unknown)

**Example:**

```rust
use stringy::detect_format;

let data = std::fs::read("binary")?;
let format = detect_format(&data);
println!("Detected format: {:?}", format);
```

## Configuration

### ExtractionConfig

Configuration options for string extraction.

```rust
pub struct ExtractionConfig {
    /// Minimum length for ASCII strings
    pub min_ascii_len: usize,
    /// Minimum length for UTF-16 strings
    pub min_utf16_len: usize,
    /// Maximum string length
    pub max_string_len: usize,
    /// Encodings to extract
    pub encodings: Vec<Encoding>,
    /// Sections to include (None = all)
    pub include_sections: Option<Vec<String>>,
    /// Sections to exclude
    pub exclude_sections: Vec<String>,
    /// Include debug sections
    pub include_debug: bool,
    /// Include import/export names
    pub include_symbols: bool,
}

impl Default for ExtractionConfig {
    fn default() -> Self {
        Self {
            min_ascii_len: 4,
            min_utf16_len: 3,
            max_string_len: 1024,
            encodings: vec![Encoding::Ascii, Encoding::Utf16Le],
            include_sections: None,
            exclude_sections: Vec::new(),
            include_debug: false,
            include_symbols: true,
        }
    }
}
```

### ClassificationConfig

Configuration for semantic classification.

```rust
pub struct ClassificationConfig {
    /// Enable URL detection
    pub detect_urls: bool,
    /// Enable domain detection
    pub detect_domains: bool,
    /// Enable IP address detection
    pub detect_ips: bool,
    /// Enable file path detection
    pub detect_paths: bool,
    /// Enable GUID detection
    pub detect_guids: bool,
    /// Enable email detection
    pub detect_emails: bool,
    /// Enable Base64 detection
    pub detect_base64: bool,
    /// Enable format string detection
    pub detect_format_strings: bool,
    /// Minimum confidence threshold
    pub min_confidence: f32,
}
```

## Container Parsing

### ContainerParser Trait

Trait for implementing binary format parsers.

```rust
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

```rust
pub struct ContainerInfo {
    /// The binary format detected
    pub format: BinaryFormat,
    /// List of sections in the binary
    pub sections: Vec<SectionInfo>,
    /// Import information
    pub imports: Vec<ImportInfo>,
    /// Export information
    pub exports: Vec<ExportInfo>,
}
```

### SectionInfo

Information about a section within the binary.

```rust
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
}
```

## Output Formatting

### OutputFormatter Trait

Trait for implementing output formatters.

```rust
pub trait OutputFormatter {
    /// Format the strings for output
    fn format(&self, strings: &[FoundString], config: &OutputConfig) -> Result<String>;
}
```

### Built-in Formatters

```rust
// Human-readable table format
pub struct HumanFormatter;

// JSON Lines format
pub struct JsonFormatter;

// YARA rule format
pub struct YaraFormatter;
```

**Example:**

```rust
use stringy::output::{JsonFormatter, OutputFormatter, OutputConfig};

let formatter = JsonFormatter::new();
let config = OutputConfig::default();
let output = formatter.format(&strings, &config)?;
println!("{}", output);
```

## Error Handling

### StringyError

Comprehensive error type for the library.

```rust
#[derive(Debug, thiserror::Error)]
pub enum StringyError {
    #[error("Unsupported file format")]
    UnsupportedFormat,

    #[error("File I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Binary parsing error: {0}")]
    ParseError(String),

    #[error("Invalid encoding in string at offset {offset}")]
    EncodingError { offset: u64 },

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Memory mapping error: {0}")]
    MemoryMapError(String),
}
```

### Result Type

Convenient result type alias.

```rust
pub type Result<T> = std::result::Result<T, StringyError>;
```

## Advanced Usage

### Custom Classification

Implement custom semantic classifiers:

```rust
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

For large files, use memory mapping:

```rust
use memmap2::Mmap;
use std::fs::File;

let file = File::open("large_binary.exe")?;
let mmap = unsafe { Mmap::map(&file)? };
let strings = extract_strings(&mmap[..], &config)?;
```

### Parallel Processing

Process multiple files in parallel:

```rust
use rayon::prelude::*;

let files = vec!["file1.exe", "file2.dll", "file3.so"];
let results: Vec<_> = files
    .par_iter()
    .map(|path| {
        let data = std::fs::read(path)?;
        extract_strings(&data, &config)
    })
    .collect();
```

## Feature Flags

Optional features can be enabled in `Cargo.toml`:

```toml
[dependencies]
stringy = { version = "0.1", features = ["pe-resources", "dwarf-debug"] }
```

Available features:

- `pe-resources`: Enhanced PE resource extraction
- `dwarf-debug`: DWARF debugging information support
- `capstone`: Disassembly support for reference analysis
- `parallel`: Parallel processing support

## Examples

### Basic String Extraction

```rust
use stringy::{ExtractionConfig, extract_strings};

fn main() -> stringy::Result<()> {
    let data = std::fs::read("binary.exe")?;
    let config = ExtractionConfig::default();
    let strings = extract_strings(&data, &config)?;

    // Print top 10 strings
    for string in strings.iter().take(10) {
        println!("{:3} | {}", string.score, string.text);
    }

    Ok(())
}
```

### Filtered Extraction

```rust
use stringy::{Encoding, ExtractionConfig, Tag, extract_strings};

fn extract_network_indicators(data: &[u8]) -> stringy::Result<Vec<String>> {
    let config = ExtractionConfig {
        min_ascii_len: 6,
        encodings: vec![Encoding::Ascii, Encoding::Utf8],
        ..Default::default()
    };

    let strings = extract_strings(data, &config)?;

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

```rust
use serde_json::json;
use stringy::output::{OutputConfig, OutputFormatter};

pub struct CustomFormatter;

impl OutputFormatter for CustomFormatter {
    fn format(&self, strings: &[FoundString], _config: &OutputConfig) -> stringy::Result<String> {
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
