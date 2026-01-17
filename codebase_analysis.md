# Stringy Codebase Analysis

## 1. Project Overview

**Stringy** is a smarter alternative to the standard `strings` command that
extracts meaningful strings from ELF, PE, and Mach-O binaries using
format-specific knowledge and semantic classification.

### Key Differentiators

- **Data-Structure Aware**: Extracts strings from actual binary data structures,
  not arbitrary byte runs
- **Section-Aware**: Prioritizes high-value sections (`.rodata`, `.rdata`,
  `__cstring`) with weight-based scoring
- **Encoding-Aware**: Supports ASCII, UTF-8, UTF-16LE/BE with confidence scoring
- **Semantically Tagged**: Identifies URLs, domains, IPs, file paths, registry
  keys, GUIDs, and more
- **Ranked Output**: Presents most relevant strings first using a scoring
  algorithm

### Project Metadata

| Attribute  | Value                                          |
| ---------- | ---------------------------------------------- |
| Language   | Rust 2024 Edition                              |
| MSRV       | 1.85+                                          |
| License    | Apache-2.0                                     |
| Repository | <https://github.com/EvilBit-Labs/Stringy>      |
| Version    | 0.1.0 (in development)                         |
| Total LoC  | ~11,153 (src) + ~5,254 (tests) = ~16,407 lines |

---

## 2. Directory Structure Analysis

```text
D:\Stringy\
|-- .github/
|   |-- copilot-instructions.md    # AI agent guidelines
|   |-- dependabot.yml             # Dependency updates
|   `-- workflows/
|       `-- ci.yml                 # CI pipeline
|-- .kiro/
|   `-- specs/
|       `-- stringy-binary-analyzer/
|           |-- design.md          # Architecture design
|           |-- requirements.md    # 9 project requirements
|           `-- tasks.md           # Implementation tracking
|-- benches/
|   |-- ascii_extraction.rs        # ASCII extraction benchmarks
|   |-- elf.rs                     # ELF parsing benchmarks
|   `-- pe.rs                      # PE parsing benchmarks
|-- docs/
|   |-- book.toml                  # mdBook configuration
|   `-- src/                       # Documentation source
|-- src/
|   |-- lib.rs                     # Library entry point (86 lines)
|   |-- main.rs                    # CLI placeholder (23 lines)
|   |-- types.rs                   # Core data structures (309 lines)
|   |-- classification/
|   |   |-- mod.rs                 # Module exports (49 lines)
|   |   `-- semantic.rs            # Semantic classifier (1,542 lines)
|   |-- container/
|   |   |-- mod.rs                 # Parser trait & detection (73 lines)
|   |   |-- elf.rs                 # ELF parser (627 lines)
|   |   |-- pe.rs                  # PE parser (661 lines)
|   |   `-- macho.rs               # Mach-O parser (574 lines)
|   |-- extraction/
|   |   |-- mod.rs                 # Extraction framework (1,498 lines)
|   |   |-- ascii.rs               # ASCII extraction (820 lines)
|   |   |-- config.rs              # Extraction config (221 lines)
|   |   |-- dedup.rs               # Deduplication (841 lines)
|   |   |-- filters.rs             # Noise filters (702 lines)
|   |   |-- macho_load_commands.rs # Mach-O commands (370 lines)
|   |   |-- pe_resources.rs        # PE resources (1,430 lines)
|   |   |-- utf16.rs               # UTF-16 extraction (1,269 lines)
|   |   `-- util.rs                # Utilities (57 lines)
|   `-- output/
|       `-- mod.rs                 # Output formatters (1 line, planned)
|-- tests/
|   |-- fixtures/                  # Binary test fixtures
|   |-- snapshots/                 # Insta snapshots
|   |-- classification_integration.rs
|   |-- integration_elf.rs
|   |-- integration_extraction.rs
|   |-- integration_macho.rs
|   |-- integration_pe.rs
|   |-- test_ascii_extraction.rs
|   |-- test_ascii_integration.rs
|   |-- test_deduplication.rs
|   |-- test_noise_filters.rs
|   `-- test_utf16_extraction.rs
|-- Cargo.toml                     # Project manifest
|-- justfile                       # Build automation (444 lines)
|-- CLAUDE.md                      # Claude Code instructions
|-- AGENTS.md                      # AI agent guidelines
`-- README.md                      # Project documentation
```

---

## 3. File-by-File Breakdown

### Core Library (`src/`)

#### `src/lib.rs` (86 lines)

Library entry point with module declarations and public re-exports.

```rust
#![forbid(unsafe_code)]
#![deny(warnings)]

pub mod classification;
pub mod container;
pub mod extraction;
pub mod output;
pub mod types;

// Re-exports for ergonomic imports
pub use classification::SemanticClassifier;
pub use container::{create_parser, detect_format, ContainerParser};
pub use extraction::{BasicExtractor, StringExtractor, /* ... */};
pub use types::{BinaryFormat, ContainerInfo, Encoding, FoundString, /* ... */};
```

#### `src/main.rs` (23 lines)

CLI placeholder using `clap` derive macros.

```rust
#[derive(Parser)]
#[command(name = "stringy")]
struct Cli {
    #[arg(value_name = "FILE")]
    input: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _args = Cli::parse();
    // TODO: Implement main extraction pipeline
    Ok(())
}
```

#### `src/types.rs` (309 lines)

Core data structures with comprehensive type definitions:

| Type            | Purpose                                             |
| --------------- | --------------------------------------------------- |
| `Tag`           | Semantic classification tags (Url, Domain, IPv4...) |
| `Encoding`      | String encoding (Ascii, Utf8, Utf16Le, Utf16Be)     |
| `BinaryFormat`  | Binary format (Elf, Pe, MachO, Unknown)             |
| `SectionType`   | Section classification (Code, ReadOnlyData, etc.)   |
| `StringSource`  | String origin (SectionData, Import, Export, etc.)   |
| `ContainerInfo` | Parsed binary metadata (non-exhaustive)             |
| `SectionInfo`   | Section details with weight scoring                 |
| `FoundString`   | Extracted string with full metadata                 |
| `StringyError`  | Error types with `thiserror`                        |

### Container Module (`src/container/`)

#### `src/container/mod.rs` (73 lines)

Defines the `ContainerParser` trait and format detection.

```rust
pub trait ContainerParser {
    fn detect(data: &[u8]) -> bool where Self: Sized;
    fn parse(&self, data: &[u8]) -> Result<ContainerInfo>;
}

pub fn detect_format(data: &[u8]) -> BinaryFormat { /* ... */ }
pub fn create_parser(format: BinaryFormat) -> Result<Box<dyn ContainerParser>> { /* ... */ }
```

#### `src/container/elf.rs` (627 lines)

ELF binary parser with section weight system:

| Section Pattern      | Weight | Description         |
| -------------------- | ------ | ------------------- |
| `.rodata`            | 10.0   | Read-only data      |
| `.comment`, `.note`  | 9.0    | Build info          |
| `.data.rel.ro`       | 7.0    | Relocated read-only |
| `.data`              | 5.0    | Writable data       |
| `.dynstr`, `.strtab` | 8.0    | String tables       |

#### `src/container/pe.rs` (661 lines)

PE binary parser with Windows-specific handling:

| Section Pattern | Weight  | Description     |
| --------------- | ------- | --------------- |
| `.rdata`        | 10.0    | Read-only data  |
| `.rsrc`         | 9.0     | Resources       |
| `.text`         | 3.0     | Code section    |
| `.data`         | 5.0-7.0 | Data (by perms) |

#### `src/container/macho.rs` (574 lines)

Mach-O parser for macOS/iOS binaries:

| Segment/Section    | Weight | Description   |
| ------------------ | ------ | ------------- |
| `__TEXT,__cstring` | 10.0   | C strings     |
| `__TEXT,__const`   | 9.0    | Constants     |
| `__DATA_CONST`     | 7.0    | Const data    |
| `__DATA,__data`    | 5.0    | Writable data |

### Extraction Module (`src/extraction/`)

#### `src/extraction/mod.rs` (1,498 lines)

Main extraction framework with `StringExtractor` trait and `BasicExtractor`.

```rust
pub trait StringExtractor {
    fn extract(&self, data: &[u8], info: &ContainerInfo) -> Vec<FoundString>;
}

pub struct BasicExtractor {
    ascii_config: AsciiExtractionConfig,
    utf16_config: Utf16ExtractionConfig,
    filter_config: FilterConfig,
}
```

#### `src/extraction/ascii.rs` (820 lines)

ASCII/UTF-8 string extraction with configurable parameters.

#### `src/extraction/utf16.rs` (1,269 lines)

UTF-16LE/BE extraction with confidence scoring and BOM detection.

#### `src/extraction/dedup.rs` (841 lines)

Deduplication with occurrence tracking and score aggregation:

```text
Score = max(base_scores) + 5*(count-1) + 10*(cross_section) + 15*(multi_source) + confidence_boost
```

#### `src/extraction/pe_resources.rs` (1,430 lines)

PE resource extraction (VERSIONINFO, STRINGTABLE, MANIFEST).

#### `src/extraction/filters.rs` (702 lines)

Noise filtering to reduce false positives.

### Classification Module (`src/classification/`)

#### `src/classification/semantic.rs` (1,542 lines)

Semantic classifier with pattern matching:

| Pattern Type   | Implementation                                   |
| -------------- | ------------------------------------------------ |
| URLs           | Regex with safe character filtering              |
| Domains        | TLD validation, DNS format compliance            |
| IPv4/IPv6      | Regex pre-filter + `std::net::IpAddr` validation |
| POSIX Paths    | `/path` format with validation rules             |
| Windows Paths  | `C:\path` format with drive letter validation    |
| UNC Paths      | `\\server\share` format                          |
| Registry Paths | HKEY__/HK_ prefix detection                      |

---

## 4. API Endpoints Analysis

**N/A** - Stringy is a command-line tool, not a web service. The public API is
exposed as a Rust library:

```rust
// Library usage
use stringy::{detect_format, create_parser, BasicExtractor, SemanticClassifier};

let data = std::fs::read("binary")?;
let format = detect_format(&data);
let parser = create_parser(format)?;
let info = parser.parse(&data)?;

let extractor = BasicExtractor::new(/* configs */);
let strings = extractor.extract(&data, &info);

let classifier = SemanticClassifier::new();
for s in &strings {
    let tags = classifier.classify(s);
}
```

---

## 5. Architecture Deep Dive

### Data Flow Pipeline

```text
Binary File
    |
    v
+-------------------+
| Format Detection  |  detect_format() -> BinaryFormat
+-------------------+
    |
    v
+-------------------+
| Container Parser  |  ContainerParser::parse() -> ContainerInfo
| (ELF/PE/Mach-O)   |  - Section analysis with weights
+-------------------+  - Import/export extraction
    |
    v
+-------------------+
| String Extraction |  StringExtractor::extract() -> Vec<FoundString>
| - ASCII/UTF-8     |  - Per-section extraction
| - UTF-16LE/BE     |  - PE resource extraction
+-------------------+
    |
    v
+-------------------+
| Deduplication     |  Deduplicator::deduplicate()
| - Occurrence      |  - Score aggregation
|   tracking        |  - Tag merging
+-------------------+
    |
    v
+-------------------+
| Classification    |  SemanticClassifier::classify()
| - URLs, IPs       |  - Pattern matching
| - Paths, Registry |  - Validation
+-------------------+
    |
    v
+-------------------+
| Ranking           |  (In progress)
| - Score-based     |
|   prioritization  |
+-------------------+
    |
    v
+-------------------+
| Output Formatter  |  (Planned)
| - JSON/JSONL      |
| - Human-readable  |
| - YARA-friendly   |
+-------------------+
```

### Design Patterns

1. **Trait-Based Polymorphism**: `ContainerParser` and `StringExtractor` traits
   enable format extensibility
2. **Builder Pattern**: Extraction configs use builder-style construction
3. **Non-Exhaustive Enums/Structs**: Public API stability via
   `#[non_exhaustive]`
4. **Lazy Static Regex**: Compiled once via `lazy_static!` for performance
5. **Error Propagation**: `thiserror` for structured error handling with context

### Module Dependencies

```text
types.rs (core data structures)
    ^
    |
+---+---+---+---+
|   |   |   |   |
v   v   v   v   v
container/ extraction/ classification/ output/
    |           |              |
    +-----------+--------------+
                |
                v
            lib.rs (re-exports)
                |
                v
            main.rs (CLI)
```

---

## 6. Environment & Setup Analysis

### Prerequisites

- Rust 1.85+ (2024 Edition)
- Cargo (included with Rust)
- Optional: `just` command runner

### Development Setup

```bash
# Clone repository
git clone https://github.com/EvilBit-Labs/Stringy
cd Stringy

# Install tools (via justfile)
just setup  # Installs rustfmt, clippy, llvm-tools-preview, mdformat

# Build
just build       # Debug build
cargo build --release  # Release build

# Test
just test        # Run with nextest
cargo test       # Standard test runner

# Lint
just lint        # Full lint suite (rustfmt, clippy, actionlint, cspell, markdown)
just check       # Pre-commit checks
```

### CI Pipeline (`.github/workflows/ci.yml`)

| Job        | Description                                |
| ---------- | ------------------------------------------ |
| `check`    | Format check, clippy, build                |
| `test`     | Run tests on ubuntu-latest, windows-latest |
| `coverage` | Generate LCOV coverage report              |
| `docs`     | Build mdBook documentation                 |

### Environment Variables

None required for basic operation. CI uses:

- `CARGO_TERM_COLOR=always`
- `RUSTFLAGS=-Cinstrument-coverage` (for coverage)

---

## 7. Technology Stack Breakdown

### Core Dependencies

| Crate         | Version | Purpose                              |
| ------------- | ------- | ------------------------------------ |
| `goblin`      | 0.10.4  | ELF/PE/Mach-O parsing                |
| `pelite`      | 0.10.0  | PE resource extraction               |
| `clap`        | 4.5.54  | CLI argument parsing (derive macros) |
| `regex`       | 1.12.2  | Pattern matching for classification  |
| `lazy_static` | 1.5     | Compile-time regex caching           |
| `serde`       | 1.0.228 | Serialization (JSON output)          |
| `serde_json`  | 1.0.148 | JSON formatting                      |
| `thiserror`   | 2.0.17  | Error handling with derives          |
| `entropy`     | 0.4.2   | Entropy calculation for filtering    |

### Development Dependencies

| Crate       | Version | Purpose                 |
| ----------- | ------- | ----------------------- |
| `criterion` | 0.8.1   | Benchmarking framework  |
| `insta`     | 1.46.0  | Snapshot testing        |
| `tempfile`  | 3.24.0  | Temporary file handling |

### Build Tools

| Tool         | Purpose                    |
| ------------ | -------------------------- |
| `just`       | Cross-platform task runner |
| `nextest`    | Fast test runner           |
| `mdformat`   | Markdown formatting        |
| `mdbook`     | Documentation generation   |
| `cspell`     | Spell checking             |
| `actionlint` | GitHub Actions linting     |

---

## 8. Visual Architecture Diagram

```text
+===========================================================================+
|                              STRINGY ARCHITECTURE                         |
+===========================================================================+

                              +----------------+
                              |  Binary File   |
                              | (ELF/PE/MachO) |
                              +-------+--------+
                                      |
                                      v
+-----------------------------------------------------------------------------+
|                           CONTAINER LAYER                                    |
|  +------------------+  +------------------+  +------------------+            |
|  |    ElfParser     |  |     PeParser     |  |   MachoParser    |            |
|  | - Section scan   |  | - Section scan   |  | - Segment scan   |            |
|  | - Weight assign  |  | - Resource enum  |  | - Load commands  |            |
|  | - Symbol extract |  | - Import/Export  |  | - Symbol extract |            |
|  +------------------+  +------------------+  +------------------+            |
|            \                    |                    /                       |
|             \                   |                   /                        |
|              +------------------+-----------------+                          |
|                                 |                                            |
|                                 v                                            |
|                        +----------------+                                    |
|                        | ContainerInfo  |                                    |
|                        | - Format       |                                    |
|                        | - Sections[]   |                                    |
|                        | - Imports[]    |                                    |
|                        | - Exports[]    |                                    |
|                        +----------------+                                    |
+-----------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------+
|                          EXTRACTION LAYER                                    |
|  +------------------+  +------------------+  +------------------+            |
|  | AsciiExtractor   |  | Utf16Extractor   |  | PeResourceExtractor|          |
|  | - Min/max length |  | - LE/BE support  |  | - VERSIONINFO    |            |
|  | - UTF-8 validate |  | - BOM detection  |  | - STRINGTABLE    |            |
|  | - Confidence     |  | - Confidence     |  | - MANIFEST       |            |
|  +------------------+  +------------------+  +------------------+            |
|            \                    |                    /                       |
|             +-------------------+-------------------+                        |
|                                 |                                            |
|                                 v                                            |
|                        +----------------+                                    |
|                        |  Deduplicator  |                                    |
|                        | - Group by key |                                    |
|                        | - Merge tags   |                                    |
|                        | - Score calc   |                                    |
|                        +----------------+                                    |
+-----------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------+
|                        CLASSIFICATION LAYER                                  |
|                        +--------------------+                                |
|                        | SemanticClassifier |                                |
|                        +--------------------+                                |
|                                 |                                            |
|    +------------+  +--------+  +--------+  +----------+  +----------+       |
|    |    URL     |  | Domain |  |   IP   |  | FilePath |  | Registry |       |
|    | Detection  |  | Check  |  | v4/v6  |  | POSIX/Win|  |   Path   |       |
|    +------------+  +--------+  +--------+  +----------+  +----------+       |
+-----------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------+
|                           OUTPUT LAYER (Planned)                             |
|  +------------------+  +------------------+  +------------------+            |
|  |  JSON Formatter  |  | Human Formatter  |  |  YARA Formatter  |            |
|  +------------------+  +------------------+  +------------------+            |
+-----------------------------------------------------------------------------+
                                      |
                                      v
                              +----------------+
                              |  CLI Output    |
                              | (stdout/file)  |
                              +----------------+
```

---

## 9. Key Insights & Recommendations

### Strengths

1. **Solid Foundation**: Well-structured module organization with clear
   separation of concerns
2. **Type Safety**: Comprehensive error handling with `thiserror` and extensive
   use of Rust's type system
3. **Extensibility**: Trait-based design (`ContainerParser`, `StringExtractor`)
   enables easy format additions
4. **Performance Focus**: Regex caching via `lazy_static!`, section weight
   prioritization
5. **Testing Coverage**: Snapshot tests with `insta`, benchmarks with
   `criterion`, integration tests for all formats
6. **Code Quality**: `#![forbid(unsafe_code)]`, `#![deny(warnings)]`,
   comprehensive linting

### Areas for Completion

1. **CLI Implementation**: `main.rs` is a placeholder - full pipeline
   integration needed
2. **Output Formatters**: `output/mod.rs` is empty - JSON, human-readable, YARA
   outputs pending
3. **Additional Classifiers**: GUIDs, email addresses, Base64, format strings
   documented but not implemented
4. **Ranking System**: Score-based prioritization framework exists but needs
   completion

### Recommendations

1. **Complete CLI Pipeline**: Wire up container parsing -> extraction ->
   classification -> output
2. **Implement Output Formatters**: Start with JSON (most requested for
   pipelines)
3. **Add Missing Classifiers**: GUID and email detection are straightforward
   additions
4. **Performance Benchmarks**: Expand benchmarks to cover full pipeline, not
   just parsing
5. **Documentation**: Complete mdBook documentation with usage examples

### Code Metrics Summary

| Category        | Files | Lines   | Status      |
| --------------- | ----- | ------- | ----------- |
| Source (`src/`) | 19    | 11,153  | Active      |
| Tests           | 10    | 5,254   | Active      |
| Benchmarks      | 3     | ~300    | Active      |
| Documentation   | 5+    | ~1,000  | In Progress |
| **Total**       | ~37   | ~17,707 | In Progress |

### Implementation Status

| Component           | Status      | Completion |
| ------------------- | ----------- | ---------- |
| Format Detection    | Complete    | 100%       |
| Container Parsers   | Complete    | 100%       |
| ASCII Extraction    | Complete    | 100%       |
| UTF-16 Extraction   | Complete    | 100%       |
| PE Resources        | Complete    | 100%       |
| Deduplication       | Complete    | 100%       |
| IP Classification   | Complete    | 100%       |
| URL/Domain          | Complete    | 100%       |
| Path Classification | Complete    | 100%       |
| Registry Paths      | Complete    | 100%       |
| GUIDs/Email/Base64  | Planned     | 0%         |
| Ranking System      | In Progress | 50%        |
| Output Formatters   | Planned     | 0%         |
| CLI Integration     | In Progress | 20%        |

---

_Generated: 2026-01-17_ _Analysis performed on branch:
`17-implement-file-path-classification-for-posix-windows-and-registry-paths`_
