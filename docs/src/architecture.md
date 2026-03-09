# Architecture Overview

Stringy is built as a modular Rust library with a clear separation of concerns. The architecture follows a pipeline approach where binary data flows through several processing stages.

## High-Level Architecture

```text
Binary File -> Format Detection -> Container Parsing -> String Extraction -> Deduplication -> Classification -> Ranking -> Output
```

## Core Components

### 1. Container Module (`src/container/`)

Handles binary format detection and parsing using the `goblin` crate with comprehensive section analysis.

- **Format Detection**: Automatically identifies ELF, PE, and Mach-O formats via `goblin::Object::parse()`
- **Section Classification**: Categorizes sections by string likelihood with weighted scoring
- **Metadata Extraction**: Collects imports, exports, and detailed structural information
- **Cross-Platform Support**: Handles platform-specific section characteristics and naming conventions

#### Supported Formats

| Format | Parser        | Key Sections (Weight)                                    | Import/Export Support |
| ------ | ------------- | -------------------------------------------------------- | --------------------- |
| ELF    | `ElfParser`   | `.rodata` (10.0), `.comment` (9.0), `.data.rel.ro` (7.0) | Dynamic and static    |
| PE     | `PeParser`    | `.rdata` (10.0), `.rsrc` (9.0), read-only `.data` (7.0)  | Import/export tables  |
| Mach-O | `MachoParser` | `__TEXT,__cstring` (10.0), `__TEXT,__const` (9.0)        | Symbol tables         |

#### Section Weight System

Container parsers assign weights (1.0-10.0) to sections based on how likely they are to contain meaningful strings. Higher weights indicate higher-value sections. For example, `.rodata` (read-only data) receives a weight of 10.0, while `.text` (executable code) receives 1.0.

### 2. Extraction Module (`src/extraction/`)

Implements encoding-aware string extraction algorithms with configurable parameters.

- **ASCII/UTF-8**: Scans for printable character sequences with noise filtering
- **UTF-16**: Detects little-endian and big-endian wide strings with confidence scoring
- **PE Resources**: Extracts version info, manifests, and string table resources from PE binaries
- **Mach-O Load Commands**: Extracts strings from Mach-O load commands (dylib paths, rpaths)
- **Deduplication**: Groups strings by (text, encoding) keys, preserves all occurrence metadata, merges tags using set union, and calculates combined scores with occurrence-based bonuses
- **Noise Filters**: Applies configurable filters to reduce false positives
- **Section-Aware**: Uses container parser weights to prioritize extraction areas

#### Deduplication System

The deduplication module (`src/extraction/dedup/`) provides comprehensive string deduplication:

- **Grouping Strategy**: Strings are grouped by `(text, encoding)` tuple, ensuring UTF-8 and UTF-16 versions are kept separate
- **Occurrence Preservation**: All occurrence metadata (offset, RVA, section, source, tags, score, confidence) is preserved
- **Tag Merging**: Tags from all occurrences are merged using `HashSet` for uniqueness, then converted to a sorted `Vec<Tag>`
- **Combined Scoring**: Calculates combined scores using a base score (maximum across occurrences) plus bonuses for multiple occurrences, cross-section appearances, and multi-source appearances

### 3. Classification Module (`src/classification/`)

Applies semantic analysis to extracted strings with comprehensive tagging system.

- **Pattern Matching**: Uses regex to identify URLs, IPs, domains, paths, GUIDs, emails, format strings, base64, user-agent strings, and version strings
- **Symbol Processing**: Demangles Rust symbols and processes imports/exports
- **Context Analysis**: Considers section context and source type for classification

#### Supported Classification Tags

| Category    | Tags                                                                        | Examples                                        |
| ----------- | --------------------------------------------------------------------------- | ----------------------------------------------- |
| Network     | `url`, `domain`, `ipv4`, `ipv6`                                             | `https://api.com`, `example.com`, `192.168.1.1` |
| Filesystem  | `filepath`, `regpath`, `dylib-path`, `rpath`, `rpath-var`, `framework-path` | `/usr/bin/app`, `HKEY_LOCAL_MACHINE\...`        |
| Identifiers | `guid`, `email`, `user-agent-ish`                                           | `{12345678-...}`, `user@domain.com`             |
| Code        | `fmt`, `b64`, `import`, `export`, `demangled`                               | `Error: %s`, `SGVsbG8=`, `CreateFileW`          |
| Resources   | `version`, `manifest`, `resource`                                           | `v1.2.3`, XML config, UI strings                |

### 4. Ranking Module (`src/classification/ranking.rs`)

Implements the scoring algorithm to prioritize relevant strings using multiple factors:

- **Section Weight**: Based on the section's classification (higher weights for string-oriented sections like `.rodata`)
- **Semantic Boost**: Bonus points for strings with recognized semantic tags (URLs, GUIDs, paths, etc.)
- **Noise Penalty**: Penalty for characteristics indicating noise (low confidence, repetitive patterns, high entropy)

The internal score is then mapped to a display score (0-100) using a band-mapping system. See [Output Formats](./output-formats.md) for the display-score band table.

### 5. Output Module (`src/output/`)

Formats results for different use cases:

- **Table** (`src/output/table/`): TTY-aware output with color-coded scores, or plain text when piped. Columns: String, Tags, Score, Section.
- **JSON** (`src/output/json.rs`): JSONL format with complete structured data including all metadata fields
- **YARA** (`src/output/yara/`): Properly escaped strings with appropriate modifiers and long-string skipping

### 6. Pipeline Module (`src/pipeline/`)

Orchestrates the entire flow from file reading through output:

- **Configuration** (`src/pipeline/config.rs`): `PipelineConfig` and related types
- **Filtering** (`src/pipeline/filter.rs`): Post-extraction filtering by tags, encoding, and top-N
- **Score Normalization** (`src/pipeline/normalizer.rs`): Maps internal scores to display scores
- **Orchestration** (`src/pipeline/mod.rs`): `Pipeline::run` drives the full pipeline

## Data Flow

### 1. Binary Analysis Phase

The pipeline reads the file, detects the binary format via `goblin`, and dispatches to the appropriate container parser (ELF, PE, or Mach-O). The parser returns a `ContainerInfo` struct containing sections with weights, imports, and exports. Unknown or unparseable formats fall back to unstructured raw byte scanning.

### 2. String Extraction Phase

Strings are extracted from each section using encoding-specific extractors (ASCII, UTF-8, UTF-16LE, UTF-16BE). Import and export symbol names are included as high-value strings. PE resources (version info, manifests, string tables) and Mach-O load command strings are also extracted. Results are then deduplicated by grouping on `(text, encoding)`.

### 3. Classification Phase

Each string is passed through pattern matchers that assign semantic tags based on content. Rust mangled symbols are demangled. The ranking algorithm then computes a score for each string combining section weight, semantic boost, and noise penalty.

### 4. Output Phase

Strings are sorted by score (descending), filtered according to user options (tags, encoding, top-N), and formatted for the selected output mode (table, JSON, or YARA).

## Data Structures

Core types are defined in `src/types/mod.rs`:

```rust
pub struct FoundString {
    pub text: String,
    pub original_text: Option<String>, // pre-demangled form
    pub encoding: Encoding,
    pub offset: u64,
    pub rva: Option<u64>,
    pub section: Option<String>,
    pub length: u32,
    pub tags: Vec<Tag>,
    pub score: i32,
    pub section_weight: Option<i32>, // debug only
    pub semantic_boost: Option<i32>, // debug only
    pub noise_penalty: Option<i32>,  // debug only
    pub display_score: Option<i32>,  // debug only
    pub source: StringSource,
    pub confidence: f32,
}
```

## Key Design Decisions

### Error Handling

- Comprehensive error types with context via `thiserror`
- Graceful degradation for partially corrupted binaries
- Unknown formats fall back to raw byte scanning rather than erroring

### Extensibility

- Trait-based architecture for easy format addition
- Pluggable classification systems
- Configurable output formats

### Performance

- Section-aware extraction reduces scan time
- Regex caching via `once_cell::sync::Lazy` for repeated pattern matching
- Weight-based prioritization avoids scanning low-value sections

## Module Dependencies

```text
main.rs
+-- lib.rs (public API, re-exports)
+-- types/
|   +-- mod.rs (core data structures: Tag, FoundString, Encoding, etc.)
|   +-- error.rs (StringyError, Result)
+-- container/
|   +-- mod.rs (format detection, ContainerParser trait)
|   +-- elf.rs (ELF parser)
|   +-- pe.rs (PE parser)
|   +-- macho.rs (Mach-O parser)
+-- extraction/
|   +-- mod.rs (extraction orchestration)
|   +-- ascii/ (ASCII/UTF-8 extraction)
|   +-- utf16/ (UTF-16LE/BE extraction with confidence scoring)
|   +-- dedup/ (deduplication with scoring)
|   +-- filters/ (noise filter implementations)
|   +-- pe_resources/ (PE version info, manifests, string tables)
|   +-- macho_load_commands.rs (Mach-O load command strings)
+-- classification/
|   +-- mod.rs (classification framework)
|   +-- patterns/ (regex-based pattern matching)
|   +-- symbols.rs (symbol processing and demangling)
|   +-- ranking.rs (scoring algorithm)
+-- output/
|   +-- mod.rs (OutputFormat, OutputMetadata, formatting dispatch)
|   +-- json.rs (JSONL format)
|   +-- table/ (TTY and plain text table formatting)
|   +-- yara/ (YARA rule generation with escaping)
+-- pipeline/
    +-- mod.rs (Pipeline::run orchestration)
    +-- config.rs (PipelineConfig, FilterConfig, EncodingFilter)
    +-- filter.rs (post-extraction filtering)
    +-- normalizer.rs (score band mapping)
```

## External Dependencies

### Core Dependencies

- `goblin` - Multi-format binary parsing (ELF, PE, Mach-O)
- `pelite` - PE resource extraction (version info, manifests, string tables)
- `serde` + `serde_json` - Serialization
- `thiserror` - Error handling
- `clap` - CLI argument parsing
- `regex` - Pattern matching for classification
- `rustc-demangle` - Rust symbol demangling
- `indicatif` - Progress bars and spinners for CLI output
- `tempfile` - Temporary file creation for stdin-to-Pipeline bridging
- `once_cell` - Lazy-initialized static regex patterns
- `patharg` - Input argument handling (file path or stdin)

## Testing Strategy

### Unit Tests

- Each module has comprehensive unit tests
- Mock data for parser testing
- Edge case coverage for string extraction

### Integration Tests

- End-to-end CLI functionality via `assert_cmd`
- Real binary file testing with compiled fixtures
- Snapshot testing via `insta`
- Cross-platform validation

### Performance Tests

- Benchmarks via `criterion` in `benches/`
