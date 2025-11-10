# Architecture Overview

Stringy is built as a modular Rust library with a clear separation of concerns. The architecture follows a pipeline approach where binary data flows through several processing stages.

## High-Level Architecture

```text
Binary File → Format Detection → Container Parsing → String Extraction → Classification → Ranking → Output
```

## Core Components

### 1. Container Module (`src/container/`) ✅ **Implemented**

Handles binary format detection and parsing using the `goblin` crate with comprehensive section analysis.

- **Format Detection**: Automatically identifies ELF, PE, and Mach-O formats via `goblin::Object::parse()`
- **Section Classification**: Categorizes sections by string likelihood with weighted scoring
- **Metadata Extraction**: Collects imports, exports, and detailed structural information
- **Cross-Platform Support**: Handles platform-specific section characteristics and naming conventions

#### Supported Formats

| Format | Parser        | Key Sections (Weight)                                    | Import/Export Support   |
| ------ | ------------- | -------------------------------------------------------- | ----------------------- |
| ELF    | `ElfParser`   | `.rodata` (10.0), `.comment` (9.0), `.data.rel.ro` (7.0) | ✅ Dynamic & Static     |
| PE     | `PeParser`    | `.rdata` (10.0), `.rsrc` (9.0), read-only `.data` (7.0)  | ✅ Import/Export Tables |
| Mach-O | `MachoParser` | `__TEXT,__cstring` (10.0), `__TEXT,__const` (9.0)        | ✅ Symbol Tables        |

#### Section Weight System

The parsers implement intelligent section prioritization:

```rust
// Example: ELF section weights
".rodata" | ".rodata.str1.*" => 10.0  // Highest priority
".comment" | ".note.*"       => 9.0   // Build info, very likely strings  
".data.rel.ro"              => 7.0   // Read-only data
".data"                     => 5.0   // Writable data
".text"                     => 1.0   // Code sections (low priority)
```

### 2. Extraction Module (`src/extraction/`) 🚧 **Framework Ready**

Implements encoding-aware string extraction algorithms with configurable parameters.

- **ASCII/UTF-8**: Scans for printable character sequences with noise filtering
- **UTF-16**: Detects little-endian and big-endian wide strings with confidence scoring
- **Deduplication**: Canonicalizes strings while preserving complete metadata
- **Section-Aware**: Uses container parser weights to prioritize extraction areas

### 3. Classification Module (`src/classification/`) 🚧 **Types Defined**

Applies semantic analysis to extracted strings with comprehensive tagging system.

- **Pattern Matching**: Uses regex to identify URLs, IPs, paths, GUIDs, etc.
- **Symbol Processing**: Demangles Rust symbols and processes imports/exports
- **Context Analysis**: Considers section context and source type for classification
- **Extensible Tags**: Supports 15+ semantic categories from network indicators to code artifacts

#### Supported Classification Tags

| Category    | Tags                              | Examples                                        |
| ----------- | --------------------------------- | ----------------------------------------------- |
| Network     | `url`, `domain`, `ipv4`, `ipv6`   | `https://api.com`, `example.com`, `192.168.1.1` |
| Filesystem  | `filepath`, `regpath`             | `/usr/bin/app`, `HKEY_LOCAL_MACHINE\...`        |
| Identifiers | `guid`, `email`, `user-agent`     | `{12345678-...}`, `user@domain.com`             |
| Code        | `fmt`, `b64`, `import`, `export`  | `Error: %s`, `SGVsbG8=`, `CreateFileW`          |
| Resources   | `version`, `manifest`, `resource` | `v1.2.3`, XML config, UI strings                |

### 4. Ranking Module (`src/classification/ranking.rs`) 🚧 **Algorithm Designed**

Implements the scoring algorithm to prioritize relevant strings using multiple factors.

```text
Score = SectionWeight + EncodingConfidence + SemanticBoost - NoisePenalty
```

**Scoring Components:**

- **Section Weight**: 1.0-10.0 based on section classification
- **Encoding Confidence**: Higher for clean UTF-8/ASCII vs. noisy UTF-16
- **Semantic Boost**: +20-50 points for URLs, GUIDs, imports/exports
- **Noise Penalty**: -10 to -30 for high entropy, excessive length, repeated patterns

### 5. Output Module (`src/output/`) 🚧 **Interfaces Defined**

Formats results for different use cases with consistent data structures.

- **Human-readable**: Sorted tables with score, offset, section, tags, and truncated strings
- **JSONL**: Complete structured data including all metadata fields
- **YARA**: Properly escaped strings with hex alternatives and confidence grouping

## Data Flow

### 1. Binary Analysis Phase ✅ **Implemented**

```rust
// Format detection using goblin
let format = detect_format(&data);  // Returns BinaryFormat enum
let parser = create_parser(format)?; // Creates appropriate parser

// Container parsing with full metadata extraction
let container_info = parser.parse(&data)?;
// Returns: sections with weights, imports, exports, format info
```

**Current Implementation:**

- Automatic format detection via `goblin::Object::parse()`
- Trait-based parser creation with `Box<dyn ContainerParser>`
- Comprehensive section analysis with classification and weighting
- Complete import/export symbol extraction

### 2. String Extraction Phase 🚧 **Framework Ready**

```rust
// Extract strings from prioritized sections (by weight)
let mut all_strings = Vec::new();
for section in container_info.sections.iter().filter(|s| s.weight > 5.0) {
    let strings = extract_strings(&data, &section, &config)?;
    all_strings.extend(strings);
}

// Include import/export names as high-value strings
all_strings.extend(extract_symbol_strings(&container_info));

// Deduplicate while preserving all metadata
let unique_strings = deduplicate(all_strings);
```

### 3. Classification Phase 🚧 **Types Ready**

```rust
// Apply semantic classification with context awareness
for string in &mut unique_strings {
    let context = StringContext {
        section_type: string.section_type,
        source: string.source,
        encoding: string.encoding,
    };
    
    string.tags = classify_string(&string.text, &context);
    string.score = calculate_score(&string, &context);
}
```

### 4. Output Phase 🚧 **Interfaces Defined**

```rust
// Sort by relevance score (descending)
unique_strings.sort_by_key(|s| std::cmp::Reverse(s.score));

// Apply user filters and limits
let filtered = apply_filters(&unique_strings, &config);

// Format according to requested output type
let output = match config.format {
    OutputFormat::Human => format_human_readable(&filtered),
    OutputFormat::Json => format_jsonl(&filtered),
    OutputFormat::Yara => format_yara_rules(&filtered),
};
```

## Current Implementation Details

### Container Parser Architecture

The container parsing system is fully implemented with a trait-based design:

```rust
pub trait ContainerParser {
    fn detect(data: &[u8]) -> bool
    where
        Self: Sized;
    fn parse(&self, data: &[u8]) -> Result<ContainerInfo>;
}
```

**Format Detection Pipeline:**

1. `detect_format()` uses `goblin::Object::parse()` to identify format
2. `create_parser()` returns appropriate `Box<dyn ContainerParser>`
3. Parser extracts sections, imports, exports with full metadata

### Section Classification System

Each parser implements intelligent section classification:

```rust
// ELF Example
fn classify_section(section: &SectionHeader, name: &str) -> SectionType {
    if section.sh_flags & SHF_EXECINSTR != 0 {
        return SectionType::Code;
    }

    match name {
        ".rodata" | ".rodata.str1.*" => SectionType::StringData,
        ".comment" | ".note.*" => SectionType::StringData,
        ".data.rel.ro" => SectionType::ReadOnlyData,
        // ... more classifications
    }
}
```

**Weight Calculation:**

- String data sections: 8.0-10.0 (highest priority)
- Read-only data: 7.0
- Resources: 8.0-9.0
- Writable data: 5.0
- Code: 1.0 (lowest priority)

### Symbol Extraction

All parsers extract import/export information:

- **ELF**: Dynamic symbol table (`dynsyms`) and static symbols (`syms`)
- **PE**: Import/export tables with library names and ordinals
- **Mach-O**: Symbol tables with undefined/defined symbol filtering

### Data Structures

Core types are fully defined and serializable:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundString {
    pub text: String,
    pub encoding: Encoding,
    pub offset: u64,
    pub rva: Option<u64>,
    pub section: Option<String>,
    pub length: u32,
    pub tags: Vec<Tag>,
    pub score: i32,
    pub source: StringSource,
}
```

**Tag System**: 15+ semantic categories ready for classification **Error Handling**: Comprehensive `StringyError` enum with context **Cross-Platform**: Handles platform-specific binary characteristics

## Key Design Decisions

### Memory Efficiency

- Uses memory mapping (`memmap2`) for large files
- Lazy evaluation for optional features
- Efficient regex compilation and caching

### Error Handling

- Comprehensive error types with context
- Graceful degradation for partially corrupted binaries
- Clear error messages for debugging

### Extensibility

- Trait-based architecture for easy format addition
- Pluggable classification systems
- Configurable output formats

### Performance

- Section-aware extraction reduces scan time
- Regex caching for repeated pattern matching
- Parallel processing where beneficial

## Module Dependencies

```text
main.rs
├── lib.rs (public API)
├── types.rs (core data structures)
├── container/
│   ├── mod.rs (format detection)
│   ├── elf.rs (ELF parser)
│   ├── pe.rs (PE parser)
│   └── macho.rs (Mach-O parser)
├── extraction/
│   ├── mod.rs (extraction traits)
│   ├── ascii.rs (ASCII/UTF-8)
│   ├── utf16.rs (UTF-16LE/BE)
│   └── dedup.rs (deduplication)
├── classification/
│   ├── mod.rs (classification framework)
│   ├── semantic.rs (pattern matching)
│   ├── symbols.rs (symbol processing)
│   └── ranking.rs (scoring algorithm)
└── output/
    ├── mod.rs (output traits)
    ├── json.rs (JSONL format)
    ├── human.rs (table format)
    └── yara.rs (YARA format)
```

## External Dependencies

### Core Dependencies

- `goblin`: Multi-format binary parsing
- `serde` + `serde_json`: Serialization
- `thiserror`: Error handling
- `clap`: CLI argument parsing

### Optional Dependencies

- `regex`: Pattern matching for classification
- `rustc-demangle`: Rust symbol demangling
- `memmap2`: Memory-mapped file I/O
- `pelite`: Enhanced PE resource extraction

## Testing Strategy

### Unit Tests

- Each module has comprehensive unit tests
- Mock data for parser testing
- Edge case coverage for string extraction

### Integration Tests

- End-to-end CLI functionality
- Real binary file testing
- Cross-platform validation

### Performance Tests

- Benchmarks for critical path components
- Memory usage profiling
- Large file handling validation

This architecture provides a solid foundation for reliable, efficient, and extensible binary string analysis.
