# Architecture Overview

Stringy is built as a modular Rust library with a clear separation of concerns. The architecture follows a pipeline approach where binary data flows through several processing stages.

## High-Level Architecture

```text
Binary File → Format Detection → Container Parsing → String Extraction → Classification → Ranking → Output
```

## Core Components

### 1. Container Module (`src/container/`)

Handles binary format detection and parsing using the `goblin` crate.

- **Format Detection**: Automatically identifies ELF, PE, and Mach-O formats
- **Section Classification**: Categorizes sections by string likelihood
- **Metadata Extraction**: Collects imports, exports, and structural information

#### Supported Formats

| Format | Parser        | Key Sections                          |
| ------ | ------------- | ------------------------------------- |
| ELF    | `ElfParser`   | `.rodata`, `.data.rel.ro`, `.comment` |
| PE     | `PeParser`    | `.rdata`, `.rsrc`, version info       |
| Mach-O | `MachoParser` | `__TEXT,__cstring`, `__DATA_CONST`    |

### 2. Extraction Module (`src/extraction/`)

Implements encoding-aware string extraction algorithms.

- **ASCII/UTF-8**: Scans for printable character sequences
- **UTF-16**: Detects little-endian and big-endian wide strings
- **Deduplication**: Canonicalizes strings while preserving metadata

### 3. Classification Module (`src/classification/`)

Applies semantic analysis to extracted strings.

- **Pattern Matching**: Uses regex to identify URLs, IPs, paths, etc.
- **Symbol Processing**: Demangles Rust symbols and processes imports/exports
- **Context Analysis**: Considers section context for classification

### 4. Ranking Module (`src/classification/ranking.rs`)

Implements the scoring algorithm to prioritize relevant strings.

```text
Score = SectionWeight + EncodingConfidence + SemanticBoost - NoisePenalty
```

### 5. Output Module (`src/output/`)

Formats results for different use cases.

- **Human-readable**: Sorted tables for interactive analysis
- **JSONL**: Structured data for automation
- **YARA**: Escaped strings for rule creation

## Data Flow

### 1. Binary Analysis Phase

```rust
// Format detection
let format = detect_format(&data);
let parser = create_parser(format)?;

// Container parsing
let container_info = parser.parse(&data)?;
```

### 2. String Extraction Phase

```rust
// Extract strings from prioritized sections
for section in container_info.sections {
    let strings = extract_strings(&data, &section)?;
    all_strings.extend(strings);
}

// Deduplicate while preserving metadata
let unique_strings = deduplicate(all_strings);
```

### 3. Classification Phase

```rust
// Apply semantic classification
for string in &mut unique_strings {
    string.tags = classify_string(&string.text, &string.context);
    string.score = calculate_score(&string);
}
```

### 4. Output Phase

```rust
// Sort by relevance and format output
unique_strings.sort_by_key(|s| -s.score);
let output = format_output(&unique_strings, &config);
```

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
