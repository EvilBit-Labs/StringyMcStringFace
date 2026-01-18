# Copilot Instructions for Stringy

## Project Overview

Stringy is a **smarter strings tool** for extracting meaningful strings from ELF, PE, and Mach-O binaries using format-specific knowledge and semantic classification. Unlike the standard `strings` command, Stringy is data-structure aware, section-aware, and semantically intelligent.

## Architecture & Data Flow

```text
Binary -> Format Detection (goblin) -> Container Parsing -> String Extraction -> Deduplication -> Classification -> Ranking -> Output
```

### Module Organization

- **`container/`** \[COMPLETE\]: Format detection (ELF/PE/Mach-O), section analysis, imports/exports via `goblin`
- **`extraction/`** \[COMPLETE\]: ASCII/UTF-8/UTF-16 string extraction, deduplication, PE resources
- **`classification/`** \[PARTIAL\]: Semantic tagging (URLs, IPs, domains, paths, GUIDs, etc.)
- **`output/`** \[PLANNED\]: JSON/human-readable/YARA-friendly formatting
- **`types/`** \[COMPLETE\]: Core data structures (`FoundString`, `ContainerInfo`, etc.), error handling

## Critical Coding Standards

### Zero Tolerance Policies

- **No `unsafe` code**: `#![forbid(unsafe_code)]` enforced at package level
- **Zero warnings**: `cargo clippy -- -D warnings` must pass (`#![deny(warnings)]` enforced)
- **Rust 2024 Edition**: MSRV 1.85+, always use latest edition features
- **File size limit**: Keep files \<=500-600 lines; split larger files into focused modules
- **No blanket `#[allow]`**: Any `allow` attribute requires inline justification and cannot apply to entire files/modules
- **Character restrictions**: Never use emojis, em-dashes, or other non-Latin characters in code or documentation. Use standard ASCII punctuation (hyphens, quotes, etc.)

### Error Handling with `thiserror`

Use structured errors with detailed context (see `src/types.rs`):

```rust
#[derive(Debug, Error)]
pub enum StringyError {
    #[error("Binary parsing error: {0}")]
    ParseError(String),

    #[error("Invalid encoding at offset {offset}")]
    EncodingError { offset: u64 },
}
```

Convert external errors with `From` implementations. Provide offsets, section names, and file paths in error messages.

## Key Implementation Patterns

### Section Weight System

Container parsers assign weights (1.0-10.0) to sections based on string likelihood:

```rust
// ELF example from container/elf.rs
".rodata" | ".rodata.str1.*" => 10.0  // Highest priority
".comment" | ".note.*"       => 9.0   // Build info
".data.rel.ro"               => 7.0   // Read-only data
".data"                      => 5.0   // Writable data (lower priority)
```

**Pattern**: Use match expressions with fallthrough to assign weights; higher = more likely to contain meaningful strings.

### String Deduplication (`extraction/dedup.rs`)

Strings are grouped by `(text, encoding)` tuple in a `HashMap<(String, Encoding), Vec<StringOccurrence>>`:

- **Preserve all occurrences**: Each occurrence captures offset, RVA, section, source, tags, score, confidence
- **Tag merging**: Union all tags via `HashSet`, then sort
- **Combined scoring formula**:
  ```text
  base_score = max(occurrence.original_score)
  occurrence_bonus = 5 * (count - 1)
  cross_section_bonus = 10 (if >1 unique section)
  multi_source_bonus = 15 (if >1 unique StringSource)
  confidence_boost = (max_confidence * 10.0) as i32
  ```

### Non-Exhaustive Structs

Use `#[non_exhaustive]` for public API structs like `ContainerInfo` and provide explicit constructors (see `types.rs`):

```rust
#[non_exhaustive]
pub struct ContainerInfo { /* fields */ }

impl ContainerInfo {
    pub fn new(format: BinaryFormat, sections: Vec<SectionInfo>, ...) -> Self { ... }
}
```

## Testing Standards

- **Snapshot testing**: Use `insta` for output verification (`tests/integration_*.rs`)
- **Fixtures**: Binary test fixtures in `tests/fixtures/` (see `fixtures/README.md`)
- **Integration tests**: Named `test_*.rs` or `integration_*.rs` in `tests/`
- **Run tests**: `just test` (uses `cargo nextest`)

Example pattern from `tests/integration_elf.rs`:

```rust
fn get_fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn test_elf_import_export_extraction() {
    let data = fs::read(&get_fixture_path("test_binary_elf")).expect("...");
    let parser = ElfParser::new();
    let info = parser.parse(&data).expect("...");
    // Verify imports/exports with specific assertions
}
```

## Development Workflow

### Common Commands (`justfile`)

**Setup**: `just setup` (installs rustfmt, clippy, llvm-tools-preview, mdformat)

**Development**:

- `just build` - Debug build
- `just test` - Run tests with nextest
- `just lint` - Full lint suite (rustfmt, clippy, actionlint, cspell, markdown)
- `just check` - Pre-commit checks + lint
- `just run <file>` - Run binary against test file

**Code Quality**:

- `just fmt` - Format Rust/markdown/YAML/JSON
- `just fix` - Auto-fix clippy warnings with `--fix`
- `just coverage` - Generate LCOV coverage report

**CI Parity**: `just ci-check` (runs full CI suite locally)

### Windows vs Unix

The `justfile` uses OS annotations (`[windows]`/`[unix]`) for cross-platform compatibility. PowerShell on Windows, bash on Unix.

## Dependencies & Crates

**Core parsing**: `goblin` (ELF/PE/Mach-O), `pelite` (PE resources)\
**CLI**: `clap` with derive macros\
**Error handling**: `thiserror`\
**Serialization**: `serde`, `serde_json`\
**Regex**: `regex` for classification\
**Testing**: `insta` (snapshots), `criterion` (benchmarks), `tempfile`

## Import Conventions

- Re-export commonly used types in `lib.rs` for ergonomic imports
- Import from `stringy::extraction` or `stringy::types`, not deeply nested paths
- Within `extraction/mod.rs`, do NOT import locally-defined types; downstream code imports from `stringy::extraction`

## What NOT to Do

- Don't use `async` (this is a synchronous CLI tool)
- Don't add `unsafe` blocks (forbidden)
- Don't ignore clippy warnings (they're errors)
- Don't create files >600 lines without splitting
- Don't use blanket `#[allow]` on modules/files
- Don't guess at section weights (refer to existing parsers in `container/`)

## Current Implementation Status

**Complete**:

- ELF/PE/Mach-O format detection and parsing
- ASCII, UTF-8, UTF-16LE/BE string extraction
- PE resource string extraction (VERSIONINFO, STRINGTABLE, MANIFEST)
- String deduplication with occurrence tracking
- IPv4/IPv6, URL, domain classification

**In Progress**:

- Full semantic classification suite (GUIDs, paths, format strings, Base64)
- Ranking/scoring algorithm implementation
- CLI (`main.rs` is placeholder)
- Output formatters (JSON, YARA-friendly, human-readable)

## Quick Reference Examples

**Adding a new section weight** (in `container/elf.rs`, `pe.rs`, or `macho.rs`):

```rust
let weight = match section_name {
    ".mydata" => 8.0,  // New section type
    _ => existing_match_arms
};
```

**Extracting strings from a section**:

```rust
use stringy::extraction::{extract_ascii_strings, AsciiExtractionConfig};
let config = AsciiExtractionConfig { min_length: 4, max_length: 1024 };
let strings = extract_ascii_strings(&section_data, &config);
```

**Adding a semantic tag**:

1. Add variant to `Tag` enum in `types.rs`
2. Implement pattern matching in `classification/semantic.rs`
3. Update deduplication tag merging if needed
