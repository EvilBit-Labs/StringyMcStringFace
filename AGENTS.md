# AI Agent Guidelines for Stringy

## Critical Rules

**These rules are non-negotiable. Violations will cause CI failures.**

1. **No `unsafe` code** - `#![forbid(unsafe_code)]` enforced
2. **Zero warnings** - `cargo clippy -- -D warnings` must pass
3. **ASCII only** - No emojis, em-dashes, smart quotes, or Unicode punctuation (except when explicitly testing or working with Unicode strings or emojis)
4. **File size limit** - Keep files under 500 lines; split larger files
5. **No blanket `#[allow]`** - Any `allow` requires inline justification

## Project Summary

Stringy extracts meaningful strings from ELF, PE, and Mach-O binaries using format-specific knowledge and semantic classification. Unlike standard `strings`, it is section-aware and semantically intelligent.

- **Rust**: Edition 2024, MSRV 1.91
- **Data flow**: Binary -> Format Detection -> Container Parsing -> String Extraction -> Deduplication -> Classification -> Ranking -> Output

## Module Structure

| Module            | Purpose                                                          |
| ----------------- | ---------------------------------------------------------------- |
| `container/`      | Format detection, section analysis, imports/exports via `goblin` |
| `extraction/`     | ASCII/UTF-8/UTF-16 extraction, deduplication, PE resources       |
| `classification/` | Semantic tagging (URLs, IPs, domains, paths, GUIDs), ranking     |
| `output/`         | Formatters: `json/`, `table/` (tty/plain), `yara/`               |
| `types/`          | Core data structures, error handling with `thiserror`            |

## Key Patterns

### Section Weights

Container parsers assign weights (1.0-10.0) based on string likelihood. Higher = more valuable. See existing parsers in `container/*.rs` for reference values.

### Error Handling

Use `thiserror` with detailed context. Include offsets, section names, and file paths in error messages. Convert external errors with `From` implementations.

### Public API Structs

Use `#[non_exhaustive]` for public structs and provide explicit constructors.

## Development Commands

```bash
just check      # Pre-commit: fmt + lint + test
just test       # Run tests with nextest
just lint       # Full lint suite
just fix        # Auto-fix clippy warnings
just ci-check   # Full CI suite locally
just build      # Debug build
just run <args> # Run stringy with arguments
just bench      # Run benchmarks
just format     # Format all (Rust, JSON, YAML, Markdown, Justfile)
```

## Testing

- Use `insta` for snapshot testing
- Binary fixtures in `tests/fixtures/`
- Integration tests named `integration_*.rs`

## Imports

Import from `stringy::extraction` or `stringy::types`, not deeply nested paths. Re-exports are in `lib.rs`.

## Key Dependencies

- `goblin` - Binary format parsing (ELF, PE, Mach-O)
- `pelite` - PE resource extraction
- `thiserror` - Error type definitions
- `insta` - Snapshot testing (dev)
- `criterion` - Benchmarking (dev)

## Adding Features

**New semantic tag**: Add variant to `Tag` enum in `types.rs`, implement pattern in `classification/semantic.rs`

**New section weight**: Add match arm in the relevant `container/*.rs` parser

**New string extractor**: Follow patterns in `extraction/` module
