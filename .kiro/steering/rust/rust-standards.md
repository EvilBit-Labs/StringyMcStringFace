---
inclusion: fileMatch
fileMatchPattern: ['**/*.rs']
---

# Rust Coding Standards for Stringy

## Language and Edition

- Always use **Rust 2024 Edition** (MSRV: 1.91+) as specified in [Cargo.toml](mdc:Cargo.toml)
- Follow the package configuration in [Cargo.toml](mdc:Cargo.toml) with `unsafe_code = "forbid"` and `warnings = "deny"`

## Code Quality Requirements

- **Zero warnings policy**: All code must pass `cargo clippy -- -D warnings`
- **No unsafe code**: `unsafe_code = "forbid"` is enforced at package level
- **Formatting**: Use standard `rustfmt` with project-specific line length
- **Error Handling**: Use `thiserror` for structured errors
- **Synchronous Design**: This is a synchronous CLI tool - no async runtime needed
- **Focused and Manageable Files**: Source files should be focused and manageable. Large files should be split into smaller, more focused files; no larger than 500-600 lines, when possible.
- **Strictness**: `warnings = "deny"` enforced at package level; any use of `allow` **MUST** be accompanied by a justification in the code and cannot be applied to entire files or modules.

## Code Organization

- Use trait-based interfaces for format parsers (`ContainerParser` trait)
- Implement comprehensive error handling with `thiserror`
- Use strongly-typed structures with `serde` for serialization
- Organize by domain: `container/`, `extraction/`, `classification/`, `output/`, `types/`

## Module Structure

- **container/**: Binary format detection and parsing (ELF, PE, Mach-O)
- **extraction/**: String extraction algorithms
- **classification/**: Semantic analysis and tagging
- **output/**: Result formatting (JSON, human-readable, YARA-friendly)
- **types/**: Core data structures and error handling

## Testing Requirements

- Include comprehensive tests with `insta` for snapshot testing
- Test binary format detection and parsing
- Test string extraction from various formats
- Use `tempfile` for temporary binary files in tests
