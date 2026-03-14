# Contributing to Stringy

We welcome contributions to Stringy! This guide will help you get started with development, testing, and submitting changes.

## Development Setup

### Prerequisites

- **Rust**: 1.91 or later (MSRV - Minimum Supported Rust Version)
- **Git**: For version control
- **just**: Task runner (install via `cargo install just` or your package manager)
- **mise**: Tool version manager (manages Zig and other dev tools)
- **Zig**: Cross-compiler for test fixtures (managed by mise)

### Clone and Setup

```bash
git clone https://github.com/EvilBit-Labs/Stringy
cd Stringy

# Generate test fixtures (ELF/PE/Mach-O via Zig cross-compilation)
just gen-fixtures

# Run the full check suite
just check
```

### Development Tools

Install recommended tools for development:

```bash
# Code formatting
rustup component add rustfmt

# Linting
rustup component add clippy

# Documentation
cargo install mdbook

# Test runner (required by just recipes)
cargo install cargo-nextest

# Coverage (optional)
cargo install cargo-llvm-cov
```

## Project Structure

```text
src/
+-- main.rs              # CLI entry point (thin wrapper)
+-- lib.rs               # Library root and public API re-exports
+-- types/
|   +-- mod.rs           # Core data structures (Tag, FoundString, Encoding, etc.)
|   +-- error.rs         # StringyError enum, Result alias
+-- container/
|   +-- mod.rs           # Format detection, ContainerParser trait
|   +-- elf.rs           # ELF parser
|   +-- pe.rs            # PE parser
|   +-- macho.rs         # Mach-O parser
+-- extraction/
|   +-- mod.rs           # Extraction orchestration
|   +-- ascii/           # ASCII/UTF-8 extraction
|   +-- utf16/           # UTF-16LE/BE extraction
|   +-- dedup/           # Deduplication with scoring
|   +-- filters/         # Noise filter implementations
|   +-- pe_resources/    # PE version info, manifests, string tables
+-- classification/
|   +-- mod.rs           # Classification framework
|   +-- patterns/        # Regex-based pattern matching
|   +-- symbols.rs       # Symbol processing and demangling
|   +-- ranking.rs       # Scoring algorithm
+-- output/
|   +-- mod.rs           # OutputFormat, OutputMetadata, dispatch
|   +-- json.rs          # JSONL format
|   +-- table/           # TTY and plain text table formatting
|   +-- yara/            # YARA rule generation
+-- pipeline/
    +-- mod.rs           # Pipeline::run orchestration
    +-- config.rs        # PipelineConfig, FilterConfig, EncodingFilter
    +-- filter.rs        # Post-extraction filtering
    +-- normalizer.rs    # Score band mapping

tests/
+-- integration_cli.rs           # CLI argument and flag tests
+-- integration_cli_errors.rs    # CLI error handling tests
+-- integration_elf.rs           # ELF-specific tests
+-- integration_pe.rs            # PE-specific tests
+-- integration_macho.rs         # Mach-O-specific tests
+-- integration_extraction.rs    # Extraction tests
+-- integration_flows_1_5.rs     # End-to-end flow tests (1-5)
+-- integration_flows_6_8.rs     # End-to-end flow tests (6-8)
+-- ... (additional test files)
+-- fixtures/                    # Test binary files (flat structure)
+-- snapshots/                   # Insta snapshot files

docs/
+-- src/                 # mdbook documentation
+-- book.toml            # Documentation config
```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-description
```

### 2. Make Changes

Use `just` recipes for development commands:

```bash
# Format code
just format

# Lint (clippy with -D warnings)
just lint

# Run tests
just test

# Full pre-commit check (fmt + lint + test)
just check

# Full CI suite locally
just ci-check
```

### 3. Test Your Changes

```bash
# Generate fixtures if needed
just gen-fixtures

# Run all tests
just test

# Run a specific test
cargo nextest run test_name

# Regenerate snapshots after changing test_binary.c
INSTA_UPDATE=always cargo nextest run
```

### 4. Update Documentation

If your changes affect the public API or add new features:

```bash
# Update API docs
cargo doc --open

# Update user documentation
cd docs
mdbook serve --open
```

## Coding Standards

### Rust Style

- Use `cargo fmt` for formatting
- Follow `cargo clippy` recommendations (warnings are errors)
- No `unsafe` code (`#![forbid(unsafe_code)]` is enforced)
- Zero warnings policy
- ASCII only in source code (no emojis, em-dashes, smart quotes)
- Files under 500 lines; split larger files into module directories
- No blanket `#[allow]` without inline justification

### Testing

Write comprehensive tests:

- Use `insta` for snapshot testing
- Binary fixtures in `tests/fixtures/` (flat structure)
- Integration tests use two naming patterns: `integration_*.rs` and `test_*.rs`
- Use `assert_cmd` for CLI testing (note: `assert_cmd` is non-TTY)

## Contribution Areas

### High-Priority Areas

1. **String Extraction Engine** - UTF-16 detection improvements, noise filtering enhancements
2. **Classification System** - New semantic patterns, improved confidence scoring
3. **Output Formats** - Customization options, additional format support

### Getting Started Ideas

- Add new semantic patterns (email formats, crypto constants)
- Improve test coverage
- Enhance error messages
- Add documentation examples

## Submitting Changes

### Pull Request Process

1. **Fork the repository** on GitHub
2. **Create a feature branch** from `main`
3. **Make your changes** following the guidelines above
4. **Add tests** for new functionality (this is policy, not optional)
5. **Sign off commits** with `git commit -s` (DCO enforced by GitHub App)
6. **Submit a pull request** with a clear description

### PR Requirements

- Sign off commits with `git commit -s` (DCO enforced)
- Pass CI (clippy, rustfmt, tests, CodeQL, cargo-deny)
- Include tests for new functionality
- Be reviewed (human or CodeRabbit) for correctness, safety, and style
- No `unwrap()` in library code, unchecked errors, or unvalidated input

### Review Process

1. **Automated checks** must pass (CI/CD)
2. **Code review** by maintainers
3. **Testing** on multiple platforms
4. **Documentation review** if applicable
5. **Merge** after approval

## Community Guidelines

### Getting Help

- **GitHub Issues**: Bug reports and feature requests
- **Discussions**: General questions and ideas
- **Documentation**: Check existing docs first

## Release Process

### Version Numbering

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

1. Update version in `Cargo.toml`
2. Update changelog via `git-cliff`
3. Run full test suite
4. Update documentation
5. Create release tag (`vX.Y.Z`)
6. Releases are built via `cargo-dist`

Thank you for contributing to Stringy!
