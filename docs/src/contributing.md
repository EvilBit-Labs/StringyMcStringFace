# Contributing to Stringy

We welcome contributions to Stringy! This guide will help you get started with development, testing, and submitting changes.

## Development Setup

### Prerequisites

- **Rust**: 1.70 or later (MSRV - Minimum Supported Rust Version)
- **Git**: For version control
- **Platform tools**: C compiler for native dependencies

### Clone and Setup

```bash
git clone https://github.com/EvilBit-Labs/string_mcstringface
cd string_mcstringface

# Install development dependencies
cargo build
cargo test
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

# Test runner (optional but recommended)
cargo install cargo-nextest

# Coverage (optional)
cargo install cargo-llvm-cov
```

## Project Structure

Understanding the codebase organization:

```text
src/
├── main.rs              # CLI entry point
├── lib.rs               # Library root and public API
├── types.rs             # Core data structures
├── container/           # Binary format parsers
│   ├── mod.rs           # Format detection
│   ├── elf.rs           # ELF parser
│   ├── pe.rs            # PE parser
│   └── macho.rs         # Mach-O parser
├── extraction/          # String extraction
├── classification/      # Semantic analysis
└── output/              # Output formatting

tests/
├── integration/         # End-to-end tests
├── fixtures/            # Test binary files
└── unit/                # Module-specific tests

docs/
├── src/                 # mdbook documentation
└── book.toml            # Documentation config
```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-description
```

### 2. Make Changes

Follow the coding standards:

```bash
# Format code
cargo fmt

# Check for issues
cargo clippy -- -D warnings

# Run tests
cargo test
# or with nextest
cargo nextest run
```

### 3. Test Your Changes

```bash
# Unit tests
cargo test --lib

# Integration tests
cargo test --test integration

# Documentation tests
cargo test --doc

# Manual testing
cargo run -- test_binary.exe
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

We follow standard Rust conventions:

- Use `cargo fmt` for formatting
- Follow `cargo clippy` recommendations
- Use meaningful variable and function names
- Add documentation comments for public APIs

### Error Handling

Use the project's error types:

```rust
use crate::types::{Result, StringyError};

fn parse_something() -> Result<ParsedData> {
    // Use ? operator for error propagation
    let data = read_file(path)?;

    // Create specific errors when needed
    if data.is_empty() {
        return Err(StringyError::ParseError("Empty file".to_string()));
    }

    Ok(ParsedData::new(data))
}
```

### Testing

Write comprehensive tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_functionality() {
        let input = create_test_input();
        let result = function_under_test(input);
        assert_eq!(result.unwrap(), expected_output());
    }

    #[test]
    fn test_error_conditions() {
        let invalid_input = create_invalid_input();
        let result = function_under_test(invalid_input);
        assert!(result.is_err());
    }
}
```

### Documentation

Document public APIs thoroughly:

````rust
/// Extracts strings from the given binary data.
///
/// This function analyzes the binary format and applies appropriate
/// extraction strategies based on the detected format and sections.
///
/// # Arguments
///
/// * `data` - The binary data to analyze
/// * `config` - Extraction configuration options
///
/// # Returns
///
/// A vector of extracted strings with metadata, or an error if
/// the binary format is unsupported or corrupted.
///
/// # Examples
///
/// ```
/// use stringy::{extract_strings, ExtractionConfig};
///
/// let data = std::fs::read("binary.exe")?;
/// let config = ExtractionConfig::default();
/// let strings = extract_strings(&data, &config)?;
/// ```
pub fn extract_strings(data: &[u8], config: &ExtractionConfig) -> Result<Vec<FoundString>> {
    // Implementation
}
````

## Testing Guidelines

### Unit Tests

- Test individual functions and methods
- Cover both success and error cases
- Use descriptive test names
- Keep tests focused and independent

### Integration Tests

- Test complete workflows
- Use real binary files when possible
- Verify output formats
- Test CLI interface

### Test Data

When adding test binaries:

```bash
# Add to tests/fixtures/
tests/fixtures/
├── elf/
│   ├── simple_hello_world
│   └── complex_application
├── pe/
│   ├── hello.exe
│   └── complex.dll
└── macho/
    ├── hello_macos
    └── framework.dylib
```

Keep test files small and focused on specific features.

### Performance Tests

For performance-critical code:

```rust
#[cfg(test)]
mod benchmarks {
    use super::*;
    use criterion::{Criterion, black_box, criterion_group, criterion_main};

    fn bench_string_extraction(c: &mut Criterion) {
        let data = load_test_binary();

        c.bench_function("extract_strings", |b| {
            b.iter(|| extract_strings(black_box(&data), &ExtractionConfig::default()))
        });
    }

    criterion_group!(benches, bench_string_extraction);
    criterion_main!(benches);
}
```

## Contribution Areas

### High-Priority Areas

1. **String Extraction Engine**

   - UTF-16 detection improvements
   - Noise filtering enhancements
   - Performance optimizations

2. **Classification System**

   - New semantic patterns
   - Improved confidence scoring
   - Language-specific detection

3. **Output Formats**

   - Additional format support
   - Customization options
   - Template system

4. **CLI Interface**

   - Argument parsing completion
   - Interactive features
   - Configuration file support

### Medium-Priority Areas

1. **Binary Format Support**

   - Enhanced PE resource extraction
   - Mach-O fat binary support
   - Additional format support (WASM, etc.)

2. **Performance**

   - Parallel processing
   - Memory optimization
   - Caching improvements

3. **Documentation**

   - Usage examples
   - Architecture guides
   - Performance analysis

### Getting Started Ideas

Good first contributions:

- Add new semantic patterns (email formats, crypto constants)
- Improve test coverage
- Add CLI argument validation
- Enhance error messages
- Add documentation examples
- Fix clippy warnings

## Submitting Changes

### Pull Request Process

1. **Fork the repository** on GitHub
2. **Create a feature branch** from `main`
3. **Make your changes** following the guidelines above
4. **Add tests** for new functionality
5. **Update documentation** if needed
6. **Submit a pull request** with a clear description

### PR Description Template

```markdown
## Description
Brief description of the changes.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added for new functionality
```

### Review Process

1. **Automated checks** must pass (CI/CD)
2. **Code review** by maintainers
3. **Testing** on multiple platforms
4. **Documentation review** if applicable
5. **Merge** after approval

## Community Guidelines

### Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help newcomers learn
- Maintain professional communication

### Getting Help

- **GitHub Issues**: Bug reports and feature requests
- **Discussions**: General questions and ideas
- **Documentation**: Check existing docs first
- **Code Review**: Ask questions during review process

### Recognition

Contributors are recognized through:

- GitHub contributor graphs
- Release notes mentions
- Documentation credits
- Community acknowledgments

## Release Process

### Version Numbering

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md`
3. Run full test suite
4. Update documentation
5. Create release tag
6. Publish to crates.io (when ready)

Thank you for contributing to Stringy! Your efforts help make binary analysis more accessible and effective for everyone.
