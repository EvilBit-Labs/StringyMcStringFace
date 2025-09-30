---
inclusion: always
---

# Development Standards & Preferences

## Rust Code Quality Standards

### Memory Safety & Performance

- **Pure Rust**: No `unsafe` code except in vetted dependencies
- **Zero Warnings**: All code must pass `cargo clippy -- -D warnings`
- **Performance First**: Prefer zero-copy operations, efficient algorithms, and memory mapping for large data
- **RAII Patterns**: Leverage Rust's ownership system for resource management

### Code Organization

- **File Size**: Keep modules under 500 lines; split larger files into focused modules
- **Module Hierarchy**: Use clear module boundaries with `mod.rs` files for organization
- **Public APIs**: All public functions and types need comprehensive rustdoc with examples
- **Internal Documentation**: Document complex algorithms and business logic inline

### Error Handling Philosophy

- **Result Types**: Use `Result<T, E>` patterns consistently throughout codebase
- **No Panics**: Avoid panics in library code; reserve for truly unrecoverable situations
- **Contextual Errors**: Provide descriptive error messages with sufficient context for debugging
- **Error Libraries**: Prefer `thiserror` for custom error types, `anyhow` for application errors

## Development Workflow & Tooling

### Preferred Build System

- **Just**: Use justfile recipes for all development tasks instead of raw cargo commands
- **Cross-platform**: Ensure all recipes work on Linux, macOS, and Windows
- **Composable**: Break complex tasks into smaller, reusable recipes

### Standard Development Commands

```bash
# Development cycle
just check         # Fast syntax/type checking and linting
just build         # Build project
just test          # Run all tests with nextest
just lint-rust     # Linting with strict warnings
just fmt           # Format code (Rust + markdown)

# Quality assurance
just bench         # Run benchmarks (use criterion)
just docs-build    # Generate documentation (mdBook + rustdoc)
just coverage      # Coverage measurement with llvm-cov (target: >85%)
just audit         # Security audit with cargo-audit
just format-docs   # Format markdown files with mdformat
```

### Testing Philosophy

- **Test Coverage**: >85% coverage required for all changes
- **Test Types**: Unit tests (in-module), integration tests (in `tests/`), property tests with `proptest`
- **Performance Tests**: Benchmark critical paths with `criterion`
- **Documentation Tests**: Ensure all code examples in docs compile and run, mdformat checks pass on markdown files including embedded code blocks
- **Deterministic Testing**: Use `insta` for snapshot testing of CLI outputs

### Code Formatting & Linting

- **Rustfmt**: Use project-wide `rustfmt.toml` for consistent formatting
- **Clippy**: Enable all lints, treat warnings as errors in CI
- **Markdown Formatting**: Use `mdformat` with extensions for consistent markdown formatting
- **Pre-commit Hooks**: Run formatting and basic lints before commits
- **IDE Integration**: Configure rust-analyzer for real-time feedback

## Documentation Standards

### API Documentation

- **Rustdoc**: Comprehensive documentation for all public APIs
- **Examples**: Include working code examples in doc comments
- **Error Cases**: Document when functions return errors and why
- **Safety**: Document any unsafe code or invariants clearly

### Project Documentation

- **mdBook**: Use mdBook for user-facing documentation and guides
- **User Guide Accuracy**: The `docs/src` user guide must accurately reflect exactly how the tool works right now, not aspirational features
- **Architecture Docs**: Maintain high-level architecture documentation
- **Decision Records**: Document significant technical decisions and trade-offs

## Dependency Management

### Dependency Selection Criteria

- **Maintenance**: Prefer actively maintained crates with recent updates
- **Security**: Regular security audits, minimal dependency trees
- **Performance**: Choose performance-oriented crates for critical paths
- **Compatibility**: Ensure cross-platform support when needed

### Preferred Crates

- **Error Handling**: `thiserror` for libraries, `anyhow` for applications
- **CLI**: `clap` with derive macros for argument parsing
- **Serialization**: `serde` ecosystem for JSON/YAML/TOML
- **Testing**: `criterion` for benchmarks, `proptest` for property testing
- **Async**: `tokio` ecosystem when async is needed

## Performance & Optimization

### Performance Principles

- **Measure First**: Profile before optimizing, use `cargo bench` and `perf`
- **Memory Efficiency**: Prefer stack allocation, use `Box`/`Arc` judiciously
- **Zero-Copy**: Minimize allocations in hot paths
- **Lazy Evaluation**: Defer expensive computations until needed

### Profiling & Benchmarking

- **Criterion**: Standard benchmarking with statistical analysis
- **Flamegraphs**: Use `cargo flamegraph` for performance profiling
- **Memory Profiling**: Use `valgrind` or `heaptrack` for memory analysis
- **Continuous Benchmarking**: Track performance regressions in CI
