# Technology Stack

## Language & Runtime

- **Rust** - Primary language for performance and memory safety
- Target: Cross-platform (Linux, Windows, macOS)

## Core Dependencies

### Binary Parsing

- `goblin` - Multi-format binary parser (ELF/PE/Mach-O)
- `pelite` - PE resource extraction (VERSIONINFO/STRINGTABLE)
- `object` - Additional Mach-O format support
- `memmap2` - Fast read-only memory mapping

### String Processing & Analysis

- `regex` - Pattern matching for semantic tagging
- `aho-corasick` - Fast multi-pattern string matching
- `rustc-demangle` - Rust symbol demangling

### Optional Features

- `gimli` - DWARF debugging information parsing
- `capstone-rs` - Disassembly for reference analysis

### CLI & Serialization

- `clap` - Command-line argument parsing
- `serde` + `serde_json` - JSON serialization for output formats

## Testing & Build Tools

- **Rust** - Primary language for performance and memory safety
- **Cargo** - Build system for Rust projects
- **cargo-nextest** - Test runner for faster, more reliable test execution
- **llvm-cov** - for coverage measurement and reporting (target: >85%)
- **insta** - for deterministic CLI output validation
- **criterion** - Performance benchmarks for critical path components

### Cross-platform Support

- **CI Matrix**: Linux, macOS, Windows with multiple Rust versions (stable, beta, MSRV)
- **Architecture**: x86_64 and ARM64 support validation

## Build Commands

```bash
# Development build
cargo build

# Release build (optimized)
cargo build --release

# Run tests
cargo test

# Run with example
cargo run -- binary_file.exe --json

# Install locally
cargo install --path .
```

## Development Phases

- **MVP**: Basic goblin + section extraction + ASCII/UTF-16 + tagging + JSONL output
- **v0.2**: PE resources + Rust demangling + import/export names
- **v0.3**: Relocation hints + basic disassembly references
- **v0.4**: DWARF support + Mach-O load commands + Go build info

## Performance Considerations

- Use memory mapping for large binaries
- Lazy evaluation for optional features (DWARF, disasm)
- Efficient regex compilation and caching
