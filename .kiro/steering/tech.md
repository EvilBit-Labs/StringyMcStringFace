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

## Project-Specific Testing Tools

- **insta** - for deterministic CLI output validation (binary analysis results)
- **criterion** - Performance benchmarks for string extraction and classification

### Cross-platform Support

- **CI Matrix**: Linux, macOS, Windows with multiple Rust versions (stable, beta, MSRV)
- **Architecture**: x86_64 and ARM64 support validation

## Development Phases

- **MVP**: Basic goblin + section extraction + ASCII/UTF-16 + tagging + JSONL output
- **v0.2**: PE resources + Rust demangling + import/export names
- **v0.3**: Relocation hints + basic disassembly references
- **v0.4**: DWARF support + Mach-O load commands + Go build info

## Project-Specific Performance Considerations

- **Memory Mapping**: Use `memmap2` for large binary files (>1MB)
- **Lazy Evaluation**: Defer expensive features (DWARF parsing, disassembly) until requested
- **Regex Caching**: Compile semantic classification patterns once at startup
- **Section Filtering**: Skip irrelevant binary sections (debug, relocation) during extraction
