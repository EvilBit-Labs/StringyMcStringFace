# Project Structure

## Root Directory

- `concept.md` - Project specification and design document
- `Cargo.toml` - Rust package manifest and dependencies
- `Cargo.lock` - Dependency lock file (committed)
- `README.md` - User-facing documentation
- `LICENSE` - Project license

## Source Code Organization

```
src/
├── main.rs              # CLI entry point and argument parsing
├── lib.rs               # Library root and public API
├── container/           # Binary format detection and parsing
│   ├── mod.rs
│   ├── elf.rs           # ELF-specific extraction
│   ├── pe.rs            # PE-specific extraction  
│   └── macho.rs         # Mach-O-specific extraction
├── extraction/          # String extraction logic
│   ├── mod.rs
│   ├── ascii.rs         # ASCII/UTF-8 extraction
│   ├── utf16.rs         # UTF-16 extraction
│   └── dedup.rs         # Deduplication and canonicalization
├── classification/      # String analysis and tagging
│   ├── mod.rs
│   ├── semantic.rs      # URL, domain, IP, path detection
│   ├── symbols.rs       # Import/export/symbol handling
│   └── ranking.rs       # Scoring algorithm
├── output/              # Output formatting
│   ├── mod.rs
│   ├── json.rs          # JSONL output
│   ├── human.rs         # Human-readable tables
│   └── yara.rs          # YARA-friendly format
└── types.rs             # Core data structures (FoundString, etc.)
```

## Test Organization

```
tests/
├── integration/         # End-to-end CLI tests
├── fixtures/            # Test binaries (ELF, PE, Mach-O samples)
└── unit/                # Module-specific unit tests
```

## Documentation

```
docs/
├── architecture.md      # Technical architecture details
├── examples/            # Usage examples and tutorials
└── benchmarks/          # Performance comparisons
```

## Configuration Files

- `.gitignore` - Git ignore patterns
- `.github/workflows/` - CI/CD configuration
- `rustfmt.toml` - Code formatting rules
- `clippy.toml` - Linting configuration

## Development Guidelines

- Keep binary format logic separated in `container/` modules
- Core data types in `types.rs` should be serializable
- All public APIs should have documentation comments
- Integration tests should cover all supported binary formats
- Performance-critical paths should have benchmarks
