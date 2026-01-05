---
inclusion: fileMatch
fileMatchPattern: [Cargo.toml]
---

# Cargo.toml Standards for Stringy

## Package Configuration

- Use **Rust 2024 Edition** (MSRV: 1.91+) as specified in the package
- Single crate structure (not a workspace)
- Enforce lint policy via `[lints.rust]` configuration
  - Forbid unsafe code globally
  - Deny all warnings to preserve code quality

Example `Cargo.toml` structure:

```toml
[package]
name = "stringy"
version = "0.1.0"
edition = "2024"
authors = ["UncleSp1d3r <unclesp1d3r@evilbitlabs.io>"]
description = "A smarter alternative to the strings command that leverages format-specific knowledge"
license = "Apache-2.0"
repository = "https://github.com/EvilBit-Labs/StringyMcStringFace"
homepage = "http://evilbitlabs.io/StringyMcStringFace/"
keywords = ["binary", "strings", "analysis", "reverse-engineering", "malware"]
categories = ["command-line-utilities", "development-tools"]

[lib]
name = "stringy"
path = "src/lib.rs"

[[bin]]
name = "stringy"
path = "src/main.rs"

[lints.rust]
unsafe_code = "forbid"
warnings = "deny"
```

## Dependencies

- **Core dependencies**:

  - `clap = { version = "4.5", features = ["derive"] }` - CLI argument parsing
  - `goblin = "0.10"` - Binary format parsing (ELF, PE, Mach-O)
  - `serde = { version = "1.0", features = ["derive"] }` - Serialization
  - `serde_json = "1.0"` - JSON output
  - `thiserror = "2.0"` - Structured error types

- **Dev dependencies**:

  - `criterion = "0.7"` - Benchmarking
  - `insta = "1.0"` - Snapshot testing
  - `tempfile = "3.8"` - Temporary file handling in tests

## Build Profiles

- Use `[profile.dist]` for distribution builds with LTO:

```toml
[profile.dist]
inherits = "release"
lto = "thin"
```

## Benchmarks

- Define benchmarks in `[[bench]]` sections:

```toml
[[bench]]
name = "elf"
harness = false
```

## Package Metadata

- Include proper license (Apache-2.0)
- Provide clear description for binary analysis tool
- Include relevant keywords for discoverability
