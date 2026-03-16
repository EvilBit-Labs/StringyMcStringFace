![Stringy Logo](docs/src/images/logo-320.png)

# Stringy

[![License][license-badge]][license] [![Sponsors][sponsors-badge]][sponsors]

[![CI][ci-badge]][ci] [![dependency status][deps-badge]][deps]

[![codecov][codecov-badge]][codecov] [![Issues][issues-badge]][issues] [![Last Commit][commits-badge]][commits] [![OpenSSF Scorecard][scorecard-badge]][scorecard]

---

A smarter alternative to `strings` that uses binary format knowledge and semantic classification to extract the strings that actually matter from ELF, PE, and Mach-O executables.

The standard `strings` command dumps every printable byte sequence it finds -- padding, table data, interleaved garbage. Stringy is section-aware, encoding-aware, and semantically intelligent: it knows where strings live in a binary, what they mean, and which ones you care about.

## Quick Start

### Installation

**Pre-built binaries** are available on the [Releases] page for Linux, macOS, and Windows.

**From source:**

```bash
git clone https://github.com/EvilBit-Labs/Stringy
cd Stringy
cargo build --release
./target/release/stringy --help
```

### Basic Usage

```bash
# Ranked output with semantic tags
stringy target_binary

# Filter by semantic tags
stringy --only-tags url target_binary
stringy --only-tags url --only-tags filepath target_binary

# Exclude noisy tags
stringy --no-tags format_string target_binary

# Control extraction
stringy --min-len 8 target_binary
stringy --enc ascii target_binary
stringy --top 50 target_binary

# Output formats
stringy --json target_binary
stringy --yara target_binary
stringy --json target_binary | jq '.[] | select(.tags[] | contains("Url"))'

# Raw extraction (no classification or ranking)
stringy --raw target_binary

# Debug and summary modes
stringy --debug target_binary
stringy --summary target_binary

# Read from stdin
cat target_binary | stringy -
```

## Example Output

**TTY table:**

```
String                                   | Tags       | Score | Section
-----------------------------------------|------------|-------|--------
https://api.example.com/v1/              | url        |    95 | .rdata
{12345678-1234-1234-1234-123456789abc}   | guid       |    87 | .rdata
/usr/local/bin/stringy                   | filepath   |    82 | __cstring
Error: %s at line %d                     | fmt        |    78 | .rdata
```

**JSON (JSONL):**

```json
{
  "text": "https://api.example.com/v1/",
  "offset": 4096,
  "rva": 4096,
  "section": ".rdata",
  "encoding": "utf-8",
  "length": 28,
  "tags": [
    "Url"
  ],
  "score": 95,
  "display_score": 95,
  "source": "SectionData",
  "confidence": 0.98
}
```

## Features

- **Format-aware parsing**: ELF, PE, and Mach-O via [goblin], with section-level weight prioritization
- **Encoding support**: ASCII, UTF-8, UTF-16LE/BE with confidence scoring
- **Semantic classification**: URLs, domains, IPv4/IPv6, file paths, registry keys, GUIDs, user agents, format strings, Base64, crypto constants
- **Symbol demangling**: C++, Rust, and other mangled symbol name recovery
- **PE resources**: VERSIONINFO, STRINGTABLE, and MANIFEST extraction
- **Import/export analysis**: Symbol extraction from all supported formats
- **Ranking**: Section-aware scoring with band-mapped 0-100 normalization
- **Deduplication**: Canonical string grouping with configurable similarity threshold
- **Output formats**: TTY table, plain text, JSONL, YARA rules
- **Pipeline architecture**: Configurable orchestrator with filtering, encoding selection, and top-N support

## Security

- Zero `unsafe` code (`#![forbid(unsafe_code)]` enforced project-wide)
- [cargo-deny] and [cargo-audit] run in CI
- Vulnerability reporting via [SECURITY.md]

### Verifying Releases

All release artifacts are signed via [Sigstore](https://www.sigstore.dev/) using GitHub Attestations:

```bash
gh attestation verify <artifact> --repo EvilBit-Labs/Stringy
```

## Documentation

Full documentation is available at **[evilbitlabs.io/stringy](https://evilbitlabs.io/stringy/)**.

Quick links: [Installation](docs/src/installation.md) | [Quick Start](docs/src/quickstart.md) | [CLI Reference](docs/src/cli.md) | [Architecture](docs/src/architecture.md) | [Troubleshooting](docs/src/troubleshooting.md)

## Contributing

See [CONTRIBUTING.md] for development setup, coding guidelines, and submission process.

## License

Licensed under the [Apache License, Version 2.0][license].

## Acknowledgments

- Inspired by `strings(1)` and the need for better binary analysis tools
- Built with [goblin], [bstr](https://docs.rs/bstr), [regex](https://docs.rs/regex), and [rustc-demangle](https://docs.rs/rustc-demangle)
- My coworkers, for their excellent input on the original name selection

<!-- links -->

[cargo-audit]: https://github.com/EvilBit-Labs/Stringy/actions/workflows/audit.yml
[cargo-deny]: https://github.com/EvilBit-Labs/Stringy/actions/workflows/security.yml
[ci]: https://github.com/EvilBit-Labs/Stringy/actions/workflows/ci.yml
[ci-badge]: https://img.shields.io/github/actions/workflow/status/EvilBit-Labs/Stringy/ci.yml?style=flat-square&label=CI
[codecov]: https://codecov.io/gh/EvilBit-Labs/Stringy
[codecov-badge]: https://img.shields.io/codecov/c/github/EvilBit-Labs/Stringy?style=flat-square
[commits]: https://github.com/EvilBit-Labs/Stringy/commits/main
[commits-badge]: https://img.shields.io/github/last-commit/EvilBit-Labs/Stringy?style=flat-square
[contributing.md]: CONTRIBUTING.md
[deps]: https://deps.rs/repo/github/EvilBit-Labs/Stringy
[deps-badge]: https://deps.rs/repo/github/EvilBit-Labs/Stringy/status.svg?style=flat-square
[goblin]: https://docs.rs/goblin
[issues]: https://github.com/EvilBit-Labs/Stringy/issues
[issues-badge]: https://img.shields.io/github/issues/EvilBit-Labs/Stringy?style=flat-square
[license]: https://github.com/EvilBit-Labs/Stringy/blob/main/LICENSE
[license-badge]: https://img.shields.io/github/license/EvilBit-Labs/Stringy?style=flat-square
[releases]: https://github.com/EvilBit-Labs/Stringy/releases
[scorecard]: https://scorecard.dev/viewer/?uri=github.com/EvilBit-Labs/Stringy
[scorecard-badge]: https://img.shields.io/ossf-scorecard/github.com/EvilBit-Labs/Stringy?style=flat-square
[security.md]: SECURITY.md
[sponsors]: https://github.com/sponsors/EvilBit-Labs
[sponsors-badge]: https://img.shields.io/github/sponsors/EvilBit-Labs?style=flat-square
