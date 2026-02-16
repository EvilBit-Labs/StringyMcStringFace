# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Output formatters: JSON (JSONL), table (TTY-friendly), and YARA rule templates
- `generated_at` timestamp support in output metadata for deterministic outputs
- Ranking system for prioritizing extracted strings by relevance
- Symbol demangling support for Rust mangled names
- File path classification for POSIX, Windows, and registry paths
- Semantic classification for URLs, domains, and IP addresses (IPv4/IPv6)
- String deduplication with full occurrence metadata preservation
- `CanonicalString` type for deduplicated strings with occurrence tracking
- UTF-16 string extraction with confidence scoring
- Noise filtering framework with entropy, linguistic, and repetition filters
- Mach-O load command extraction with section weight normalization
- Comprehensive PE support: section classification, import/export parsing, resource extraction
- ELF symbol extraction with type support and visibility filtering
- `#[non_exhaustive]` and builder pattern for `FoundString` public API
- Contributing guidelines document

### Changed
- Repository renamed from StringyMcStringFace to Stringy
- Improved YARA formatter code quality and test coverage
- Clarified ASCII rule for Unicode handling in documentation

### Fixed
- Rustdoc warning for IPv6 address example in documentation

### Dependencies
- Updated criterion to 0.8.1
- Updated actions/checkout to v6
- Updated actions/download-artifact to v7
- Updated actions/attest-build-provenance to v3
- Updated actions/upload-artifact to v5
- Updated github/codeql-action to v4
- Updated EmbarkStudios/cargo-deny-action to v2

## [0.1.0] - TBD

Initial release with core functionality:

### Added
- ELF, PE, and Mach-O binary format detection and parsing
- ASCII and UTF-8 string extraction from binary sections
- Section-aware extraction with weight-based prioritization
- Basic semantic tagging infrastructure
- Command-line interface (in development)
