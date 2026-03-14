# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Pipeline orchestrator (`Pipeline::run`) with configurable stages: parse, extract, classify, rank, normalize, filter, output
- `PipelineConfig`, `FilterConfig`, and `EncodingFilter` for pipeline configuration
- `FilterEngine` for post-extraction string filtering (min-len, encoding, tags, top-N)
- `ScoreNormalizer` for mapping raw scores to bounded 0-100 display range
- CLI flags: `--raw`, `--json`, `--yara`, `--summary`, `--debug`, `--enc`, `--only-tags`, `--no-tags`, `--min-len`, `--top`
- `parse_from()` methods on container parsers to avoid double-parsing (single `Object::parse` dispatch)
- Memory-mapped file I/O via `mmap-guard` for zero-copy read-only access
- Progress spinner via `indicatif` for CLI feedback
- Processing warning emission for demangle/classification failures with `catch_unwind` safety
- Stdin-to-pipeline bridging via `tempfile` for piped input
- Output formatters: JSON (JSONL), table (TTY-friendly), and YARA rule templates
- `generated_at` timestamp support in output metadata for deterministic outputs
- Ranking system for prioritizing extracted strings by relevance
- Symbol demangling support for C++, Rust, and other mangled names
- File path classification for POSIX, Windows, and registry paths
- Semantic classification for URLs, domains, and IP addresses (IPv4/IPv6)
- String deduplication with full occurrence metadata preservation
- `CanonicalString` type for deduplicated strings with occurrence tracking
- UTF-16 string extraction with LE/BE/Auto byte order and confidence scoring
- Noise filtering framework with entropy, linguistic, and repetition filters (`CompositeNoiseFilter` with `CharStats` pre-computation)
- Mach-O load command extraction with section weight normalization
- Comprehensive PE support: section classification, import/export parsing, resource extraction
- ELF symbol extraction with type support and visibility filtering
- `#[non_exhaustive]` and builder pattern for `FoundString`, `SectionInfo`, `ContainerInfo`, and config types
- Builder methods on `ExtractionConfig` for forward-compatible configuration
- Contributing guidelines document
- Comprehensive integration test suite (CLI flows, extraction, deduplication, output formatting)
- Test fixtures cross-compiled via Zig (managed by mise)
- Debug-build env var injection for e2e warning-path testing

### Changed
- Container parsers refactored from single files to module directories (elf/, pe/, macho/)
- Repository renamed from StringyMcStringFace to Stringy
- Improved YARA formatter code quality and test coverage
- Clarified ASCII rule for Unicode handling in documentation
- Replaced `once_cell::sync::Lazy` with `std::sync::LazyLock` (stabilized in Rust 1.80)

### Fixed
- Rustdoc warning for IPv6 address example in documentation
- ELF section name fallback no longer eagerly allocates on every iteration
- Pipeline section lookups use HashMap for O(1) access instead of O(n) linear scans
- TTY table format_tags pre-computed once instead of called twice per string
- RankingConfig::default() cached via LazyLock to avoid per-call HashMap allocation
- Filter tag containment uses HashSet for O(1) lookup instead of Vec linear scan
- Demangler text clone now conditional (only for mangled-looking symbols)

### Dependencies
- Added `mmap-guard` for safe memory-mapped file I/O
- Added `indicatif` for progress bars and spinners
- Added `tempfile` for stdin-to-pipeline bridging
- Removed `once_cell` (replaced by `std::sync::LazyLock`)
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
