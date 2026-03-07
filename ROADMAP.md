# Stringy Development Roadmap

This document tracks planned improvements and future directions for Stringy. Items are organized by priority and timeframe.

Last updated: 2026-03-07

---

## Near-Term (Next 1-2 Releases)

### Architecture

#### Add `#[non_exhaustive]` to remaining public enums

**Priority:** Medium

`Encoding` and `BinaryFormat` enums in `src/types/mod.rs` lack `#[non_exhaustive]`, which limits forward compatibility. `Tag` and public structs like `ContainerInfo` and `FoundString` already have it.

#### Add constructors to remaining public structs

**Priority:** Medium

`ImportInfo`, `ExportInfo`, and `SectionInfo` lack explicit `new()` constructors. Since other public structs use `#[non_exhaustive]` with constructors, these should follow the same pattern for API consistency.

#### Move PE resources to container module

**Priority:** Medium

`src/extraction/pe_resources/` is conceptually container analysis (parsing PE resource structures), not string extraction. Moving it to `container/` would better reflect the data flow.

#### Decouple semantic enrichment from extraction

**Priority:** Medium

The `extraction` module imports from `classification`, creating a bidirectional dependency. Semantic enrichment should move to an orchestration layer that callers control.

### Error Handling

#### Add `SerializationError` variant to `StringyError`

**Priority:** Medium

JSON serialization failures currently use `ConfigError`, which is misleading. A dedicated `SerializationError` variant would improve error clarity.

#### Add format-specific error variants

**Priority:** Low

Replace generic `ParseError(String)` with `InvalidPeError`, `InvalidElfError`, `InvalidMachOError` for better diagnostics.

### Performance

#### Add memory mapping for large files

**Priority:** High

The entire file is currently loaded into memory. For 1GB+ binaries this is impractical. Use `memmap2` for memory-mapped read-only access.

#### Optimize redundant regex matching

**Priority:** Low

`URL_REGEX` runs twice on URLs (once in `classify_url`, again in `classify_domain`). Could be deduplicated.

### Documentation

#### Update API documentation for accuracy

**Priority:** Medium

Some function signatures in `docs/src/api.md` may not match the current implementation.

#### Add security considerations to README

**Priority:** Medium

Document the malware analysis use case, safe handling of untrusted binaries, and limitations when processing packed/obfuscated samples.

#### Document deduplication in user docs

**Priority:** Medium

The deduplication feature is not covered in README.md or `docs/src/string-extraction.md`.

### Testing

#### Add fuzzing for binary parsers

**Priority:** Medium

Use `cargo-fuzz` to fuzz `container/*.rs` parsers with malformed input. These are the primary attack surface for untrusted binaries.

---

## Medium-Term (v1.x Releases)

### Oversized Files

The following files still exceed the 500-line project limit and should be split:

| File                     | Lines | Overage |
| ------------------------ | ----- | ------- |
| `src/container/pe.rs`    | 661   | +161    |
| `src/container/elf.rs`   | 627   | +127    |
| `src/container/macho.rs` | 574   | +74     |

### Feature Integration

#### Integrate Mach-O load command strings into main pipeline

**Priority:** Medium

`extract_load_command_strings()` exists in `src/extraction/macho_load_commands.rs` and the `StringSource::LoadCommand` variant is defined, but load command extraction is not wired into `BasicExtractor`. It requires a separate manual call.

#### Parse all Mach-O architectures in fat binaries

**Priority:** Low

Currently only the first architecture in a fat/universal binary is parsed. Multi-arch support would allow extracting strings from all slices.

### Dependency Modernization

#### Migrate from `once_cell` to `std::sync::LazyLock`

**Priority:** Low

All files in `src/classification/patterns/` use `once_cell::sync::Lazy`. `std::sync::LazyLock` has been stable since Rust 1.80 and removes the external dependency.

### Performance Optimizations

#### Parallel extraction with rayon

**Priority:** Low

Section-by-section extraction is embarrassingly parallel. Using `rayon` could improve throughput on multi-core systems for large binaries, especially combined with memory mapping.

#### `Cow<str>` for hot paths

**Priority:** Low

`FoundString` fields currently clone strings. Using `Cow<str>` could avoid allocations when strings can be borrowed directly from mapped memory.

#### `SmallVec` for tags

**Priority:** Low

Most strings have 0-3 tags. `SmallVec<[Tag; 4]>` would use stack allocation for the common case.

### Build Configuration

#### Feature flags for output formats

**Priority:** Low

Allow compile-time selection of output formats (json, yara, table) via Cargo features for smaller binaries.

---

## Long-Term (v2+)

### Binary Analysis Enhancements

- **Light XREF hinting**: Check ELF relocations targeting `.rodata` addresses; strings with inbound relocs rank higher
- **Capstone-lite pass**: Scan for immediates in `.text` that point into string pools; mark as "referenced" (flag only, no CFG)
- **DWARF skim**: Extract function/file names with `gimli` to augment context
- **PDB integration**: Use `pdb` crate to enrich imports/function names (no symbol server fetch)
- **Go build info**: Detect Go binaries and extract build paths, module info
- **.NET metadata**: Surface .NET-specific strings and metadata
- **UPX/packer detection**: Detect common packers; offer `--expect-upx` mode to reduce false negatives

### Red Team / Analyst Features

- `--diff old.bin new.bin` to highlight string deltas between binary versions
- `--mask common` to drop common libc/CRT strings and reduce noise
- `--profile malware` to enhance tags with suspicious keywords, cloud endpoints, and telemetry beacons
- Stable NDJSON schema for pipeline integration with `jq` and similar tools

---

## Completed

- [x] Split `extraction/mod.rs` into focused submodules (PR #135)
- [x] Split all oversized extraction files (`ascii`, `utf16`, `dedup`, `filters`, `pe_resources`, `table`)
- [x] Implement working CLI with format selection, min-length filtering
- [x] Add criterion benchmarks (`benches/`)
- [x] Set up code coverage in CI (`cargo llvm-cov` + Codecov)
- [x] Add `#[non_exhaustive]` to `Tag`, `OutputFormat`, `ContainerInfo`, `FoundString`
- [x] Add `OutputFormatter` trait for extensibility
- [x] Fix O(n^2) deduplication using HashSet
- [x] Add `Hash` derive to `Encoding` and `StringSource` enums
- [x] Fix failing doctests in extraction module
- [x] Create CHANGELOG.md
- [x] Add `#[allow]` justification comments to all directives
- [x] Wire up CLI to full extraction pipeline
