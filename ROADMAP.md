# Stringy Development Roadmap

This document tracks medium-term and long-term improvements identified during the comprehensive code review (2026-01-18). Issues are organized by priority and category.

## Medium-Term Issues (Next 1-3 Releases)

### Architecture Improvements

#### 1. Split `extraction/mod.rs` into smaller modules
**Priority:** High
**Current state:** 1542 lines (exceeds 500-line project limit by 1042 lines)
**Files affected:** `src/extraction/mod.rs`

Recommended split:
- `src/extraction/config.rs` - Move `ExtractionConfig` and validation logic
- `src/extraction/trait.rs` - Move `StringExtractor` trait definition
- `src/extraction/basic.rs` - Move `BasicExtractor` implementation
- `src/extraction/helpers.rs` - Move internal helper functions (`is_printable_text_byte`, `could_be_utf8_byte`, `extract_ascii_utf8_strings`)

Other oversized files to address:
| File | Lines | Overage |
|------|-------|---------|
| `src/extraction/pe_resources.rs` | 1449 | +949 |
| `src/extraction/utf16.rs` | 1273 | +773 |
| `src/extraction/dedup.rs` | 849 | +349 |
| `src/extraction/ascii.rs` | 832 | +332 |
| `src/output/table.rs` | 708 | +208 |
| `src/extraction/filters.rs` | 702 | +202 |
| `src/container/pe.rs` | 661 | +161 |
| `src/container/elf.rs` | 627 | +127 |
| `src/container/macho.rs` | 574 | +74 |
| `src/types.rs` | 558 | +58 |

#### 2. Move PE resources to container module
**Priority:** Medium
**Current state:** `src/extraction/pe_resources.rs` is in extraction but conceptually belongs in container
**Rationale:** PE resource parsing is part of container analysis, not string extraction

#### 3. Decouple semantic enrichment from extraction
**Priority:** Medium
**Current state:** `extraction` module imports from `classification` creating bidirectional dependency
**Files affected:** `src/extraction/mod.rs:129`
**Recommendation:** Move semantic enrichment to an orchestration layer that callers control

#### 4. Add `#[non_exhaustive]` to remaining public enums
**Priority:** Medium
**Files affected:**
- `src/types.rs:4-10` - `Encoding` enum
- `src/types.rs:130-136` - `BinaryFormat` enum

### Error Handling

#### 5. Add `SerializationError` variant to `StringyError`
**Priority:** Medium
**Current state:** `ConfigError` is incorrectly used for JSON serialization failures
**Files affected:** `src/output/json.rs:14-16`, `src/types.rs`

#### 6. Add format-specific error variants
**Priority:** Low
**Recommendation:** Add `InvalidPeError`, `InvalidElfError`, `InvalidMachOError` instead of generic `ParseError(String)`

### API Improvements

#### 7. Add constructors to remaining public structs
**Priority:** Medium
**Files affected:** `src/types.rs`
**Structs needing constructors:** `ImportInfo`, `ExportInfo`, `SectionInfo`
**Rationale:** Required for `#[non_exhaustive]` compatibility

#### 8. Add `#[allow]` justification comments
**Priority:** Low
**Files affected:**
- `src/extraction/utf16.rs:334` - `#[allow(clippy::result_unit_err)]`
- `src/extraction/utf16.rs:350` - `#[allow(dead_code)]`

### Documentation

#### 9. Update API documentation for accuracy
**Priority:** Medium
**Files affected:** `docs/src/api.md`
**Issues:** Some function signatures don't match actual implementation

#### 10. Add security considerations to README
**Priority:** Medium
**Content to add:** Document malware analysis use case, safe handling of untrusted binaries

#### 11. Document deduplication feature in user docs
**Priority:** Medium
**Files affected:** README.md, `docs/src/string-extraction.md`

### Performance

#### 12. Add memory mapping for large files
**Priority:** High
**Current state:** Entire file is loaded into memory
**Impact:** Processing 1GB+ binaries requires 1GB+ RAM
**Recommendation:** Use `memmap2` crate for memory-mapped file access

```rust
// Recommended approach
use memmap2::Mmap;
use std::fs::File;

let file = File::open(path)?;
let mmap = unsafe { Mmap::map(&file)? };
let data: &[u8] = &mmap;
```

#### 13. Optimize redundant regex matching
**Priority:** Low
**Files affected:** `src/classification/patterns/network.rs:92-106`
**Issue:** URL_REGEX runs twice on URLs (in `classify_url` then `classify_domain`)

### Testing

#### 14. Set up code coverage metrics
**Priority:** Medium
**Tool:** `cargo-tarpaulin`
**Command:** `cargo tarpaulin --out Html`

#### 15. Add performance benchmarks
**Priority:** Medium
**Tool:** `criterion`
**Focus areas:** Deduplication with large input sets, regex pattern matching

#### 16. Add fuzzing for binary parsers
**Priority:** Medium
**Tool:** `cargo-fuzz`
**Targets:** `container/*.rs` parsers with malformed input

---

## Long-Term Issues (Future Releases)

### Performance Optimizations

#### 17. Consider parallel extraction with rayon
**Priority:** Low
**Rationale:** Section-by-section extraction is embarrassingly parallel

```rust
use rayon::prelude::*;

let section_strings: Vec<Vec<FoundString>> = sections
    .par_iter()
    .map(|section| extractor.extract_from_section(data, section, config))
    .collect();
```

#### 18. Consider `Cow<str>` for hot paths
**Priority:** Low
**Files affected:** `src/types.rs:236-237`
**Benefit:** Avoid cloning when strings could be borrowed

#### 19. Consider `SmallVec` for tags
**Priority:** Low
**Field:** `FoundString::tags`
**Rationale:** Typical 0-3 tags could use stack allocation with `SmallVec<[Tag; 4]>`

### Dependency Management

#### 20. Migrate to `std::sync::LazyLock`
**Priority:** Low
**Current state:** Uses `once_cell::sync::Lazy`
**Target:** `std::sync::LazyLock` (stabilized in Rust 1.80)
**Files affected:** All files in `src/classification/patterns/`

### Feature Enhancements

#### 21. Implement main CLI
**Priority:** High
**Current state:** `src/main.rs` is a stub with TODO
**File:** `src/main.rs:18`

#### 22. Integrate Mach-O load command strings
**Priority:** Medium
**Current state:** Feature exists but not integrated into main pipeline
**File:** `src/container/macho.rs:198`

#### 23. Parse all Mach-O architectures
**Priority:** Low
**Current state:** Only parses first architecture in fat binaries
**File:** `src/container/macho.rs:312`

### Build Configuration

#### 24. Add feature flags for output formats
**Priority:** Low
**File:** `Cargo.toml`

```toml
[features]
default = ["json", "yara", "table"]
json = []
yara = []
table = []
```

#### 25. Add `include` field to Cargo.toml
**Priority:** Low
**Purpose:** Control what gets published to crates.io

```toml
[package]
include = ["src/**/*", "Cargo.toml", "LICENSE", "README.md"]
```

---

## Completed Items

The following issues from the comprehensive review have been addressed:

- [x] Fix failing doctests in `extraction/mod.rs` (2026-01-18)
- [x] Fix rustdoc warning in `patterns/ip.rs:107` (2026-01-18)
- [x] Create `CHANGELOG.md` (2026-01-18)
- [x] Fix O(n^2) algorithms in `dedup.rs` using HashSet (2026-01-18)
- [x] Add `OutputFormatter` trait for extensibility (2026-01-18)
- [x] Add `#[non_exhaustive]` to `OutputFormat` enum (2026-01-18)
- [x] Create `examples/` directory with usage examples (2026-01-18)
- [x] Add `Hash` derive to `Encoding` and `StringSource` enums (2026-01-18)

---

## Review Summary

**Overall Rating from Comprehensive Review: B+ (85/100)**

| Dimension | Rating |
|-----------|--------|
| Code Quality | B+ |
| Architecture | B+ |
| Security | A |
| Performance | B |
| Testing | B+ |
| Documentation | B+ |
| Best Practices | A- |

With the immediate issues addressed and medium-term improvements completed, this project would be ready for a stable 1.0 release.
