---
date: 2026-06-19
topic: symbol-classification-pipeline
---

# Import/Export Symbol Classification Pipeline

## Summary

Add an `ImportClassifier` that converts parsed import/export symbols and section names from `ContainerInfo` into tagged, scored `FoundString` objects, and route it into the live extraction path so the already-defined Import/Export ranking boosts finally fire. Four new semantic tags (crypto, network, file-I/O, entry-point) are recognized via static API-name sets and the existing symbol demangler.

---

## Problem Frame

`stringy` already emits import and export names in its default output: when `include_symbols` is on (the default), `src/extraction/basic_extractor.rs:67-89` pushes each `ImportInfo`/`ExportInfo` name as a `FoundString`. But those strings are emitted bare: no `Tag::Import`/`Tag::Export`, no RVA, no originating library, and no semantic classification. The `RankingEngine` defines +60 boosts for `Tag::Import` and `Tag::Export` (`src/classification/ranking.rs:131-132`), but nothing ever applies those tags, so the boosts are dead code and symbol strings rank no higher than incidental noise. A binary analyst scanning a packed sample gets `CreateFileW` buried next to junk instead of surfaced as a tagged file-I/O import.

The pieces to fix this already exist in isolation - the demangler, the tag enum scaffolding, the ranking boosts, the parsed symbol metadata. What is missing is the classifier that ties symbol metadata to tags, plus the wiring that makes the tagged strings the ones that actually reach output.

---

## Key Decisions

- **Replace the existing untagged symbol emission rather than add a parallel path.** `basic_extractor` already emits import/export names untagged and default-on. Adding a second, tagged emission path would produce two `FoundString`s per symbol; deduplication is by text with a nondeterministic HashMap winner, so dedup could keep the untagged copy and silently drop the tagged one, no-opping the feature. The classifier becomes the single emission point at that call site instead. The issue's `ImportClassifier` / `extract_symbol_strings` design is unchanged; only where it is called moves.

- **Emit section names as ranked output rows.** Section names (`.text`, `.idata`) are not emitted as standalone strings today (only attached as the `section` field on content strings), so this is net-new with no duplication risk. Generic short names rely on the existing noise/min-length filter to stay out of the way.

- **Reuse `SymbolDemangler` as-is.** It already handles both Rust and C++ (`src/classification/symbols.rs`); no new demangling logic is introduced.

- **New tags ride the existing tag machinery.** No new CLI flags. Once the four variants are wired through `FromStr`, `Display`, serde, and the help text, `--only-tags`/`--no-tags` filter them automatically.

---

## Requirements

**Symbol classification**

- R1. Import names emit as `FoundString`s with `source: StringSource::ImportName`, always carrying `Tag::Import`, at `confidence: 1.0`.
- R2. Imports whose name matches the crypto, network, or file-I/O API sets additionally carry `Tag::Crypto`, `Tag::Network`, or `Tag::FileIO`; imports that match none carry only `Tag::Import`.
- R3. An import's originating library populates the `section` field when present; when absent, a format-appropriate default is used (`.idata` for PE, `.dynsym` for ELF, `__LINKEDIT` for Mach-O -- Mach-O imports never carry a library, so they always use the default).
- R4. An import's RVA populates from `ImportInfo::address` when present (it is optional).
- R5. Export names emit as `FoundString`s with `source: StringSource::ExportName`, always carrying `Tag::Export`, with RVA from `ExportInfo::address` (always available).
- R6. Exports are run through the existing `SymbolDemangler`; successfully demangled exports additionally carry `Tag::DemangledSymbol`. (Implementation note: demangling runs in the pipeline's `classify_strings` -- under `catch_unwind` and skipped in raw mode -- not in the classifier, so a third-party demangler panic never aborts extraction.)
- R7. Exports whose name is a known entry point (`main`, `_start`, `DllMain`, `WinMain`, `wWinMain`) additionally carry `Tag::EntryPoint`.
- R8. Section names emit as standalone `FoundString`s with `source: StringSource::SectionName` (a dedicated variant, distinct from `SectionData`, so section-name rows are distinguishable from byte-scanned section content) at `confidence: 1.0`, ranked alongside other output.

**Type system and ranking**

- R9. Add `Tag` variants `Crypto`, `Network`, `FileIO`, `EntryPoint` with serde renames (`crypto`, `network`, `fileio`, `entry-point`), wired through `Tag::from_str`, `Display`, and every exhaustive match site, including the CLI help text that the `cli_help_lists_all_canonical_tags` test guards.
- R10. `RankingConfig` gains tag boosts: `Crypto` +50, `Network` +45, `FileIO` +35, `EntryPoint` +40.

**Pipeline integration**

- R11. The tagged classifier replaces the untagged import/export emission in `basic_extractor` so each symbol is emitted exactly once, already tagged; section-name emission is added to the same path.
- R12. Tagged symbol strings flow through the remaining pipeline stages (classification, ranking) with their classifier-assigned tags preserved, so the Import/Export and new semantic boosts apply to live output.

**Tests and docs**

- R13. `tests/classification_symbols.rs` covers import classification, export classification, API-set detection (at least 3 representative symbols per category plus a negative case), section-name extraction, and end-to-end `extract_symbol_strings` output against the existing ELF, PE, and Mach-O fixtures.
- R14. `docs/src/classification.md` is updated to reference `std::sync::LazyLock` instead of the stale `once_cell::sync::Lazy` pattern example.

---

## Acceptance Examples

- AE1. **Covers R2.** Import `CreateFileW` yields tags `Import` + `FileIO`; `connect` yields `Import` + `Network`; `EVP_EncryptInit` yields `Import` + `Crypto`; `printf` yields `Import` only.
- AE2. **Covers R6, R7.** A C++-mangled export demangles and yields `Export` + `DemangledSymbol`; export `main` yields `Export` + `EntryPoint`; export `DllMain` yields `Export` + `EntryPoint`.
- AE3. **Covers R3.** A PE import from `kernel32.dll` sets `section` to `kernel32.dll`; an ELF import with no library sets `section` to `.dynsym`.
- AE4. **Covers R11, R12.** Running `stringy` on a PE fixture (with the default `include_symbols`) shows `CreateFileW` exactly once, tagged `import` + `fileio`
  - not a duplicate untagged row, and not dropped by dedup.

---

## Scope Boundaries

- New CLI flags to filter the four new tags - out of scope; the existing `--only-tags`/`--no-tags` machinery covers them.
- Redesigning deduplication or string-ordering behavior - out of scope.
- Tuning exact membership of the crypto/network/file-I/O API sets beyond the issue's seed lists - deferred to planning and implementation.

---

## Dependencies / Assumptions

- `ExportInfo::address` is a required `u64` while `ImportInfo::address` is `Option<u64>`; export RVA is always available, import RVA is conditional (R4, R5 reflect this).
- This work assumes `include_symbols` remains default-on, so the upgrade is visible in default output rather than gated behind a flag.

---

## Sources / Research

- `src/extraction/basic_extractor.rs:67-89` - existing untagged import/export emission that R11 replaces (gated on `config.include_symbols`).
- `src/extraction/traits.rs:97` - `include_symbols` defaults to `true`.
- `src/types/mod.rs` - `ImportInfo` (`name`, `library: Option<String>`, `address: Option<u64>`, `ordinal`), `ExportInfo` (`name`, `address: u64`, `ordinal`), `ContainerInfo.imports`/`exports`, and the `Tag` / `StringSource` enums (`Import`, `Export`, `DemangledSymbol`, `ImportName`, `ExportName`, `SectionData` all present; `Crypto`/`Network`/`FileIO`/ `EntryPoint` absent).
- `src/types/found_string.rs` - `FoundString::new(text, encoding, offset, length, source)` plus `with_rva`, `with_section`, `with_tags`, `with_confidence` builders (constructor defaults `confidence: 1.0`).
- `src/classification/symbols.rs` - `SymbolDemangler` (Rust via `rustc_demangle`, C++ via `cpp_demangle`), reused directly.
- `src/classification/ranking.rs:131-132` - existing `Import`/`Export` +60 boosts that R10 extends.
- `docs/src/classification.md:77,83` - stale `once_cell::sync::Lazy` example that R14 corrects.
- GitHub issue #20 - originating specification (note: its "nothing converts imports/exports into FoundStrings" premise is corrected by R11).
