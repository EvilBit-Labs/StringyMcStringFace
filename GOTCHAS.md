# GOTCHAS.md

Hard-won lessons, edge cases, and "watch out for" patterns. Organized by domain.

## Struct Literals

### `FoundString`

Adding a field to `FoundString` requires updating struct literals in `extraction/`, `classification/`, and `types/tests.rs`. Search for an adjacent field (e.g., `noise_penalty: None,`) to find all sites. Prefer using `FoundString::new()` + builder methods over struct literals where possible.

### `SectionInfo`

`SectionInfo` is NOT `#[non_exhaustive]` -- struct literals are valid. Adding a field requires updating all struct literal sites (search for `section_type:` or `weight:` to find them). Sites include `container/*.rs` parsers and `pipeline/mod.rs` (synthetic unknown-data fallback).

### `OutputMetadata`

Adding a field to `OutputMetadata` requires: (1) add field to struct, (2) initialize in `new()` with a sensible default, (3) add `with_*` builder method, (4) update unit tests in `output/mod.rs` for default assertion and builder test, (5) update TTY formatter if the field affects display (rename `_metadata` to `metadata` if unused).

## CLI

- `clap::value_parser!(usize).range(..)` does not exist -- use a custom `fn(s: &str) -> Result<usize, String>` value parser for range-constrained `usize` args
- `Tag::from_str` in `value_parser` requires `use std::str::FromStr` in scope (clap resolves it as an associated fn, not a trait method)
- CLI flag changes in `main.rs` require updating `tests/integration_cli.rs` (uses `Command` with flag names)

## Dependencies

- `mmap-guard` -- wraps `memmap2` behind a safe API. Stringy uses it unconditionally via `mmap_guard::map_file()` in `pipeline/mod.rs`. The `unsafe` boundary lives in `mmap-guard`, not in Stringy. `mmap_guard::FileData` is `#[non_exhaustive]` and the `Mapped` variant holds internal fields (mmap handle + file handle for advisory locking). Always access data via `Deref<Target = [u8]>`, never pattern-match on variant fields. The `FileData` value must be kept alive for the duration of data access to maintain the advisory lock.
- `memmap2` -- transitive dependency via `mmap-guard`. Never use directly; `Mmap::map` requires `unsafe`, which is forbidden by `#![forbid(unsafe_code)]` in both `lib.rs` and `main.rs`.

## CI

- cargo subcommands installed via mise (e.g. cargo-dist) must be invoked as standalone binaries (`dist plan`) not cargo subcommands (`cargo dist plan`) -- cargo can't find mise-managed subcommands
- Mergify merge protections evaluate from the **main branch** config, not the PR branch
- Quality/MSRV jobs use `dtolnay/rust-toolchain` -- do NOT use `just` recipes here (they use `mise exec --` which conflicts)

## Pipeline

- Unknown/unparseable formats (plain text, etc.) do NOT error -- the pipeline falls back to unstructured raw byte scanning and succeeds. Tests should NOT expect failure when feeding non-binary files like `Cargo.toml`.
