# GOTCHAS.md

Hard-won lessons, edge cases, and "watch out for" patterns. Organized by domain.

## Struct Literals

### `FoundString`

Adding a field to `FoundString` requires updating struct literals in `extraction/`, `classification/`, and `types/tests.rs`. Search for an adjacent field (e.g., `noise_penalty: None,`) to find all sites. Prefer using `FoundString::new()` + builder methods over struct literals where possible.

### `SectionInfo`

`SectionInfo` is `#[non_exhaustive]` -- struct literals are NOT valid outside the crate. Always construct via `SectionInfo::new()` and configure optional fields with `with_*` builder methods. When adding a field, update the struct definition, initialize it with a sensible default in `SectionInfo::new()`, and add the relevant builder method.

### `OutputMetadata`

Adding a field to `OutputMetadata` requires: (1) add field to struct, (2) initialize in `new()` with a sensible default, (3) add `with_*` builder method, (4) update unit tests in `output/mod.rs` for default assertion and builder test, (5) update TTY formatter if the field affects display (rename `_metadata` to `metadata` if unused).

### `ExtractionConfig`

Changing default values in `ExtractionConfig::default()` requires updating assertions in both `src/extraction/tests.rs` (`test_extraction_config_default`) and `tests/integration_extraction.rs` (`test_extraction_config_defaults`). Search for the field name (e.g., `min_length`) in both files.

## CLI

- `clap::value_parser!(usize).range(..)` does not exist -- use a custom `fn(s: &str) -> Result<usize, String>` value parser for range-constrained `usize` args
- `Tag::from_str` in `value_parser` requires `use std::str::FromStr` in scope (clap resolves it as an associated fn, not a trait method)
- CLI flag changes in `main.rs` require updating `tests/integration_cli.rs` (uses `Command` with flag names)
- `Tag::from_str` accepts lowercase (`"url"`) but serde serializes PascalCase (`"Url"`) for variants without `#[serde(rename)]` -- tests comparing JSON output must use case-insensitive comparison or the serialized form
- `--raw` mode performs extraction only and then early-exits: ranking, normalization, and pipeline-level classification are skipped. `tags` are cleared, `score` is forced to 0, and `display_score` is set to `Some(0)`. `assert_cmd` tests run piped (non-TTY); use `format_table_with_mode(&strings, &metadata, true)` to test TTY table rendering
- Exit codes are typed: 0=success, 2=config/validation error, 3=file not found, 4=permission denied, 1=other. Tests asserting exit codes must match `StringyError::exit_code()` in `types/error.rs`
- `--no-tags` is the canonical flag name (kebab-case). Previously was `--notags` -- update all references when touching CLI flag names
- Short flags: `-j` (json), `-m` (min-len), `-t` (top). Do not add short flags for infrequent flags (--enc, --yara, --raw, --summary, --debug)
- `NO_COLOR` env var disables progress spinner. The spinner is also hidden when stderr is not a TTY
- Clap derive attributes (`long_help`, `about`, etc.) require string literals -- `const` values and `concat!` with consts do not work. The `cli_help_lists_all_canonical_tags` test in `integration_cli.rs` verifies help text stays in sync with `Tag::from_str()`

## Dependencies

- `mmap-guard` -- wraps `memmap2` behind a safe API. Stringy uses it unconditionally via `mmap_guard::map_file()` in `pipeline/mod.rs`. The `unsafe` boundary lives in `mmap-guard`, not in Stringy. `mmap_guard::FileData` is `#[non_exhaustive]` and the `Mapped` variant holds internal fields (mmap handle + file handle for advisory locking). Always access data via `Deref<Target = [u8]>`, never pattern-match on variant fields. The `FileData` value must be kept alive for the duration of data access to maintain the advisory lock.
- `memmap2` -- transitive dependency via `mmap-guard`. Never use directly; `Mmap::map` requires `unsafe`, which is forbidden by `#![forbid(unsafe_code)]` in both `lib.rs` and `main.rs`.

## CI

- cargo subcommands installed via mise (e.g. cargo-dist) must be invoked as standalone binaries (`dist plan`) not cargo subcommands (`cargo dist plan`) -- cargo can't find mise-managed subcommands
- Mergify merge protections evaluate from the **main branch** config, not the PR branch
- Quality/MSRV jobs use `dtolnay/rust-toolchain` -- do NOT use `just` recipes here (they use `mise exec --` which conflicts)

## Justfile Recipes

- All tool invocations must use `{{ mise_exec }}` prefix to ensure mise-managed versions
- Use `just rmrf` for cross-platform file/directory cleanup (not raw `rm` or `Remove-Item`)
- Unix shebang recipes use `set -euo pipefail`; Windows recipes need `$ErrorActionPreference = "Stop"` for parity
- Keep recipe output minimal -- no excessive echo/Write-Host; let tools speak for themselves

## Test Fixtures

- When gitignoring already-tracked files, always `git rm --cached` them too -- `.gitignore` only affects untracked files
- Compiled binary fixtures (ELF, PE, Mach-O) are gitignored -- `just gen-fixtures` must run before tests
- `test_binary.c` changes require rebuilding all fixtures and regenerating insta snapshots
- All fixtures are cross-compiled via `zig cc` (managed by mise) -- no Docker or platform-specific compilers needed
- Changing the Zig version in `mise.toml` may alter compiled layouts, breaking insta snapshots
- CI runs `just gen-fixtures` before test steps automatically
- `test_unknown.bin` and `test_empty.bin` are regenerated by `just gen-fixtures` -- to change their content, edit the Justfile recipes (both Unix and Windows), not the files directly
- `test_unknown.bin` contains a URL string (`http://example.com/test`) to enable tag-coverage assertions in unknown-binary fallback tests

## Pipeline

- `load_file` handles empty files via `mmap_guard`'s `InvalidInput` error branch, returning `FileData::Loaded(Vec::new())`. Unit tests for all four branches (happy path, empty, missing, permission-denied) live in `pipeline/mod.rs`'s `#[cfg(test)] mod tests`. The permission-denied test is `#[cfg(unix)]` only.
- Unknown/unparseable formats (plain text, etc.) do NOT error -- the pipeline falls back to unstructured raw byte scanning and succeeds. Tests should NOT expect failure when feeding non-binary files like `Cargo.toml`.
- Raw mode extraction order is non-deterministic across runs (HashMap iteration order in dedup/import processing). Do not write tests asserting deterministic row ordering in `--raw` output.
- Import/export strings have `offset: 0` (no meaningful file offset). Only `SectionData` source has real offsets, and even those are NOT globally monotonic (sections processed by weight priority).
- Homogeneous strings (e.g. `"A".repeat(250)`) are filtered as noise by the extractor. Use varied character patterns for test fixtures that must survive extraction.
- Do NOT make pipeline helpers `pub` solely for test access -- keep them private and add `#[cfg(test)] mod tests` within the module for format-contract checks; use e2e CLI assertions (env var injection) for integration tests
- Debug-build env vars `STRINGY_TEST_INJECT_DEMANGLE_FAILURES` and `STRINGY_TEST_INJECT_CLASSIFY_FAILURES` inject failure counts for e2e warning-path testing (only active under `#[cfg(debug_assertions)]`)
- Classification is performed once in the pipeline's `classify_strings()` with `catch_unwind` safety. Extraction does NOT classify strings.
