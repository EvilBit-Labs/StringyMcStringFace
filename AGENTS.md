# AI Agent Guidelines for Stringy

@GOTCHAS.md

## Critical Rules

**These rules are non-negotiable. Violations will cause CI failures.**

1. **No `unsafe` code** - `#![forbid(unsafe_code)]` enforced
2. **Zero warnings** - `cargo clippy -- -D warnings` must pass
3. **ASCII only** - No emojis, em-dashes, smart quotes, or Unicode punctuation (except when explicitly testing or working with Unicode strings or emojis)
4. **File size limit** - Keep files under 500 lines; split larger files
5. **No blanket `#[allow]`** - Any `allow` requires inline justification

## Project Summary

Stringy extracts meaningful strings from ELF, PE, and Mach-O binaries using format-specific knowledge and semantic classification. Unlike standard `strings`, it is section-aware and semantically intelligent.

- **Rust**: Edition 2024, MSRV 1.91
- **Data flow**: Binary -> Format Detection -> Container Parsing -> String Extraction -> Deduplication -> Classification -> Ranking -> Output

## Module Structure

| Module            | Purpose                                                               |
| ----------------- | --------------------------------------------------------------------- |
| `container/`      | Format detection, section analysis, imports/exports via `goblin`      |
| `extraction/`     | ASCII/UTF-8/UTF-16 extraction, deduplication, PE resources            |
| `classification/` | Semantic tagging (URLs, IPs, domains, paths, GUIDs), ranking          |
| `output/`         | Formatters: `json/`, `table/` (tty/plain), `yara/`                    |
| `pipeline/`       | Orchestrator: config, filtering, score normalization, `Pipeline::run` |
| `types/`          | Core data structures, error handling with `thiserror`                 |

## Key Patterns

### Section Weights

Container parsers assign weights (1.0-10.0) based on string likelihood. Higher = more valuable. See existing parsers in `container/*.rs` for reference values.

### Error Handling

Use `thiserror` with detailed context. Include offsets, section names, and file paths in error messages. Convert external errors with `From` implementations.

### Public API Structs

Use `#[non_exhaustive]` for public structs and provide explicit constructors. When using `#[non_exhaustive]` structs internally, always use the constructor pattern (`Type::new()`) rather than struct literals - struct literals bypass the forward-compatibility guarantee. See GOTCHAS.md for struct literal update checklists.

### Test-Only Code

For test utilities that shouldn't be in production builds:

- Add `#[cfg(test)]` to both the struct/type definition AND any impl blocks
- Use `pub(crate)` visibility for internal test helpers
- Keep test infrastructure in `#[cfg(test)] mod tests` blocks within the module

### CLI (clap)

Use idiomatic `clap` derive API patterns. Push validation into clap wherever possible -- use `value_parser`, `PossibleValue`, range constraints, and custom value parsers rather than manual post-parse validation. Keep `main.rs` thin by letting clap handle argument conflicts, defaults, and error messages. See GOTCHAS.md for clap pitfalls and test co-change requirements.

### Current CLI Flags (main.rs)

| Flag          | Type                  | Notes                                                                  |
| ------------- | --------------------- | ---------------------------------------------------------------------- |
| `FILE`        | positional            | Input binary                                                           |
| `--json`      | bool                  | Conflicts with `--yara`                                                |
| `--yara`      | bool                  | Conflicts with `--json`                                                |
| `--only-tags` | `Vec<Tag>`            | Repeatable, `value_parser = Tag::from_str`                             |
| `--notags`    | `Vec<Tag>`            | Repeatable, runtime overlap check with `--only-tags`                   |
| `--min-len`   | `Option<usize>`       | Default 4, custom parser enforces >= 1                                 |
| `--top`       | `Option<usize>`       | Custom parser enforces >= 1                                            |
| `--enc`       | `Option<CliEncoding>` | ascii, utf8, utf16, utf16le, utf16be                                   |
| `--raw`       | bool                  | Conflicts with `--only-tags`, `--notags`, `--top`, `--debug`, `--yara` |
| `--summary`   | bool                  | Conflicts with `--json`, `--yara`; runtime TTY check                   |
| `--debug`     | bool                  | Conflicts with `--raw`                                                 |

### Regex Patterns

Use `lazy_static!` or `once_cell::sync::Lazy` for compiled regexes. Always use `.expect("descriptive message")` instead of `.unwrap()` for regex compilation - invalid regex patterns should fail fast with clear error messages.

## Development Commands

```bash
just gen-fixtures # Generate test fixtures (ELF/PE/Mach-O via Zig cross-compilation)
just check      # Pre-commit: fmt + lint + test
just test       # Run tests with nextest
just lint       # Full lint suite
just fix        # Auto-fix clippy warnings
just ci-check   # Full CI suite locally
just build      # Debug build
just run <args> # Run stringy with arguments
just bench      # Run benchmarks
just format     # Format all (Rust, JSON, YAML, Markdown, Justfile)
```

## CI Architecture

- CI workflows use `just` recipes as single source of truth, except Quality/MSRV jobs
- **All other jobs**: Use `jdx/mise-action@v3` for tooling -- `just` recipes work here
- See GOTCHAS.md for CI edge cases (Quality/MSRV jobs, mise cargo subcommands, Mergify).

## Testing

- Use `insta` for snapshot testing
- Binary fixtures in `tests/fixtures/`
- Integration tests use two naming patterns: `integration_*.rs` (CLI and format tests) and `test_*.rs` (extraction and filter tests)
- Compiled fixtures (ELF, PE, Mach-O) are gitignored -- run `just gen-fixtures` before `just test`
- Fixtures are cross-compiled via Zig (managed by mise) -- no Docker required
- `test_empty.bin` and `test_unknown.bin` are committed (platform-independent)
- Regenerate snapshots after changing `test_binary.c`: `INSTA_UPDATE=always cargo nextest run`
- `integration_flows_1_5.rs` contains end-to-end CLI flow tests (quick analysis, filtering, top-N, JSON, YARA)
- `assert_cmd` is non-TTY; use `format_table_with_mode(..., true)` to test TTY table output at the library level

## Imports

Import from `stringy::extraction` or `stringy::types`, not deeply nested paths. Re-exports are in `lib.rs`. Pipeline types (`Pipeline`, `PipelineConfig`, `FilterConfig`, `EncodingFilter`) are re-exported from `lib.rs`. New public pipeline types must be added to both `pipeline/mod.rs` re-exports and `lib.rs`.

## Key Dependencies

- `goblin` - Binary format parsing (ELF, PE, Mach-O)
- `mmap-guard` - Safe memory-mapped file I/O (wraps `memmap2`)
- `pelite` - PE resource extraction
- `thiserror` - Error type definitions
- `indicatif` - Progress bars and spinners for CLI output
- `tempfile` - Temporary file creation for stdin-to-Pipeline bridging in `main.rs`
- `insta` - Snapshot testing (dev)
- `criterion` - Benchmarking (dev)

## Adding Features

**New semantic tag**: Add variant to `Tag` enum in `types/mod.rs`, implement pattern in `classification/patterns/` or `classification/mod.rs`

**New section weight**: Add match arm in the relevant `container/*.rs` parser

**New string extractor**: Follow patterns in `extraction/` module

**Splitting large files**: When a file exceeds 500 lines, convert to a module directory: `foo.rs` -> `foo/mod.rs` + `foo/submodule.rs`. Move related code to submodules while keeping public re-exports in `mod.rs`.

## Open-Source Quality Standards (OSSF Best Practices)

Maintain these standards for OSSF Scorecard compliance:

### Every PR Must

- Sign off commits with `git commit -s` (DCO enforced by GitHub App)
- Pass CI (clippy, rustfmt, tests, CodeQL, cargo-deny) before merge
- Include tests for new functionality -- this is policy, not optional
- Be reviewed (human or CodeRabbit) for correctness, safety, and style
- Not introduce `unwrap()` in library code, unchecked errors, or unvalidated input

### Every Release Must

- Have human-readable release notes via git-cliff (not raw git log)
- Use unique SemVer identifiers (`vX.Y.Z` tags)
- Be built reproducibly (pinned toolchain, committed `Cargo.lock`, cargo-dist)

### Security

- Vulnerabilities go through private reporting (GitHub advisories or <support@evilbitlabs.io>), never public issues
- `cargo-deny` and `cargo-audit` run in CI -- fix findings promptly
- Medium+ severity vulnerabilities: we aim to release a fix within 90 days of confirmation (see SECURITY.md for canonical policy)

### Documentation

- Exported APIs require rustdoc comments with examples where appropriate
- CONTRIBUTING.md documents code review criteria, test policy, DCO, and governance
- SECURITY.md documents vulnerability reporting with scope, safe harbor, and PGP key
- AGENTS.md must accurately reflect implemented features (not aspirational)
