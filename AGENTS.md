# AI Agent Guidelines for Stringy

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

| Module            | Purpose                                                          |
| ----------------- | ---------------------------------------------------------------- |
| `container/`      | Format detection, section analysis, imports/exports via `goblin` |
| `extraction/`     | ASCII/UTF-8/UTF-16 extraction, deduplication, PE resources       |
| `classification/` | Semantic tagging (URLs, IPs, domains, paths, GUIDs), ranking     |
| `output/`         | Formatters: `json/`, `table/` (tty/plain), `yara/`               |
| `types/`          | Core data structures, error handling with `thiserror`            |

## Key Patterns

### Section Weights

Container parsers assign weights (1.0-10.0) based on string likelihood. Higher = more valuable. See existing parsers in `container/*.rs` for reference values.

### Error Handling

Use `thiserror` with detailed context. Include offsets, section names, and file paths in error messages. Convert external errors with `From` implementations.

### Public API Structs

Use `#[non_exhaustive]` for public structs and provide explicit constructors. When using `#[non_exhaustive]` structs internally, always use the constructor pattern (`Type::new()`) rather than struct literals - struct literals bypass the forward-compatibility guarantee.

### Test-Only Code

For test utilities that shouldn't be in production builds:

- Add `#[cfg(test)]` to both the struct/type definition AND any impl blocks
- Use `pub(crate)` visibility for internal test helpers
- Keep test infrastructure in `#[cfg(test)] mod tests` blocks within the module

### Regex Patterns

Use `lazy_static!` or `once_cell::sync::Lazy` for compiled regexes. Always use `.expect("descriptive message")` instead of `.unwrap()` for regex compilation - invalid regex patterns should fail fast with clear error messages.

## Development Commands

```bash
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

- CI workflows use `just` recipes as single source of truth, except Quality/MSRV jobs (see below)
- **Quality/MSRV jobs**: Use `dtolnay/rust-toolchain` for Rust (pinned toolchain, matrix support) -- do NOT use `just` recipes here (they use `mise exec --` which conflicts)
- **All other jobs**: Use `jdx/mise-action@v3` for tooling -- `just` recipes work here
- cargo subcommands installed via mise (e.g. cargo-dist) must be invoked as standalone binaries (`dist plan`) not cargo subcommands (`cargo dist plan`) -- cargo can't find mise-managed subcommands
- Mergify merge protections evaluate from the **main branch** config, not the PR branch

## Testing

- Use `insta` for snapshot testing
- Binary fixtures in `tests/fixtures/`
- Integration tests named `integration_*.rs`

## Imports

Import from `stringy::extraction` or `stringy::types`, not deeply nested paths. Re-exports are in `lib.rs`.

## Key Dependencies

- `goblin` - Binary format parsing (ELF, PE, Mach-O)
- `pelite` - PE resource extraction
- `thiserror` - Error type definitions
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
