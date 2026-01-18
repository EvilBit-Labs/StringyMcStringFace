# Contributing to Stringy

Thanks for your interest in Stringy. This guide explains how to propose changes and what we expect for code quality.

## Quick start

1. Search existing issues and pull requests before filing a new one.
2. For bugs, open an issue with a clear reproduction and expected vs actual behavior.
3. For new features or larger changes, open an issue first to discuss scope.

## Development setup

Stringy uses Rust 2024 (MSRV 1.85+, see `rust-toolchain.toml`). We also use just for common tasks.

Recommended workflow:

- `just setup` (to install tools)
- `just build` (compiles a debug build)
- `just test` (runs tests)
- `just lint` (runs linters)

If you do not use just, the critical requirement is that:

- `cargo clippy -- -D warnings` passes
- `cargo fmt` produces no changes

## Coding standards

These rules are enforced by CI:

- No unsafe code
- Zero warnings (`clippy -D warnings`)
- ASCII only in code and documentation, unless explicitly working with Unicode handling
- Keep files under 500-600 lines; split when needed
- No blanket `#[allow]` on modules or files
- No async; this is a synchronous CLI tool

Use thiserror for structured errors and include context (offsets, section names, file paths) when relevant.

## Project-specific guidance

Module layout:

- `container/` handles format detection and section analysis
- `extraction/` handles string extraction, filtering, and deduplication
- `classification/` handles semantic tagging and ranking
- `output/` handles output formatters
- `types.rs` contains core data structures and error types
  
Key patterns:

- Section weights: add new section weights in `container/*.rs` using existing match patterns. Higher weight means more likely to contain useful strings.
- Semantic tags: add new Tag variants in `types.rs`, implement detection in `classification/semantic.rs`, and update any tag merging logic if needed.
- Deduplication: preserve all occurrences and merge tags across occurrences in `extraction/dedup.rs`.
- Public structs: keep public API structs non_exhaustive and provide explicit constructors.
- Imports: prefer `stringy::extraction` or `stringy::types`. Do not import locally-defined types inside `extraction/mod.rs`.

## Tests

- Add or update tests for behavior changes.
- Use insta snapshots for output verification when appropriate.
- Integration tests live in tests/ and fixtures in tests/fixtures/.
- Use insta snapshots for output verification when changing output formatters.

Run:

- `just test`

## Pull requests

- Keep PRs focused and small when possible.
- Include a clear description of the problem and the solution.
- Link related issues in the PR description.
- Update documentation when behavior changes.

## Documentation

Docs live under docs/ and project planning artifacts are in project_plan/. Update them when you change user-facing behavior.

## Security

If you believe you found a security issue, please do not open a public issue. Use GitHub Security Advisories if available, or contact the maintainers privately.

## Questions

If you are unsure where to start, open an issue with your question and we will point you in the right direction.
