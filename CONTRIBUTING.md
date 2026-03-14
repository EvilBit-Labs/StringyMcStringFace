# Contributing to Stringy

Thanks for your interest in Stringy. This guide explains how to propose changes and what we expect for code quality.

> **Before you start:** check [GOTCHAS.md](GOTCHAS.md) for hard-won lessons and edge cases organized by domain (struct literals, CLI, CI, dependencies, pipeline). It will save you from common pitfalls that have tripped up contributors before.

## Quick start

1. Search existing issues and pull requests before filing a new one.
2. For bugs, open an issue with a clear reproduction and expected vs actual behavior.
3. For new features or larger changes, open an issue first to discuss scope.

## Development setup

Stringy uses Rust 2024 (MSRV 1.91+, see `rust-toolchain.toml`). We also use just for common tasks.

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

- No unsafe code (`#![forbid(unsafe_code)]`)
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
- `pipeline/` handles orchestration: config, filtering, normalization, `Pipeline::run`
- `types/` contains core data structures and error types

Key patterns:

- Section weights: add new section weights in `container/*.rs` using existing match patterns. Higher weight means more likely to contain useful strings.
- Semantic tags: add new Tag variants in `types/mod.rs`, implement detection in `classification/`, and update any tag merging logic if needed.
- Deduplication: preserve all occurrences and merge tags across occurrences in `extraction/dedup.rs`.
- Public structs: keep public API structs non_exhaustive and provide explicit constructors.
- Imports: prefer `stringy::extraction` or `stringy::types`. Do not import deeply nested paths.

## Tests

- Add or update tests for behavior changes.
- Use insta snapshots for output verification when appropriate.
- Integration tests live in tests/ and fixtures in tests/fixtures/.

Run:

- `just test`

## Pull requests

- Keep PRs focused and small when possible.
- Include a clear description of the problem and the solution.
- Link related issues in the PR description.
- Update documentation when behavior changes.

### Code review requirements

All pull requests require review before merging. Reviewers check for:

- **Correctness**: Does the code do what it claims? Are edge cases handled?
- **Safety**: No unsafe code, proper bounds checking, no panics/unwraps in library code
- **Tests**: New functionality has tests, existing tests still pass
- **Style**: Follows project conventions, passes `cargo fmt` and `cargo clippy -- -D warnings`
- **Documentation**: Public APIs have rustdoc, AGENTS.md updated if architecture changes

CI must pass before merge. The merge queue requires quality, MSRV, test, cross-platform test, and coverage checks. Security audit and CodeQL run as additional CI jobs but are not currently merge-blocking.

## Developer Certificate of Origin (DCO)

This project requires all contributors to sign off on their commits, certifying that they have the right to submit the code under the project's license. This is enforced by the [DCO GitHub App](https://github.com/apps/dco).

To sign off, add `-s` to your commit command:

```bash
git commit -s -m "feat: add new feature"
```

This adds a `Signed-off-by` line to your commit message:

```text
Signed-off-by: Your Name <your.email@example.com>
```

By signing off, you agree to the [Developer Certificate of Origin](https://developercertificate.org/).

## Documentation

Docs live under docs/ and project planning artifacts are in project_plan/. Update them when you change user-facing behavior.

## Security

If you believe you found a security issue, please do not open a public issue. See [SECURITY.md](SECURITY.md) for reporting instructions, scope, and our PGP key.

## Project governance

### Decision-making

Stringy uses a **maintainer-driven** governance model. Decisions are made by the project maintainers through consensus on GitHub issues and pull requests.

### Roles

| Role            | Responsibilities                                                           | Current                                                                                        |
| --------------- | -------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| **Maintainer**  | Merge PRs, manage releases, set project direction, review security reports | [@unclesp1d3r](https://github.com/unclesp1d3r), [@KryptoKat08](https://github.com/KryptoKat08) |
| **Contributor** | Submit issues, PRs, and participate in discussions                         | Anyone following this guide                                                                    |

### How decisions are made

- **Bug fixes and minor changes**: Any maintainer can review and merge
- **New features**: Discussed in a GitHub issue before implementation; maintainer approval required
- **Architecture changes**: Require agreement from both maintainers
- **Breaking API changes**: Discussed in a GitHub issue with community input; require agreement from both maintainers

### Becoming a maintainer

As the project grows, active contributors who demonstrate sustained, high-quality contributions and alignment with project goals may be invited to become maintainers.

## AI-assisted development

This project includes Claude Code configuration in `.claude/settings.json`. These settings enable plugins that help maintain code quality and follow project conventions. If you use Claude Code, the configuration will be applied automatically.

## Questions

If you are unsure where to start, open an issue with your question and we will point you in the right direction.
