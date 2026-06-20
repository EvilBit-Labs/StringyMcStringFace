# Stringy justfile -- run `just` or `just --list` to see available recipes.
#
# Windows uses PowerShell, Unix uses bash. mise manages every dev tool
# (Rust toolchain + components, cargo subcommands, mdbook plugins, mdformat,
# zig, etc.) -- see mise.toml. There are no per-tool install recipes; `setup`
# just runs `mise install`.

set shell := ["bash", "-cu"]
set windows-shell := ["powershell", "-NoProfile", "-Command"]
set dotenv-load
set ignore-comments
set quiet

mise_exec := "mise exec --"
root := justfile_dir()

# General

[private]
default:
    just --choose

[group('general')]
help:
    just --list

# Cross-platform helpers. Each keeps Windows and Unix variants only because
# the underlying shell command genuinely differs.

[private]
[windows]
ensure-dir dir:
    New-Item -ItemType Directory -Force -Path "{{ dir }}" | Out-Null

[private]
[unix]
ensure-dir dir:
    /bin/mkdir -p "{{ dir }}"

[private]
[windows]
rmrf path:
    if (Test-Path "{{ path }}") { Remove-Item "{{ path }}" -Recurse -Force }

[private]
[unix]
rmrf path:
    /bin/rm -rf "{{ path }}"

# Setup

# Development setup. mise installs every tool from mise.toml, including the
# Rust toolchain + components, all cargo subcommands, the mdbook plugins,
# and mdformat -- so there are no separate per-tool install recipes.
[group('setup')]
setup:
    mise trust
    mise install

# Update dependencies
[group('setup')]
update-deps:
    mise upgrade --bump --local
    {{ mise_exec }} cargo update --workspace
    {{ mise_exec }} pre-commit autoupdate

# Formatting and Linting

alias format-rust := fmt
alias format-md := format-docs
alias format-just := fmt-justfile

# Run every formatter
[group('quality')]
format: fmt format-json-yaml format-docs fmt-justfile

[group('quality')]
format-json-yaml:
    {{ mise_exec }} prettier --write "**/*.{json,yaml,yml}"

[group('quality')]
[windows]
format-docs:
    Get-ChildItem -Recurse -Filter "*.md" | Where-Object { $_.FullName -notmatch "\\target\\" -and $_.FullName -notmatch "\\node_modules\\" } | ForEach-Object { {{ mise_exec }} mdformat $_.FullName }

[group('quality')]
[unix]
format-docs:
    find . -type f -name "*.md" -not -path "./target/*" -not -path "./node_modules/*" -exec {{ mise_exec }} mdformat {} +

[group('quality')]
fmt:
    {{ mise_exec }} cargo fmt --all

[group('quality')]
fmt-check:
    {{ mise_exec }} cargo fmt --all --check

[group('quality')]
lint-rust: fmt-check
    {{ mise_exec }} cargo clippy --workspace --all-targets --all-features -- -D warnings

[group('quality')]
lint-rust-min:
    {{ mise_exec }} cargo clippy --workspace --all-targets --no-default-features -- -D warnings

# Format justfile
[group('quality')]
fmt-justfile:
    just --fmt --unstable

# Lint justfile formatting
[group('quality')]
lint-justfile:
    just --fmt --check --unstable

# Run every linter
[group('quality')]
lint: lint-rust lint-actions lint-docs lint-justfile

[group('quality')]
lint-actions:
    {{ mise_exec }} actionlint .github/workflows/*.yml

[group('quality')]
lint-docs:
    {{ mise_exec }} markdownlint-cli2 docs/**/*.md README.md
    {{ mise_exec }} lychee docs/**/*.md README.md

alias lint-just := lint-justfile

# Run clippy with fixes
[group('quality')]
fix:
    {{ mise_exec }} cargo clippy --fix --allow-dirty --allow-staged

# Quick development check
[group('quality')]
check: pre-commit-run lint

[private]
pre-commit-run:
    {{ mise_exec }} pre-commit run -a

# Format a single file (for pre-commit hooks)
[group('quality')]
format-files +FILES:
    {{ mise_exec }} prettier --write --config .prettierrc.json {{ FILES }}

# Building and Testing

[group('build')]
build:
    {{ mise_exec }} cargo build --workspace

[group('build')]
build-release:
    {{ mise_exec }} cargo build --workspace --release --all-features

[group('test')]
test:
    {{ mise_exec }} cargo nextest run --workspace --no-capture

[group('test')]
test-ci:
    {{ mise_exec }} cargo nextest run --workspace --all-features --no-capture

# Run all tests including ignored/slow tests across workspace
[group('test')]
test-all:
    {{ mise_exec }} cargo nextest run --workspace --no-capture -- --ignored

# Run all benchmarks
[group('test')]
bench:
    {{ mise_exec }} cargo bench --workspace

# Test Fixtures

# Zig cross-compiles test fixtures for all targets from any host.
# Changing the Zig version in mise.toml may alter compiled layouts,
# which breaks insta snapshots. After bumping, run:
#   just gen-fixtures
#   INSTA_UPDATE=always cargo nextest run
#   cargo insta accept          # review & commit updated snapshots

# Generate all test fixtures via Zig cross-compilation
[group('test')]
gen-fixtures:
    just ensure-dir tests/fixtures
    {{ mise_exec }} zig cc -target x86_64-linux-gnu -o tests/fixtures/test_binary_elf tests/fixtures/test_binary.c
    {{ mise_exec }} zig cc -target x86_64-windows-gnu -o tests/fixtures/test_binary_pe.exe tests/fixtures/test_binary.c
    {{ mise_exec }} zig rc /fo tests/fixtures/test_binary_with_resources.res -- tests/fixtures/test_binary_with_resources.rc
    {{ mise_exec }} zig cc -target x86_64-windows-gnu -o tests/fixtures/test_binary_with_resources.exe tests/fixtures/test_binary_with_resources.c tests/fixtures/test_binary_with_resources.res
    just rmrf tests/fixtures/test_binary_with_resources.res
    # Zig bundles macOS libc stubs, so this works from any host without an Apple SDK.
    # The fixture only needs to be a valid Mach-O container for parser tests, not a runnable binary.
    {{ mise_exec }} zig cc -target x86_64-macos -o tests/fixtures/test_binary_macho tests/fixtures/test_binary.c
    just gen-static-fixtures

# Write the committed, platform-independent fixtures (empty file + unknown
# blob). Only the byte-writing primitive differs per OS; keep the two in sync.
[private]
[unix]
gen-static-fixtures:
    truncate -s 0 tests/fixtures/test_empty.bin
    printf '\xde\xad\xbe\xef\x00\x00\x00\x00NOT_A_BINARY\nhttp://example.com/test\n' > tests/fixtures/test_unknown.bin

[private]
[windows]
gen-static-fixtures:
    New-Item -ItemType File -Force -Path "tests/fixtures/test_empty.bin" | Out-Null
    [System.IO.File]::WriteAllBytes("tests/fixtures/test_unknown.bin", [byte[]]@(0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00) + [System.Text.Encoding]::ASCII.GetBytes("NOT_A_BINARY`nhttp://example.com/test`n"))

# Security and Auditing

[group('security')]
audit:
    {{ mise_exec }} cargo audit

[group('security')]
deny:
    {{ mise_exec }} cargo deny check

[group('security')]
outdated:
    {{ mise_exec }} cargo outdated --depth=1 --exit-code=1

# CI and Quality Assurance

# Generate coverage report
[group('ci')]
coverage:
    {{ mise_exec }} cargo llvm-cov --workspace --all-features --lcov --output-path lcov.info

# Check coverage thresholds
[group('ci')]
coverage-check:
    {{ mise_exec }} cargo llvm-cov --workspace --all-features --lcov --output-path lcov.info --fail-under-lines 9.7

# Full local CI parity check (gen-fixtures ensures compiled test binaries exist)
[group('ci')]
ci-check: pre-commit-run fmt-check lint-rust lint-rust-min gen-fixtures test-ci build-release audit coverage-check dist-check

# Development and Execution

[group('dev')]
run *args:
    {{ mise_exec }} cargo run -p stringy -- {{ args }}

# Distribution and Packaging

[group('dist')]
dist:
    {{ mise_exec }} dist build

[group('dist')]
dist-check:
    {{ mise_exec }} dist plan

alias dist-plan := dist-check

# Regenerate cargo-dist CI workflow safely
[group('dist')]
dist-generate-ci:
    {{ mise_exec }} dist generate --ci github
    echo "Generated CI workflow. Remember to fix any expression errors if they exist."
    echo "Run 'just lint-actions' to validate the generated workflow."

[group('dist')]
install:
    {{ mise_exec }} cargo install --path .

# Documentation

# Build complete documentation (mdBook + rustdoc)
[group('docs')]
[unix]
docs-build:
    #!/usr/bin/env bash
    set -euo pipefail
    # Build rustdoc
    {{ mise_exec }} cargo doc --no-deps --document-private-items --target-dir docs/book/api-temp
    # Move rustdoc output to final location
    mkdir -p docs/book/api
    cp -r docs/book/api-temp/doc/* docs/book/api/
    rm -rf docs/book/api-temp
    # Build mdBook
    cd docs && {{ mise_exec }} mdbook build

# Serve documentation locally with live reload
[group('docs')]
[unix]
docs-serve:
    cd docs && {{ mise_exec }} mdbook serve --open

# Clean documentation artifacts
[group('docs')]
[unix]
docs-clean:
    rm -rf docs/book target/doc

# Check documentation (build + link validation + formatting)
[group('docs')]
[unix]
docs-check:
    cd docs && {{ mise_exec }} mdbook build
    just fmt-check

# Generate and serve documentation
[group('docs')]
[unix]
docs: docs-build docs-serve

[group('docs')]
[windows]
docs:
    echo "mdbook requires a Unix-like environment to serve"

# GoReleaser Testing

# Test GoReleaser configuration
[group('dist')]
goreleaser-check:
    {{ mise_exec }} goreleaser check

# Build binaries locally with GoReleaser (test build process)
[group('dist')]
goreleaser-build:
    {{ mise_exec }} goreleaser build --clean

# Run snapshot release (test full pipeline without publishing)
[group('dist')]
goreleaser-snapshot:
    {{ mise_exec }} goreleaser release --snapshot --clean

# Test GoReleaser with specific target
[arg("target", help="Target triple to build for (e.g., x86_64-unknown-linux-gnu)")]
[group('dist')]
goreleaser-build-target target:
    {{ mise_exec }} goreleaser build --clean --single-target {{ target }}

# Clean GoReleaser artifacts
[group('dist')]
goreleaser-clean:
    just rmrf dist

# Release Management

[group('release')]
release:
    {{ mise_exec }} cargo release

[group('release')]
release-dry-run:
    {{ mise_exec }} cargo release --dry-run

[group('release')]
release-patch:
    {{ mise_exec }} cargo release patch

[group('release')]
release-minor:
    {{ mise_exec }} cargo release minor

[group('release')]
release-major:
    {{ mise_exec }} cargo release major
