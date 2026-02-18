# Cross-platform justfile using OS annotations
# Windows uses PowerShell, Unix uses bash

set shell := ["bash", "-cu"]
set windows-shell := ["powershell", "-NoProfile", "-Command"]
set dotenv-load := true
set ignore-comments := true

# Use mise to manage all dev tools (cargo, node, pre-commit, etc.)
# See mise.toml for tool versions

mise_exec := "mise exec --"
root := justfile_dir()

# =============================================================================
# GENERAL COMMANDS
# =============================================================================

default:
    @just --choose

help:
    @just --list

# =============================================================================
# CROSS-PLATFORM HELPERS
# =============================================================================
# Cross-platform helpers using OS annotations
# Each helper has Windows and Unix variants

[windows]
cd-root:
    Set-Location "{{ root }}"

[unix]
cd-root:
    cd "{{ root }}"

[windows]
ensure-dir dir:
    New-Item -ItemType Directory -Force -Path "{{ dir }}" | Out-Null

[unix]
ensure-dir dir:
    /bin/mkdir -p "{{ dir }}"

[windows]
rmrf path:
    if (Test-Path "{{ path }}") { Remove-Item "{{ path }}" -Recurse -Force }

[unix]
rmrf path:
    /bin/rm -rf "{{ path }}"

# =============================================================================
# SETUP AND INITIALIZATION
# =============================================================================

# Development setup
[windows]
setup:
    @just mise-install
    rustup component add rustfmt clippy llvm-tools-preview
    @just mdformat-install
    Write-Host "Note: You may need to restart your shell for pipx PATH changes to take effect"

[unix]
setup:
    @just mise-install
    rustup component add rustfmt clippy llvm-tools-preview
    @just mdformat-install
    echo "Note: You may need to restart your shell for pipx PATH changes to take effect"

# Install tool versions defined in mise.toml
[windows]
mise-install:
    mise trust
    mise install

[unix]
mise-install:
    mise trust
    mise install

# Install development tools not managed by mise
[windows]
install-tools:
    @just mise-install
    @{{ mise_exec }} cargo binstall --disable-telemetry cargo-llvm-cov cargo-audit cargo-deny cargo-dist cargo-release cargo-cyclonedx cargo-auditable cargo-nextest --locked

[unix]
install-tools:
    @just mise-install
    @{{ mise_exec }} cargo binstall --disable-telemetry cargo-llvm-cov cargo-audit cargo-deny cargo-dist cargo-release cargo-cyclonedx cargo-auditable cargo-nextest --locked

# Install mdBook plugins for documentation
[windows]
docs-install:
    @just mise-install
    @{{ mise_exec }} cargo binstall mdbook-admonish mdbook-mermaid mdbook-linkcheck mdbook-toc mdbook-open-on-gh mdbook-tabs mdbook-i18n-helpers

[unix]
docs-install:
    @just mise-install
    @{{ mise_exec }} cargo binstall mdbook-admonish mdbook-mermaid mdbook-linkcheck mdbook-toc mdbook-open-on-gh mdbook-tabs mdbook-i18n-helpers

# Install pipx for Python tool management
[windows]
pipx-install:
    python -m pip install --user pipx
    python -m pipx ensurepath

[unix]
pipx-install:
    #!/bin/bash
    set -e
    set -u
    set -o pipefail

    if command -v pipx >/dev/null 2>&1; then
        echo "pipx already installed"
    else
        echo "Installing pipx..."
        python3 -m pip install --user pipx
        python3 -m pipx ensurepath
    fi

# Install mdformat and extensions for markdown formatting
[windows]
mdformat-install: pipx-install
    pipx install mdformat
    pipx inject mdformat mdformat-gfm mdformat-frontmatter mdformat-footnote mdformat-simple-breaks mdformat-gfm-alerts mdformat-toc mdformat-wikilink mdformat-tables

[unix]
mdformat-install:
    @just pipx-install
    pipx install mdformat
    pipx inject mdformat mdformat-gfm mdformat-frontmatter mdformat-footnote mdformat-simple-breaks mdformat-gfm-alerts mdformat-toc mdformat-wikilink mdformat-tables

# =============================================================================
# FORMATTING AND LINTING
# =============================================================================

alias format-rust := fmt
alias format-md := format-docs
alias format-just := fmt-justfile

# Main format recipe - calls all formatters
format: fmt format-json-yaml format-docs fmt-justfile

# Individual format recipes

format-json-yaml:
    @{{ mise_exec }} prettier --write "**/*.{json,yaml,yml}"

[windows]
format-docs:
    @if (Get-Command mdformat -ErrorAction SilentlyContinue) { Get-ChildItem -Recurse -Filter "*.md" | Where-Object { $_.FullName -notmatch "\\target\\" -and $_.FullName -notmatch "\\node_modules\\" } | ForEach-Object { mdformat $_.FullName } } else { Write-Host "mdformat not found. Run 'just mdformat-install' first." }

[unix]
format-docs:
    @if command -v mdformat >/dev/null 2>&1; then find . -type f -name "*.md" -not -path "./target/*" -not -path "./node_modules/*" -exec mdformat {} + ; else echo "mdformat not found. Run 'just mdformat-install' first."; fi

fmt:
    @{{ mise_exec }} cargo fmt --all

fmt-check:
    @{{ mise_exec }} cargo fmt --all --check

lint-rust: fmt-check
    @{{ mise_exec }} cargo clippy --workspace --all-targets --all-features -- -D warnings

lint-rust-min:
    @{{ mise_exec }} cargo clippy --workspace --all-targets --no-default-features -- -D warnings

# Format justfile
fmt-justfile:
    @just --fmt --unstable

# Lint justfile formatting
lint-justfile:
    @just --fmt --check --unstable

# Main lint recipe - calls all sub-linters
lint: lint-rust lint-actions lint-docs lint-justfile

# Individual lint recipes
lint-actions:
    @{{ mise_exec }} actionlint .github/workflows/*.yml

lint-docs:
    @{{ mise_exec }} markdownlint-cli2 docs/**/*.md README.md
    @{{ mise_exec }} lychee docs/**/*.md README.md

alias lint-just := lint-justfile

# Run clippy with fixes
fix:
    @{{ mise_exec }} cargo clippy --fix --allow-dirty --allow-staged

# Quick development check
check: pre-commit-run lint

pre-commit-run:
    @{{ mise_exec }} pre-commit run -a

# Format a single file (for pre-commit hooks)
format-files +FILES:
    @{{ mise_exec }} prettier --write --config .prettierrc.json {{ FILES }}

# =============================================================================
# BUILDING AND TESTING
# =============================================================================

build:
    @{{ mise_exec }} cargo build --workspace

build-release:
    @{{ mise_exec }} cargo build --workspace --release --all-features

test:
    @{{ mise_exec }} cargo nextest run --workspace --no-capture

# Test justfile cross-platform functionality
[windows]
test-justfile:
    $p = (Get-Location).Path; Write-Host "Current directory: $p"; Write-Host "Expected directory: {{ root }}"

[unix]
test-justfile:
    /bin/echo "Current directory: $(pwd -P)"
    /bin/echo "Expected directory: {{ root }}"

# Test cross-platform file system helpers
[windows]
test-fs:
    @just rmrf tmp/xfstest
    @just ensure-dir tmp/xfstest/sub
    @just rmrf tmp/xfstest

[unix]
test-fs:
    @just rmrf tmp/xfstest
    @just ensure-dir tmp/xfstest/sub
    @just rmrf tmp/xfstest

test-ci:
    @{{ mise_exec }} cargo nextest run --workspace --all-features --no-capture

# Run all tests including ignored/slow tests across workspace
test-all:
    @{{ mise_exec }} cargo nextest run --workspace --no-capture -- --ignored

# =============================================================================
# BENCHMARKING
# =============================================================================

# Run all benchmarks
bench:
    @{{ mise_exec }} cargo bench --workspace

# =============================================================================
# SECURITY AND AUDITING
# =============================================================================

audit:
    @{{ mise_exec }} cargo audit

deny:
    @{{ mise_exec }} cargo deny check

outdated:
    @{{ mise_exec }} cargo outdated --depth=1 --exit-code=1

# =============================================================================
# CI AND QUALITY ASSURANCE
# =============================================================================

# Generate coverage report
coverage:
    @{{ mise_exec }} cargo llvm-cov --workspace --all-features --lcov --output-path lcov.info

# Check coverage thresholds
coverage-check:
    @{{ mise_exec }} cargo llvm-cov --workspace --all-features --lcov --output-path lcov.info --fail-under-lines 9.7

# Full local CI parity check
ci-check: pre-commit-run fmt-check lint-rust lint-rust-min test-ci build-release audit coverage-check dist-plan

# =============================================================================
# DEVELOPMENT AND EXECUTION
# =============================================================================

run *args:
    @{{ mise_exec }} cargo run -p stringy -- {{ args }}

# =============================================================================
# DISTRIBUTION AND PACKAGING
# =============================================================================

dist:
    @{{ mise_exec }} dist build

dist-check:
    @{{ mise_exec }} dist plan

dist-plan:
    @{{ mise_exec }} dist plan

# Regenerate cargo-dist CI workflow safely
dist-generate-ci:
    @{{ mise_exec }} dist generate --ci github
    @echo "Generated CI workflow. Remember to fix any expression errors if they exist."
    @echo "Run 'just lint:actions' to validate the generated workflow."

install:
    @{{ mise_exec }} cargo install --path .

# =============================================================================
# DOCUMENTATION
# =============================================================================

# Build complete documentation (mdBook + rustdoc)
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
[unix]
docs-serve:
    cd docs && {{ mise_exec }} mdbook serve --open

# Clean documentation artifacts
[unix]
docs-clean:
    rm -rf docs/book target/doc

# Check documentation (build + link validation + formatting)
[unix]
docs-check:
    cd docs && {{ mise_exec }} mdbook build
    @just fmt-check

# Generate and serve documentation
[unix]
docs: docs-build docs-serve

[windows]
docs:
    @echo "mdbook requires a Unix-like environment to serve"

# =============================================================================
# GORELEASER TESTING
# =============================================================================

# Test GoReleaser configuration
goreleaser-check:
    @{{ mise_exec }} goreleaser check

# Build binaries locally with GoReleaser (test build process)
goreleaser-build:
    @{{ mise_exec }} goreleaser build --clean

# Run snapshot release (test full pipeline without publishing)
goreleaser-snapshot:
    @{{ mise_exec }} goreleaser release --snapshot --clean

# Test GoReleaser with specific target
[arg("target", help="Target triple to build for (e.g., x86_64-unknown-linux-gnu)")]
goreleaser-build-target target:
    @{{ mise_exec }} goreleaser build --clean --single-target {{ target }}

# Clean GoReleaser artifacts
goreleaser-clean:
    @just rmrf dist

# =============================================================================
# RELEASE MANAGEMENT
# =============================================================================

release:
    @{{ mise_exec }} cargo release

release-dry-run:
    @{{ mise_exec }} cargo release --dry-run

release-patch:
    @{{ mise_exec }} cargo release patch

release-minor:
    @{{ mise_exec }} cargo release minor

release-major:
    @{{ mise_exec }} cargo release major
