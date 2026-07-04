#!/usr/bin/env bash
#
# setup.sh - one-command bootstrap for a Stringy development environment.
#
# Stringy manages its entire toolchain (Rust, Zig, just, and friends) with mise.
# This script is a thin wrapper around that flow: it verifies mise is present,
# installs the pinned tools, and builds the test fixtures so `just test` works.
#
# It intentionally does NOT pipe a remote installer into your shell. If mise is
# missing, it prints the official install instructions and exits.
#
# Usage:
#   ./setup.sh
#
# For day-to-day tasks after setup, use the just recipes (see `just --list`).

set -euo pipefail

cd "$(dirname "$0")"

if ! command -v mise >/dev/null 2>&1; then
  cat >&2 <<'EOF'
error: mise is not installed.

Stringy uses mise (https://mise.jdx.dev) to manage its toolchain. Install it,
then re-run ./setup.sh. See https://mise.jdx.dev/getting-started.html

  macOS/Linux (Homebrew):  brew install mise
  macOS/Linux (script):    https://mise.jdx.dev/getting-started.html
  Windows:                 https://mise.jdx.dev/getting-started.html#windows

After installing, make sure mise is activated in your shell, or run the commands
below through `mise exec --`.
EOF
  exit 1
fi

echo "==> Installing pinned toolchain via mise"
mise trust
mise install

echo "==> Generating test fixtures (cross-compiled via Zig)"
mise exec -- just gen-fixtures

cat <<'EOF'

Setup complete. Next steps:

  just build      # debug build
  just test       # run the test suite
  just lint       # run the lint suite
  just ci-check   # full local CI parity check

Run `just --list` to see all available recipes.
EOF
