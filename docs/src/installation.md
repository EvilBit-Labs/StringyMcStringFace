# Installation

## Pre-built Binaries

Pre-built binaries for Linux, macOS, and Windows are available on the [Releases] page.

Download the appropriate archive for your platform, extract it, and place the `stringy` binary somewhere on your PATH.

## From Source

### Prerequisites

- **Rust**: Version 1.91 or later (see [rustup.rs](https://rustup.rs/) if you need to install Rust)
- **Git**: For cloning the repository

### Build and Install

```bash
git clone https://github.com/EvilBit-Labs/Stringy
cd Stringy
cargo install --path .
```

This installs the `stringy` binary to `~/.cargo/bin/`, which should be in your PATH.

### Verify Installation

```bash
stringy --version
```

## Development Build

For development and testing, Stringy uses [just](https://just.systems/) and [mise](https://mise.jdx.dev/) to manage tooling:

```bash
git clone https://github.com/EvilBit-Labs/Stringy
cd Stringy
just setup         # Install tools and components
just gen-fixtures  # Generate test fixtures (requires Zig via mise)
just test          # Run tests
```

If you do not use `just`, the minimum requirements are:

```bash
cargo build --release
cargo test
```

## Troubleshooting

### Build Failures

Update Rust to the latest version:

```bash
rustup update
```

Clear the build cache:

```bash
cargo clean
cargo build --release
```

### Getting Help

If you encounter issues:

1. Check the [troubleshooting guide](./troubleshooting.md)
2. Search existing [GitHub issues](https://github.com/EvilBit-Labs/Stringy/issues)
3. Open a new issue with your OS, Rust version (`rustc --version`), and complete error output

## Next Steps

Once installed, see the [Quick Start](./quickstart.md) guide to begin using Stringy.

[releases]: https://github.com/EvilBit-Labs/Stringy/releases
