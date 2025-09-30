# Installation

Stringy is currently in active development and not yet published to crates.io. You can install it from source or use development builds.

## Prerequisites

- **Rust**: Version 1.70 or later
- **Git**: For cloning the repository
- **Build tools**: Platform-specific C compiler (for some dependencies)

### Installing Rust

If you don't have Rust installed, get it from [rustup.rs](https://rustup.rs/):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

## From Source (Recommended)

### Clone and Build

```bash
git clone https://github.com/EvilBit-Labs/string_mcstringface
cd string_mcstringface
cargo build --release
```

### Install Locally

```bash
cargo install --path .
```

This installs the `stringy` binary to `~/.cargo/bin/`, which should be in your PATH.

### Verify Installation

```bash
stringy --help
```

## Development Build

For development and testing:

```bash
git clone https://github.com/EvilBit-Labs/string_mcstringface
cd string_mcstringface
cargo run -- --help
```

## Platform-Specific Notes

### Linux

Most distributions include the necessary build tools. If you encounter issues:

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install build-essential

# Fedora/RHEL
sudo dnf groupinstall "Development Tools"

# Arch Linux
sudo pacman -S base-devel
```

### macOS

Install Xcode command line tools:

```bash
xcode-select --install
```

### Windows

Install Visual Studio Build Tools or Visual Studio Community with C++ support.

Alternatively, use the GNU toolchain:

```bash
rustup toolchain install stable-x86_64-pc-windows-gnu
rustup default stable-x86_64-pc-windows-gnu
```

## Docker (Alternative)

If you prefer containerized builds:

```dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/stringy /usr/local/bin/
ENTRYPOINT ["stringy"]
```

Build and run:

```bash
docker build -t stringy .
docker run --rm -v $(pwd):/data stringy /data/binary_file
```

## Troubleshooting

### Common Issues

#### "cargo: command not found"

Ensure Rust is properly installed and `~/.cargo/bin` is in your PATH:

```bash
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

#### Build Failures

Update Rust to the latest version:

```bash
rustup update
```

Clear the build cache:

```bash
cargo clean
cargo build --release
```

#### Permission Denied

On Unix systems, ensure the binary is executable:

```bash
chmod +x ~/.cargo/bin/stringy
```

### Getting Help

If you encounter issues:

1. Check the [troubleshooting guide](./troubleshooting.md)
2. Search existing [GitHub issues](https://github.com/EvilBit-Labs/string_mcstringface/issues)
3. Open a new issue with:
   - Your operating system and version
   - Rust version (`rustc --version`)
   - Complete error output
   - Steps to reproduce

## Next Steps

Once installed, see the [Quick Start](./quickstart.md) guide to begin using Stringy.
