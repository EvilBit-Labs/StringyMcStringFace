# Troubleshooting

This guide helps resolve common issues when using Stringy. If you don't find a solution here, please check the [GitHub issues](https://github.com/EvilBit-Labs/Stringy/issues) or create a new issue.

## Installation Issues

### "cargo: command not found"

**Problem**: Rust/Cargo is not installed or not in PATH.

**Solution**:

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Verify installation
cargo --version
```

### Build Failures

**Problem**: Compilation errors during `cargo build`.

**Common causes and solutions**:

#### Outdated Rust Version

```bash
# Update Rust
rustup update

# Check version (should be 1.91+)
rustc --version
```

#### Missing System Dependencies

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install build-essential pkg-config

# Fedora/RHEL
sudo dnf groupinstall "Development Tools"
sudo dnf install pkg-config

# macOS
xcode-select --install
```

#### Network Issues

```bash
# Use alternative registry
export CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse

# Or use offline mode if dependencies are cached
cargo build --offline
```

### Permission Denied

**Problem**: Cannot execute the binary after installation.

**Solution**:

```bash
# Make binary executable
chmod +x ~/.cargo/bin/stringy

# Or reinstall with proper permissions
cargo install --path . --force
```

## Runtime Issues

### "Unsupported file format"

**Problem**: Stringy cannot detect the binary format.

**Diagnosis**:

```bash
# Check file type
file binary_file

# Check if it's actually a binary
hexdump -C binary_file | head
```

**Note**: Unknown or unparseable formats (plain text, etc.) do not error. Stringy falls back to unstructured raw byte scanning and succeeds. This message only appears if something else goes wrong during parsing.

### "Permission denied" when reading files

**Problem**: Cannot read the target binary file.

**Solutions**:

```bash
# Check file permissions
ls -l binary_file

# Make readable
chmod +r binary_file

# Run with appropriate privileges
sudo stringy system_binary
```

## Output Issues

### No Strings Found

**Problem**: Stringy reports no strings in a binary that should have strings.

**Diagnosis**:

```bash
# Check with traditional strings command
strings binary_file | head -20

# Try different encodings (one at a time)
stringy --enc ascii binary_file
stringy --enc utf8 binary_file
stringy --enc utf16le binary_file
stringy --enc utf16be binary_file

# Lower minimum length
stringy --min-len 1 binary_file
```

**Common causes**:

- Packed or encrypted binary
- Unusual string encoding
- Strings in unexpected sections
- Very short strings below minimum length

### Garbled Output

**Problem**: String output contains garbled or binary characters.

**Solutions**:

```bash
# Force specific encoding
stringy --enc ascii binary_file

# Increase minimum length to filter noise
stringy --min-len 6 binary_file

# Use JSON output which properly escapes invalid sequences
stringy --json binary_file | jq '.text'

# Filter by score
stringy --json binary_file | jq 'select(.score > 70)'
```

### Missing Expected Strings

**Problem**: Known strings are not appearing in output.

**Diagnosis**:

```bash
# Check if strings exist with traditional tools
strings binary_file | grep "expected_string"

# Try each encoding
stringy --enc ascii binary_file | grep "expected"
stringy --enc utf8 binary_file | grep "expected"
stringy --enc utf16le binary_file | grep "expected"

# Lower score threshold
stringy --json binary_file | jq 'select(.score > 0)' | grep "expected"
```

## Error Messages

### "--summary requires a TTY"

**Problem**: `--summary` flag used when stdout is piped or redirected.

**Solution**: `--summary` only works when stdout is a terminal. Remove `--summary` when piping output:

```bash
# This will error (exit 1):
stringy --summary binary | grep foo

# This works:
stringy --summary binary
```

### Tag overlap error

**Problem**: Same tag appears in both `--only-tags` and `--no-tags`.

**Solution**: Remove the duplicate tag from one of the two flags. This is a runtime validation error (exit 1).

### "Invalid UTF-8 sequence"

**Problem**: String contains invalid UTF-8 bytes.

**Solution**: This is usually normal for binary data. Stringy handles this automatically, but you can:

```bash
# Use ASCII only to avoid UTF-8 issues
stringy --enc ascii binary_file

# Use JSON output which properly escapes invalid sequences
stringy --json binary_file
```

### "Regex compilation failed"

**Problem**: Internal regex pattern compilation error.

**Solution**: This indicates a bug. Please report it with:

```bash
# Get version information
stringy --version
```

### File Not Found

**Problem**: The specified file does not exist.

**Exit code**: 1

**Solution**: Check the file path and ensure the file exists:

```bash
ls -l /path/to/binary
```

## Performance Issues

### Very Slow Processing

**Problem**: Stringy takes too long to process files.

**Solutions**:

```bash
# Increase minimum length to reduce extraction volume
stringy --min-len 8 large_file.exe

# Limit results
stringy --top 50 large_file.exe

# Use ASCII only
stringy --enc ascii large_file.exe

# Use raw mode (skip classification)
stringy --raw large_file.exe
```

### High Memory Usage

**Problem**: Stringy uses too much memory.

**Solutions**:

```bash
# Limit results
stringy --top 100 file.exe

# Increase minimum length
stringy --min-len 8 file.exe

# Use raw mode to skip classification
stringy --raw file.exe
```

## Exit Code Reference

| Code | Meaning                                                                    |
| ---- | -------------------------------------------------------------------------- |
| 0    | Success (including unknown binary format, empty binary, no filter matches) |
| 1    | Runtime error (file not found, tag overlap, `--summary` in non-TTY)        |
| 2    | Argument parsing error (invalid flag, flag conflict, invalid tag name)     |

## Debugging Tips

### Compare with Traditional Tools

```bash
# Compare with standard strings
strings binary_file > traditional.txt
stringy --json binary_file | jq -r '.text' > stringy.txt
diff traditional.txt stringy.txt
```

### Test with Known Good Files

```bash
# Test with system binaries
stringy /bin/ls        # Linux
stringy /bin/cat       # Linux
stringy /usr/bin/grep  # macOS
```

## Getting Help

### Information to Include in Bug Reports

1. **System information**:

   ```bash
   stringy --version
   rustc --version
   uname -a  # Linux/macOS
   ```

2. **File information**:

   ```bash
   file binary_file
   ls -l binary_file
   ```

3. **Exact command line used**

4. **Expected vs actual behavior**

### Where to Get Help

1. **Documentation**: Check this guide and the project documentation
2. **GitHub Issues**: Search existing issues or create a new one
3. **Discussions**: Use GitHub Discussions for questions and ideas
