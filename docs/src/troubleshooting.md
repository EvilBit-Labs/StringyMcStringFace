# Troubleshooting

This guide helps resolve common issues when using Stringy. If you don't find a solution here, please check the [GitHub issues](https://github.com/EvilBit-Labs/string_mcstringface/issues) or create a new issue.

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

# Check version (should be 1.70+)
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

**Solutions**:

- Ensure the file is actually a binary (ELF, PE, or Mach-O)
- Check if the file is corrupted or truncated
- Try with a known good binary first

### "Memory mapping error"

**Problem**: Cannot memory-map large files.

**Diagnosis**:

```bash
# Check available memory
free -h  # Linux
vm_stat  # macOS

# Check file size
ls -lh large_file.exe
```

**Solutions**:

```bash
# Disable memory mapping
stringy --no-mmap large_file.exe

# Increase virtual memory (if possible)
ulimit -v unlimited

# Process on a system with more RAM
```

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

## Performance Issues

### Very Slow Processing

**Problem**: Stringy takes too long to process files.

**Diagnosis**:

```bash
# Enable timing to identify bottlenecks
stringy --timing slow_file.exe

# Check system resources
top  # or htop
```

**Solutions**:

#### Large Files

```bash
# Focus on high-value sections
stringy --sections .rodata,.rdata large_file.exe

# Increase minimum length
stringy --min-len 8 large_file.exe

# Limit results
stringy --top 50 large_file.exe
```

#### Many Small Strings

```bash
# Increase minimum length
stringy --min-len 6 file.exe

# Disable expensive classification
stringy --no-classify file.exe

# Use ASCII only
stringy --enc ascii file.exe
```

#### Complex Patterns

```bash
# Disable specific pattern types
stringy --exclude b64,fmt file.exe

# Use simpler patterns only
stringy --only url,domain,filepath file.exe
```

### High Memory Usage

**Problem**: Stringy uses too much memory.

**Solutions**:

```bash
# Limit string length
stringy --max-len 200 file.exe

# Limit results
stringy --top 100 file.exe

# Use memory mapping
stringy --force-mmap file.exe

# Process sections individually
for section in .rodata .rdata; do
    stringy --sections $section file.exe
done
```

## Output Issues

### No Strings Found

**Problem**: Stringy reports no strings in a binary that should have strings.

**Diagnosis**:

```bash
# Check with traditional strings command
strings binary_file | head -20

# Try different encodings
stringy --enc ascii,utf8,utf16le,utf16be binary_file

# Lower minimum length
stringy --min-len 1 binary_file

# Include all sections
stringy --all-sections binary_file
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

# Use JSON output to avoid terminal issues
stringy --json binary_file | jq '.[] | .text'

# Filter by confidence
stringy --json binary_file | jq 'select(.score > 70)'
```

### Missing Expected Strings

**Problem**: Known strings are not appearing in output.

**Diagnosis**:

```bash
# Check if strings exist with traditional tools
strings binary_file | grep "expected_string"

# Try all encodings
stringy --enc ascii,utf8,utf16le,utf16be binary_file | grep "expected"

# Include debug sections
stringy --debug binary_file | grep "expected"

# Lower score threshold
stringy --json binary_file | jq 'select(.score > 0)' | grep "expected"
```

## Format-Specific Issues

### PE Files (Windows)

#### Missing Version Information

```bash
# Explicitly enable PE resources
stringy --pe-version --pe-manifest app.exe

# Check if resources exist
stringy --sections .rsrc app.exe
```

#### UTF-16 Issues

```bash
# Force UTF-16 extraction
stringy --enc utf16le app.exe

# Use UTF-16 only mode
stringy --utf16-only app.exe
```

### ELF Files (Linux)

#### Missing Symbol Names

```bash
# Include symbol tables
stringy --symbols elf_binary

# Include debug information
stringy --debug elf_binary

# Check specific sections
stringy --sections .dynstr,.strtab elf_binary
```

### Mach-O Files (macOS)

#### Fat Binary Issues

```bash
# Process all architectures
stringy --macho-fat app

# Check file structure first
file app
lipo -info app  # if available
```

## Error Messages

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

# Run with debug output
RUST_LOG=debug stringy binary_file 2> debug.log
```

### "Section not found"

**Problem**: Specified section doesn't exist in the binary.

**Diagnosis**:

```bash
# List available sections
stringy --list-sections binary_file

# Use correct section names
stringy --sections .text,.data binary_file  # ELF
stringy --sections .rdata,.rsrc binary.exe  # PE
```

## Debugging Tips

### Enable Debug Logging

```bash
# Set log level
export RUST_LOG=stringy=debug
stringy binary_file

# Or for all components
export RUST_LOG=debug
stringy binary_file
```

### Verbose Output

```bash
# Show detailed processing information
stringy --verbose binary_file

# Show timing for each stage
stringy --timing binary_file

# Combine with JSON for machine processing
stringy --json --verbose binary_file > debug_output.json
```

### Compare with Traditional Tools

```bash
# Compare with standard strings
strings binary_file > traditional.txt
stringy --json binary_file | jq -r '.[] | .text' > stringy.txt
diff traditional.txt stringy.txt
```

### Test with Known Good Files

```bash
# Test with system binaries
stringy /bin/ls        # Linux
stringy /bin/cat       # Linux  
stringy C:\Windows\System32\notepad.exe  # Windows
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

3. **Complete error output**:

   ```bash
   RUST_LOG=debug stringy binary_file 2>&1 | tee error.log
   ```

4. **Minimal reproduction case**:

   - Smallest file that reproduces the issue
   - Exact command line used
   - Expected vs actual behavior

### Where to Get Help

1. **Documentation**: Check this guide and the [API documentation](./api.md)
2. **GitHub Issues**: Search existing issues or create a new one
3. **Discussions**: Use GitHub Discussions for questions and ideas
4. **Community**: Join discussions in the project community

### Creating Good Bug Reports

```markdown
## Bug Description
Brief description of the issue.

## Environment
- OS: Linux/Windows/macOS version
- Stringy version: x.y.z
- Rust version: x.y.z

## Steps to Reproduce
1. Run command: `stringy --options file.exe`
2. Observe error: [error message]

## Expected Behavior
What should happen.

## Actual Behavior
What actually happens.

## Additional Context
- File type: PE/ELF/Mach-O
- File size: XXX MB
- Any relevant logs or output
```

This troubleshooting guide should help resolve most common issues. For persistent problems, don't hesitate to reach out to the community or maintainers.
