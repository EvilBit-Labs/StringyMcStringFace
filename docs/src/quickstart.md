# Quick Start

This guide will get you up and running with Stringy in minutes.

## Basic Usage

### Analyze a Binary

```bash
stringy /path/to/binary
```

Stringy will:

- Detect ELF, PE, or Mach-O format automatically
- Extract ASCII and UTF-16 strings from prioritized sections
- Apply semantic classification (URLs, paths, GUIDs, etc.)
- Rank results by relevance and display them in a table

### Example Output (TTY)

```text
String                                   Tags              Score  Section
------                                   ----              -----  -------
https://api.example.com/v1/users         Url                 95   .rdata
{12345678-1234-1234-1234-123456789abc}   guid                87   .rdata
/usr/local/bin/application               filepath            82   __cstring
Error: %s at line %d                     fmt                 78   .rdata
MyApplication v1.2.3                     Version             75   .rsrc
```

## Common Use Cases

### Security Analysis

Extract network indicators and file paths:

```bash
stringy --only-tags url --only-tags domain --only-tags filepath --only-tags regpath malware.exe
```

### YARA Rule Development

Generate rule candidates:

```bash
stringy --yara --min-len 8 target.bin > candidates.yar
```

### JSON Output for Automation

```bash
stringy --json --debug binary.elf | jq 'select(.display_score > 80)'
```

### Extraction-Only Mode

Skip classification and ranking for fast raw extraction:

```bash
stringy --raw binary
```

## Understanding the Output

### Score Column

Strings are ranked using a display score from 0-100:

- **90-100**: High-value indicators (URLs, GUIDs in high-priority sections)
- **70-89**: Meaningful strings (file paths, format strings)
- **50-69**: Moderate relevance (imports, version info)
- **0-49**: Low relevance (short or noisy strings)

See [Output Formats](./output-formats.md) for the full band-mapping table.

### Tags

Semantic classifications help identify string types:

| Tag               | Description             | Example                   |
| ----------------- | ----------------------- | ------------------------- |
| `url`             | Web URLs                | `https://example.com/api` |
| `domain`          | Domain names            | `api.example.com`         |
| `ipv4`/`ipv6`     | IP addresses            | `192.168.1.1`             |
| `filepath`        | File paths              | `/usr/bin/app`            |
| `regpath`         | Registry paths          | `HKEY_LOCAL_MACHINE\...`  |
| `guid`            | GUIDs/UUIDs             | `{12345678-1234-...}`     |
| `email`           | Email addresses         | `user@example.com`        |
| `b64`             | Base64 data             | `SGVsbG8gV29ybGQ=`        |
| `fmt`             | Format strings          | `Error: %s`               |
| `import`/`export` | Symbol names            | `CreateFileW`             |
| `user-agent-ish`  | User-agent-like strings | `Mozilla/5.0 ...`         |
| `dylib-path`      | Dynamic library paths   | `/usr/lib/libfoo.dylib`   |
| `rpath`           | Runtime search paths    | `/usr/local/lib`          |
| `rpath-var`       | Rpath variables         | `@loader_path/../lib`     |
| `framework-path`  | Framework paths (macOS) | `/System/Library/...`     |

### Sections

Shows where strings were found:

- **ELF**: `.rodata`, `.data.rel.ro`, `.comment`
- **PE**: `.rdata`, `.rsrc`, version info
- **Mach-O**: `__TEXT,__cstring`, `__DATA_CONST`

## Filtering and Options

### By String Length

```bash
# Minimum 6 characters
stringy --min-len 6 binary
```

### By Encoding

```bash
# ASCII only
stringy --enc ascii binary

# UTF-16 only (useful for Windows binaries)
stringy --enc utf16 binary.exe
```

### By Tags

```bash
# Only network-related strings
stringy --only-tags url --only-tags domain --only-tags ipv4 --only-tags ipv6 binary

# Exclude Base64 noise
stringy --notags b64 binary
```

### Limit Results

```bash
# Top 50 results
stringy --top 50 binary
```

### Summary

Append a summary block after table output (TTY only):

```bash
stringy --summary binary
```

## Output Formats

### Table (Default)

Best for interactive analysis:

```bash
stringy binary
```

### JSON Lines

For programmatic processing:

```bash
stringy --json binary | jq 'select(.tags[] == "Url")'
```

### YARA Format

For security rule creation:

```bash
stringy --yara binary > rule_candidates.yar
```

## Tips and Best Practices

### Start Broad, Then Focus

1. Run basic analysis first: `stringy binary`
2. Identify interesting patterns in high-scoring results
3. Use filters to focus: `--only-tags url --only-tags filepath`

### Combine with Other Tools

```bash
# Find strings, then search for references
stringy --json binary | jq -r 'select(.score > 80) | .text' | xargs -I {} grep -r "{}" /path/to/source

# Extract URLs for further analysis
stringy --only-tags url --json binary | jq -r '.text' | sort -u
```

### Performance Considerations

- Use `--top N` to limit output for large binaries
- Use `--enc` to restrict to a single encoding
- Consider `--min-len` to reduce noise

## Next Steps

- Learn about [output formats](./output-formats.md) in detail
- Understand the [classification system](./classification.md)
- Explore [advanced CLI options](./cli.md)
- Read about [performance optimization](./performance.md)
