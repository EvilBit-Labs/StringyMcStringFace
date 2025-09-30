# Quick Start

This guide will get you up and running with Stringy in minutes.

## Basic Usage

**Note**: The CLI interface is currently under development. This guide shows the planned interface.

### Analyze a Binary

```bash
stringy /path/to/binary
```

This performs a basic analysis with default settings:

- Extracts ASCII and UTF-16 strings
- Applies semantic classification
- Shows top results in human-readable format

### Example Output

```text
Score  Offset    Section    Encoding  Tags           String
-----  ------    -------    --------  ----           ------
  95   0x1000    .rdata     utf-8     url,https      https://api.example.com/v1/users
  87   0x2000    .rdata     utf-8     guid           {12345678-1234-1234-1234-123456789abc}
  82   0x3000    __cstring  utf-8     filepath       /usr/local/bin/application
  78   0x4000    .rdata     utf-8     fmt            Error: %s at line %d
  75   0x5000    .rsrc      utf-16le  version        MyApplication v1.2.3
```

## Common Use Cases

### Security Analysis

Extract network indicators and file paths:

```bash
stringy --only url,domain,filepath,regpath malware.exe
```

### YARA Rule Development

Generate rule candidates:

```bash
stringy --yara --min-len 8 target.bin > candidates.txt
```

### JSON Output for Automation

```bash
stringy --json binary.elf | jq '.[] | select(.score > 80)'
```

### Focus on Specific Sections

```bash
stringy --sections .rdata,.rsrc windows_binary.exe
```

## Understanding the Output

### Score Column

Strings are ranked by relevance:

- **90-100**: High-confidence indicators (URLs, GUIDs, etc.)
- **70-89**: Likely meaningful strings (paths, format strings)
- **50-69**: Possible indicators (long strings, imports)
- **\<50**: Low confidence (short strings, common words)

### Tags

Semantic classifications help identify string types:

| Tag               | Description     | Example                   |
| ----------------- | --------------- | ------------------------- |
| `url`             | Web URLs        | `https://example.com/api` |
| `domain`          | Domain names    | `api.example.com`         |
| `ipv4`/`ipv6`     | IP addresses    | `192.168.1.1`             |
| `filepath`        | File paths      | `/usr/bin/app`            |
| `regpath`         | Registry paths  | `HKEY_LOCAL_MACHINE\...`  |
| `guid`            | GUIDs/UUIDs     | `{12345678-1234-...}`     |
| `email`           | Email addresses | `user@example.com`        |
| `b64`             | Base64 data     | `SGVsbG8gV29ybGQ=`        |
| `fmt`             | Format strings  | `Error: %s`               |
| `import`/`export` | Symbol names    | `CreateFileW`             |

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

# Maximum 100 characters  
stringy --max-len 100 binary
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
stringy --only url,domain,ipv4,ipv6 binary

# Exclude Base64 noise
stringy --exclude b64 binary
```

### Limit Results

```bash
# Top 50 results
stringy --top 50 binary

# All results (no limit)
stringy --all binary
```

## Output Formats

### Human-Readable (Default)

Best for interactive analysis:

```bash
stringy binary
```

### JSON Lines

For programmatic processing:

```bash
stringy --json binary | jq '.[] | select(.tags[] == "url")'
```

### YARA Format

For security rule creation:

```bash
stringy --yara binary > rule_candidates.txt
```

## Working with Different Formats

### Linux Binaries (ELF)

```bash
# Focus on read-only sections
stringy --sections .rodata,.data.rel.ro /bin/ls

# Include debug information
stringy --debug /usr/bin/app
```

### Windows Binaries (PE)

```bash
# Extract version information
stringy --pe-version app.exe

# Focus on resources
stringy --sections .rsrc,.rdata app.exe

# UTF-16 strings only
stringy --enc utf16 app.exe
```

### macOS Binaries (Mach-O)

```bash
# String sections
stringy --sections __TEXT,__cstring /usr/bin/app

# Load command strings
stringy --load-commands /Applications/App.app/Contents/MacOS/App
```

## Tips and Best Practices

### Start Broad, Then Focus

1. Run basic analysis first: `stringy binary`
2. Identify interesting patterns in high-scoring results
3. Use filters to focus on specific types: `--only url,filepath`

### Combine with Other Tools

```bash
# Find strings, then search for references
stringy --json binary | jq -r '.[] | select(.score > 80) | .text' | xargs -I {} grep -r "{}" /path/to/source

# Extract URLs for further analysis
stringy --only url --json binary | jq -r '.[] | .text' | sort -u
```

### Performance Considerations

- Use `--top N` to limit output for large binaries
- Filter by section to reduce processing time
- Consider `--min-len` to reduce noise

## Next Steps

- Learn about [output formats](./output-formats.md) in detail
- Understand the [classification system](./classification.md)
- Explore [advanced CLI options](./cli.md)
- Read about [performance optimization](./performance.md)
