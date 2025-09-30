# Command Line Interface

**Note**: The CLI interface is currently under development. This documentation describes the planned interface.

## Basic Syntax

```bash
stringy [OPTIONS] <FILE>
```

## Global Options

### Input/Output

| Option              | Description                            | Default  |
| ------------------- | -------------------------------------- | -------- |
| `<FILE>`            | Binary file to analyze                 | Required |
| `--output <FILE>`   | Write output to file                   | stdout   |
| `--format <FORMAT>` | Output format: `human`, `json`, `yara` | `human`  |
| `--json`            | Shorthand for `--format json`          | -        |
| `--yara`            | Shorthand for `--format yara`          | -        |

### Filtering

| Option               | Description                 | Default       |
| -------------------- | --------------------------- | ------------- |
| `--min-len <N>`      | Minimum string length       | 4             |
| `--max-len <N>`      | Maximum string length       | 1024          |
| `--enc <ENCODINGS>`  | Comma-separated encodings   | `ascii,utf16` |
| `--only <TAGS>`      | Only show these tags        | All tags      |
| `--exclude <TAGS>`   | Exclude these tags          | None          |
| `--sections <NAMES>` | Only scan these sections    | All sections  |
| `--top <N>`          | Limit to top N results      | 100           |
| `--all`              | Show all results (no limit) | -             |

### Analysis Options

| Option       | Description               | Default       |
| ------------ | ------------------------- | ------------- |
| `--no-dedup` | Don't deduplicate strings | Deduplicate   |
| `--no-rank`  | Don't apply ranking       | Apply ranking |
| `--debug`    | Include debug sections    | Exclude debug |
| `--imports`  | Include import names      | Include       |
| `--exports`  | Include export names      | Include       |

## Format-Specific Options

### PE (Windows) Options

| Option          | Description                    |
| --------------- | ------------------------------ |
| `--pe-version`  | Extract version information    |
| `--pe-manifest` | Extract manifest resources     |
| `--pe-strings`  | Extract string table resources |
| `--utf16-only`  | Only extract UTF-16 strings    |

### ELF (Linux) Options

| Option          | Description                     |
| --------------- | ------------------------------- |
| `--elf-notes`   | Include note sections           |
| `--elf-dynamic` | Include dynamic section strings |
| `--elf-debug`   | Include DWARF debug info        |

### Mach-O (macOS) Options

| Option        | Description                             |
| ------------- | --------------------------------------- |
| `--macho-lc`  | Include load command strings            |
| `--macho-fat` | Process all architectures in fat binary |

## Encoding Options

### Supported Encodings

| Encoding  | Description            | Alias   |
| --------- | ---------------------- | ------- |
| `ascii`   | 7-bit ASCII            | `a`     |
| `utf8`    | UTF-8 (includes ASCII) | `u8`    |
| `utf16`   | UTF-16 (both endians)  | `u16`   |
| `utf16le` | UTF-16 Little Endian   | `u16le` |
| `utf16be` | UTF-16 Big Endian      | `u16be` |

### Examples

```bash
# ASCII only
stringy --enc ascii binary

# UTF-16 only (common for Windows)
stringy --enc utf16 app.exe

# Multiple encodings
stringy --enc ascii,utf16le,utf8 binary
```

## Tag Filtering

### Available Tags

| Tag        | Description      | Example                   |
| ---------- | ---------------- | ------------------------- |
| `url`      | HTTP/HTTPS URLs  | `https://api.example.com` |
| `domain`   | Domain names     | `example.com`             |
| `ipv4`     | IPv4 addresses   | `192.168.1.1`             |
| `ipv6`     | IPv6 addresses   | `2001:db8::1`             |
| `filepath` | File paths       | `/usr/bin/app`            |
| `regpath`  | Registry paths   | `HKEY_LOCAL_MACHINE\...`  |
| `guid`     | GUIDs/UUIDs      | `{12345678-1234-...}`     |
| `email`    | Email addresses  | `user@example.com`        |
| `b64`      | Base64 data      | `SGVsbG8=`                |
| `fmt`      | Format strings   | `Error: %s`               |
| `import`   | Import names     | `CreateFileW`             |
| `export`   | Export names     | `main`                    |
| `version`  | Version strings  | `v1.2.3`                  |
| `manifest` | Manifest data    | XML/JSON config           |
| `resource` | Resource strings | UI text                   |

### Examples

```bash
# Network indicators only
stringy --only url,domain,ipv4,ipv6 malware.exe

# Exclude noisy Base64
stringy --exclude b64 binary

# File system related
stringy --only filepath,regpath app.exe
```

## Section Filtering

### Common Section Names

#### ELF Sections

- `.rodata` - Read-only data
- `.data.rel.ro` - Read-only after relocation
- `.comment` - Build information
- `.note.*` - Various notes

#### PE Sections

- `.rdata` - Read-only data
- `.rsrc` - Resources
- `.data` - Initialized data

#### Mach-O Sections

- `__TEXT,__cstring` - C strings
- `__TEXT,__const` - Constants
- `__DATA_CONST` - Read-only data

### Examples

```bash
# High-value sections only
stringy --sections .rodata,.rdata,__cstring binary

# Resource sections
stringy --sections .rsrc app.exe

# Multiple sections
stringy --sections ".rodata,.data.rel.ro" elf_binary
```

## Output Formats

### Human-Readable Format

Default format for interactive use:

```bash
stringy binary
```

Output columns:

- **Score**: Relevance ranking (0-100)
- **Offset**: File offset (hex)
- **Section**: Section name
- **Encoding**: String encoding
- **Tags**: Semantic classifications
- **String**: The extracted string (truncated if long)

### JSON Lines Format

Machine-readable format:

```bash
stringy --json binary
```

Each line contains a JSON object:

```json
{
  "text": "https://api.example.com",
  "encoding": "utf-8",
  "offset": 4096,
  "rva": 4096,
  "section": ".rdata",
  "length": 23,
  "tags": [
    "url"
  ],
  "score": 95,
  "source": "SectionData"
}
```

### YARA Format

Optimized for security rule creation:

```bash
stringy --yara binary
```

Output includes:

- Properly escaped strings
- Hex representations for binary data
- Comments with metadata
- Grouped by confidence level

## Advanced Usage

### Pipeline Integration

```bash
# Extract URLs and check them
stringy --only url --json binary | jq -r '.text' | xargs -I {} curl -I {}

# Find high-confidence strings
stringy --json binary | jq 'select(.score > 80)'

# Count strings by tag
stringy --json binary | jq -r '.tags[]' | sort | uniq -c
```

### Batch Processing

```bash
# Process multiple files
find /path/to/binaries -type f -exec stringy --json {} \; > all_strings.jsonl

# Compare two versions
stringy --json old_binary > old.json
stringy --json new_binary > new.json
diff <(jq -r '.text' old.json | sort) <(jq -r '.text' new.json | sort)
```

### Performance Tuning

```bash
# Fast scan for high-value strings only
stringy --top 20 --min-len 8 --only url,guid,filepath large_binary

# Memory-efficient processing
stringy --sections .rodata --enc ascii huge_binary
```

## Configuration File

Future versions will support configuration files:

```toml
# ~/.config/stringy/config.toml
[default]
min_len = 6
encodings = ["ascii", "utf16"]
exclude_tags = ["b64"]
top = 50

[profiles.security]
only_tags = ["url", "domain", "ipv4", "ipv6", "filepath"]
min_len = 8

[profiles.yara]
format = "yara"
min_len = 10
exclude_tags = ["import", "export"]
```

Usage:

```bash
stringy --profile security malware.exe
```

## Exit Codes

| Code | Meaning            |
| ---- | ------------------ |
| 0    | Success            |
| 1    | General error      |
| 2    | Invalid arguments  |
| 3    | File not found     |
| 4    | Unsupported format |
| 5    | Permission denied  |

## Environment Variables

| Variable         | Description            | Default                         |
| ---------------- | ---------------------- | ------------------------------- |
| `STRINGY_CONFIG` | Config file path       | `~/.config/stringy/config.toml` |
| `STRINGY_CACHE`  | Cache directory        | `~/.cache/stringy/`             |
| `NO_COLOR`       | Disable colored output | -                               |

This comprehensive CLI interface provides flexibility for both interactive analysis and automated processing workflows.
