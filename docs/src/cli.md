# Command Line Interface

## Basic Syntax

```bash
stringy [OPTIONS] <FILE>
stringy [OPTIONS] -        # read from stdin
```

## Options

### Input/Output

| Option      | Description                                | Default |
| ----------- | ------------------------------------------ | ------- |
| `<FILE>`    | Binary file to analyze (use `-` for stdin) | -       |
| `--json`    | JSONL output; conflicts with `--yara`      | -       |
| `--yara`    | YARA rule output; conflicts with `--json`  | -       |
| `--help`    | Show help                                  | -       |
| `--version` | Show version                               | -       |

### Filtering

| Option            | Description                                                        | Default |
| ----------------- | ------------------------------------------------------------------ | ------- |
| `--min-len N`     | Minimum string length (must be >= 1)                               | 4       |
| `--top N`         | Limit to top N strings by score (applied after all filters)        | -       |
| `--enc ENCODING`  | Filter by encoding: `ascii`, `utf8`, `utf16`, `utf16le`, `utf16be` | all     |
| `--only-tags TAG` | Include strings with any of these tags (OR); repeatable            | all     |
| `--no-tags TAG`   | Exclude strings with any of these tags; repeatable                 | none    |

### Mode Flags

| Option      | Description                                                                                                                     |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `--raw`     | Extraction-only mode (no tagging, ranking, or scoring); conflicts with `--only-tags`, `--no-tags`, `--top`, `--debug`, `--yara` |
| `--summary` | Append summary block (TTY table mode only); conflicts with `--json`, `--yara`                                                   |
| `--debug`   | Include score-breakdown fields (`section_weight`, `semantic_boost`, `noise_penalty`) in JSON output; conflicts with `--raw`     |

## Encoding Options

The `--enc` flag accepts exactly one encoding value per invocation:

| Value     | Description                          |
| --------- | ------------------------------------ |
| `ascii`   | 7-bit ASCII only                     |
| `utf8`    | UTF-8 (includes ASCII)               |
| `utf16`   | UTF-16 (both little- and big-endian) |
| `utf16le` | UTF-16 Little Endian only            |
| `utf16be` | UTF-16 Big Endian only               |

### Examples

```bash
# ASCII only
stringy --enc ascii binary

# UTF-16 only (common for Windows)
stringy --enc utf16 app.exe

# UTF-8 only
stringy --enc utf8 binary
```

## Tag Filtering

Tags are specified with the repeatable `--only-tags` and `--no-tags` flags. Repeat the flag for each tag value:

```bash
# Network indicators only
stringy --only-tags url --only-tags domain --only-tags ipv4 --only-tags ipv6 malware.exe

# Exclude noisy Base64
stringy --no-tags b64 binary

# File system related
stringy --only-tags filepath --only-tags regpath app.exe
```

### Available Tags

| Tag              | Description             | Example                          |
| ---------------- | ----------------------- | -------------------------------- |
| `url`            | HTTP/HTTPS URLs         | `https://api.example.com`        |
| `domain`         | Domain names            | `example.com`                    |
| `ipv4`           | IPv4 addresses          | `192.168.1.1`                    |
| `ipv6`           | IPv6 addresses          | `2001:db8::1`                    |
| `filepath`       | File paths              | `/usr/bin/app`                   |
| `regpath`        | Registry paths          | `HKEY_LOCAL_MACHINE\...`         |
| `guid`           | GUIDs/UUIDs             | `{12345678-1234-...}`            |
| `email`          | Email addresses         | `user@example.com`               |
| `b64`            | Base64 data             | `SGVsbG8=`                       |
| `fmt`            | Format strings          | `Error: %s`                      |
| `user-agent-ish` | User-agent-like strings | `Mozilla/5.0 ...`                |
| `demangled`      | Demangled symbols       | `std::io::Read::read`            |
| `import`         | Import names            | `CreateFileW`                    |
| `export`         | Export names            | `main`                           |
| `version`        | Version strings         | `v1.2.3`                         |
| `manifest`       | Manifest data           | XML/JSON config                  |
| `resource`       | Resource strings        | UI text                          |
| `dylib-path`     | Dynamic library paths   | `/usr/lib/libfoo.dylib`          |
| `rpath`          | Runtime search paths    | `/usr/local/lib`                 |
| `rpath-var`      | Rpath variables         | `@loader_path/../lib`            |
| `framework-path` | Framework paths (macOS) | `/System/Library/Frameworks/...` |

## Output Formats

### Table (Default, TTY)

When stdout is a TTY, results are shown as a table with columns:

```
String | Tags | Score | Section
```

When piped (non-TTY), output is plain text with one string per line and no headers.

### JSON Lines (`--json`)

Each line is a JSON object with full metadata. See [Output Formats](./output-formats.md) for the schema.

### YARA (`--yara`)

Generates a YARA rule template. See [Output Formats](./output-formats.md) for details.

## Exit Codes

| Code | Meaning                                                                    |
| ---- | -------------------------------------------------------------------------- |
| 0    | Success (including unknown binary format, empty binary, no filter matches) |
| 1    | Runtime error (file not found, tag overlap, `--summary` in non-TTY)        |
| 2    | Argument parsing error (invalid flag, flag conflict, invalid tag name)     |

## Advanced Usage

### Pipeline Integration

```bash
# Extract URLs and check them
stringy --only-tags url --json binary | jq -r '.text' | xargs -I {} curl -I {}

# Find high-score strings
stringy --json binary | jq 'select(.score > 80)'

# Count strings by tag
stringy --json binary | jq -r '.tags[]' | sort | uniq -c
```

### Batch Processing

```bash
# Process multiple files
find /path/to/binaries -type f -exec stringy --json {} \; > all_strings.jsonl

# Compare two versions
stringy --json old_binary > old.jsonl
stringy --json new_binary > new.jsonl
diff <(jq -r '.text' old.jsonl | sort) <(jq -r '.text' new.jsonl | sort)
```

### Focused Analysis

```bash
# Fast scan for high-value strings only
stringy --top 20 --min-len 8 --only-tags url --only-tags guid --only-tags filepath large_binary

# Extraction-only mode (no classification overhead)
stringy --raw binary
```
