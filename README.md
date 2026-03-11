![Stupid Sentient Yarn Ball Logo](docs/src/images/logo-320.png)

# Stringy

A smarter alternative to the standard `strings` command that uses binary analysis to extract meaningful strings from executables, focusing on data structures rather than arbitrary byte runs.

---

## The Problem with `strings`

The standard `strings` command dumps every printable byte sequence it finds, which means you get:

- Padding bytes and table data
- Interleaved garbage in UTF-16 strings
- No context about where strings come from
- No prioritization of what's actually useful

**Stringy** solves this by being data-structure aware, section-aware, and semantically intelligent.

---

## What Makes Stringy Different

### **Data-Structure Aware**

Only extracts strings that are part of the binary's actual data structures, not arbitrary byte runs.

### **Section-Aware**

Prioritizes `.rodata`/`.rdata`/`__cstring`, resources, and version info; de-emphasizes writable `.data`; avoids `.bss`.

### **Encoding-Aware**

Supports ASCII/UTF-8, UTF-16LE (PE), and UTF-16BE; detects null-interleaved text.

### **Semantically Tagged**

Identifies URLs, domains, IPs, file paths, registry keys, GUIDs, user agents, format strings, Base64 runs, crypto constants, and cloud metadata.

### **Runtime-Specific**

Handles import/export names, demangled Rust symbols, section names, Go build info, .NET metadata, and PE resources.

### **Ranked**

Presents the most relevant strings first using a scoring algorithm.

---

## Features

- **Format-aware parsing** via [`goblin`](https://docs.rs/goblin): ELF, PE, Mach-O
- **Section targeting**: `.rodata`, `.rdata`, `__cstring`, resources, manifests
- **Encoding support**: ASCII, UTF-8, UTF-16LE/BE with confidence scoring
- **Smart classification**:
  - URLs, domains, IPv4/IPv6 addresses (implemented)
  - Filepaths & registry keys
  - GUIDs & user agents
  - Format strings (`%s`, `%d`, etc.)
  - Base64 & crypto constants
- **Rust symbol demangling** (`rustc-demangle`)
- **JSON output** for pipelines
- **YARA-friendly output** for rule generation
- **Ranking & scoring**: high-signal strings first

---

## Installation

**Note**: Stringy is currently in development and not yet published to crates.io.

### From Source

```bash
git clone https://github.com/EvilBit-Labs/Stringy
cd Stringy
cargo build --release
./target/release/stringy --help
```

### Development Build

```bash
cargo run -- --help
```

---

## Usage

```bash
# Basic analysis with ranked output
stringy target_binary

# Filter by semantic tags
stringy --only-tags url target_binary
stringy --only-tags url --only-tags filepath target_binary

# Exclude noisy tags
stringy --notags format_string target_binary

# Control extraction
stringy --min-len 8 target_binary
stringy --enc ascii target_binary
stringy --top 50 target_binary

# Output formats
stringy --json target_binary
stringy --yara target_binary
stringy --json target_binary | jq '.[] | select(.tags[] | contains("Url"))'

# Raw extraction (no classification/ranking)
stringy --raw target_binary

# Debug and summary modes
stringy --debug target_binary
stringy --summary target_binary
```

---

## Example Output

**Human-readable mode (TTY):**

```
String                                   | Tags       | Score | Section
-----------------------------------------|------------|-------|--------
https://api.example.com/v1/              | url        |    95 | .rdata
{12345678-1234-1234-1234-123456789abc}   | guid       |    87 | .rdata
/usr/local/bin/stringy                   | filepath   |    82 | __cstring
Error: %s at line %d                     | fmt        |    78 | .rdata
```

**JSON mode (JSONL):**

```json
{
  "text": "https://api.example.com/v1/",
  "offset": 4096,
  "rva": 4096,
  "section": ".rdata",
  "encoding": "utf-8",
  "length": 28,
  "tags": [
    "Url"
  ],
  "score": 95,
  "display_score": 95,
  "source": "SectionData",
  "confidence": 0.98
}
```

---

## Advantages Over Standard `strings`

- **Eliminates noise**: Stops dumping padding, tables, and interleaved garbage
- **UTF-16 support**: Surfaces UTF-16 (crucial for PE) cleanly
- **Actionable buckets**: Provides categorized results (URLs, keys, UAs, registry paths) first
- **Provenance tracking**: Keeps offset/section info for pivoting to other tools
- **YARA integration**: Feeds only high-signal candidates

---

## Features

- **Format Detection**: ELF, PE, and Mach-O via `goblin` with single-parse optimization
- **Container Parsing**: Section classification with weight-based prioritization (1.0-10.0 scale)
- **String Extraction**: ASCII, UTF-8, and UTF-16 (LE/BE/Auto) with noise filtering
- **Semantic Classification**: URLs, IPs, domains, file paths, GUIDs, format strings, registry keys, and more
- **Symbol Demangling**: C++, Rust, and other mangled symbol name recovery
- **Ranking**: Section-aware scoring with band-mapped 0-100 normalization
- **Deduplication**: Canonical string grouping with configurable similarity threshold
- **Output Formats**: TTY table, plain text, JSONL, YARA rules
- **PE Resources**: VERSIONINFO, STRINGTABLE, and MANIFEST extraction
- **Import/Export Analysis**: Symbol extraction from all supported binary formats
- **Pipeline Architecture**: Configurable orchestrator with filtering, encoding selection, and top-N support

---

## License

Licensed under Apache 2.0.

---

## Acknowledgements

- Inspired by `strings(1)` and the need for better binary analysis tools
- Built with Rust ecosystem crates: `goblin`, `bstr`, `regex`, `rustc-demangle`
- My coworkers, for their excellent input on the original name selection
