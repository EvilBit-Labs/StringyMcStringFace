![Stupid Sentient Yarn Ball Logo](docs/logo.png)

# StringyMcStringFace

A smarter alternative to the standard `strings` command that uses binary analysis to extract meaningful strings from executables, focusing on data structures rather than arbitrary byte runs.

> **Why the stupid name?** My coworkers held a democratic vote and chose "StringyMcStringFace" over my more dignified suggestions. I trusted their maturity. This was a mistake. The command is still just `stringy` though.

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
  - URLs, domains, IPs
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
git clone https://github.com/EvilBit-Labs/string_mcstringface
cd string_mcstringface
cargo build --release
./target/release/stringy --help
```

### Development Build

```bash
cargo run -- --help
```

---

## Usage

**Current Status**: The CLI interface is under development. Currently available:

```bash
stringy target_binary
```

### Planned CLI Interface

The following features are being implemented:

```bash
# Basic analysis (coming soon)
stringy target_binary

# Focused extraction (planned)
stringy --only url,filepath target_binary
stringy --min-len 8 --enc ascii,utf16 target_binary
stringy --top 50 --json target_binary

# PE-specific features (planned)
stringy --pe-version --pe-manifest target.exe
stringy --utf16-only target.exe

# Pipeline integration (planned)
stringy --json target_binary | jq '.[] | select(.tags[] | contains("url"))'
stringy --yara candidates.txt target_binary
```

---

## Example Output

**Human-readable mode:**

```
Score  Offset    Section    Tags           String
-----  ------    -------    ----           ------
  95   0x1000    .rdata     url,https      https://api.example.com/v1/
  87   0x2000    .rdata     guid           {12345678-1234-1234-1234-123456789abc}
  82   0x3000    __cstring  filepath       /usr/local/bin/stringy
  78   0x4000    .rdata     fmt            Error: %s at line %d
```

**JSON mode:**

```json
{
  "text": "https://api.example.com/v1/",
  "offset": 4096,
  "rva": 4096,
  "section": ".rdata",
  "encoding": "utf-8",
  "length": 28,
  "tags": [
    "url"
  ],
  "score": 95,
  "source": "SectionData"
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

## Development Status

This project is in active development. Current implementation status:

- ✅ **Core Infrastructure**: Project structure, data types, error handling
- ✅ **Format Detection**: ELF, PE, Mach-O binary format detection via `goblin`
- ✅ **Container Parsers**: Section classification, import/export extraction
- 🚧 **String Extraction**: ASCII/UTF-8 and UTF-16 extraction engines
- 🚧 **Semantic Classification**: URL, domain, path, GUID pattern matching
- 🚧 **Ranking System**: Section-aware scoring and relevance calculation
- 🚧 **Output Formats**: JSONL, human-readable, and YARA-friendly output
- 🚧 **CLI Interface**: Command-line argument parsing and main pipeline

### Current Capabilities

The foundation is solid with working binary format parsers that can:

- Detect ELF, PE, and Mach-O formats
- Classify sections by string likelihood (`.rodata`, `.rdata`, `__cstring`, etc.)
- Extract import/export symbol names
- Handle cross-platform section characteristics

See the [implementation plan](.kiro/specs/stringy-binary-analyzer/tasks.md) for detailed progress tracking.

---

## License

Licensed under Apache 2.0.

---

## Acknowledgements

- Inspired by `strings(1)` and the need for better binary analysis tools
- Built with Rust ecosystem crates: `goblin`, `bstr`, `regex`, `rustc-demangle`
- My coworkers, for selecting the name and abusing my willingness to trust democracy and their maturity

---

*Remember: it's **`StringyMcStringFace`** on GitHub, but just **`stringy`** on your command line.*
