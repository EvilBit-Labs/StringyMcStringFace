# Introduction

Stringy is a smarter alternative to the standard `strings` command that uses binary analysis to extract meaningful strings from executables. Unlike traditional string extraction tools, Stringy focuses on data structures rather than arbitrary byte runs.

## Why Stringy?

The standard `strings` command has several limitations:

- **Noise**: Dumps every printable byte sequence, including padding and table data
- **UTF-16 Issues**: Produces interleaved garbage when scanning UTF-16 strings
- **No Context**: Provides no information about where strings come from
- **No Prioritization**: Treats all strings equally, regardless of relevance

Stringy addresses these issues by being:

- **Data-structure aware**: Only extracts strings from actual binary data structures
- **Section-aware**: Prioritizes meaningful sections like `.rodata`, `.rdata`, `__cstring`
- **Encoding-aware**: Properly handles ASCII/UTF-8, UTF-16LE, and UTF-16BE
- **Semantically intelligent**: Identifies and tags URLs, domains, file paths, GUIDs, etc.
- **Ranked**: Presents the most relevant strings first

## Key Features

### Multi-Format Support

- **ELF** (Linux executables and libraries)
- **PE** (Windows executables and DLLs)
- **Mach-O** (macOS executables and frameworks)

### Smart String Extraction

- Section-aware extraction prioritizing string-rich sections
- Multi-encoding support (ASCII, UTF-8, UTF-16LE/BE)
- Deduplication with metadata preservation
- Configurable minimum length filtering

### Semantic Classification

- **Network**: URLs, domains, IP addresses
- **Filesystem**: File paths, registry keys
- **Identifiers**: GUIDs, email addresses, user agents
- **Code**: Format strings, Base64 data
- **Symbols**: Import/export names, demangled symbols

### Multiple Output Formats

- **Human-readable**: Sorted tables for interactive analysis
- **JSONL**: Machine-readable format for automation
- **YARA-friendly**: Optimized for security rule creation

## Use Cases

### Binary Analysis & Reverse Engineering

Extract meaningful strings to understand program functionality, identify libraries, and discover embedded resources.

### Malware Analysis

Quickly identify network indicators, file paths, registry keys, and other artifacts of interest in suspicious binaries.

### YARA Rule Development

Generate high-confidence string candidates for creating detection rules, with automatic escaping and formatting.

### Security Research

Analyze binaries for hardcoded credentials, API endpoints, configuration data, and other security-relevant strings.

## Project Status

Stringy is in active development with a solid foundation already in place. The core infrastructure is complete and robust:

**✅ Implemented:**

- Complete binary format detection (ELF, PE, Mach-O)
- Comprehensive section classification with intelligent weighting
- Import/export symbol extraction from all formats
- Type-safe error handling and data structures
- Extensible architecture with trait-based parsers

**🚧 In Progress:**

- String extraction engines (ASCII/UTF-8, UTF-16)
- Semantic classification system (URLs, paths, GUIDs, etc.)
- Ranking and scoring algorithms
- Output formatters (JSON, human-readable, YARA)
- Full CLI interface implementation

The foundation provides reliable binary analysis capabilities that can already identify and classify sections by their likelihood of containing meaningful strings, extract symbol information, and handle cross-platform binary formats.

See the [Architecture Overview](./architecture.md) for technical details and the [Contributing](./contributing.md) guide to get involved.
