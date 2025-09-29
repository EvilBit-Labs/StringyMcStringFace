# Product Overview

Stringy is a smarter alternative to the standard `strings` command that uses binary analysis to extract meaningful strings from executables. Unlike traditional string extraction tools, Stringy focuses on data structures rather than arbitrary byte runs.

## Key Features

- **Data-structure aware**: Extracts strings from actual binary data structures
- **Section-aware**: Prioritizes meaningful sections like `.rodata`, `.rdata`, `__cstring`
- **Multi-encoding support**: ASCII/UTF-8, UTF-16LE (PE), UTF-16BE
- **Semantic tagging**: Identifies URLs, domains, IPs, file paths, registry keys, GUIDs, format strings, Base64, crypto constants
- **Runtime-specific**: Handles imports/exports, Rust symbols, .NET metadata, PE resources
- **Ranked output**: Presents most relevant strings first

## Target Use Cases

- Binary analysis and reverse engineering
- Malware analysis and security research
- YARA rule development
- Red team operations with diff capabilities
- General executable inspection

## Output Formats

- JSONL for programmatic use
- Human-readable sorted tables
- YARA-friendly format for rule creation
