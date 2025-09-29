![Stupid Sentient Yarn Ball Logo](docs/logo.png)

# StringyMcStringFace

Because Strings Weren’t Dumb Enough Already

---

## Overview

**StringyMcStringFace** (command: `stringy`) is a smarter alternative to the classic `strings` tool. It extracts meaningful strings from binaries using format-aware parsing, section awareness, and encoding detection to surface the strings analysts actually care about.

Instead of dumping every printable byte run, `stringy` focuses on *signal over noise*, giving you clean results with context.

---

## Features

- **Format-aware parsing** via [`goblin`](https://docs.rs/goblin): ELF, PE, Mach-O
- **Section targeting**: `.rodata`, `.rdata`, `__cstring`, resources, manifests
- **Encoding support**: ASCII, UTF-8, UTF-16LE/BE
- **Smart tagging**:
  - URLs, domains, IPs
  - Filepaths & registry keys
  - GUIDs & user agents
  - Format strings (`%s`, `%d`, etc.)
- **Rust symbol demangling** (`rustc-demangle`)
- **JSON output** for pipelines
- **Ranking & scoring**: high-signal strings first

---

## Installation

```bash
cargo install stringy
```

---

## Usage

### Basic

```bash
stringy target_binary
```

### JSON Output

```bash
stringy --json target_binary > results.json
```

### Filtering

```bash
stringy --only url,guid,filepath target_binary
```

### Example Output

**Text mode:**

```hexdump
[0x0000] PK..   → Zip archive header
[0x0020] META-INF/   → Java JAR marker
[0x1000] https://api.example.com/v1/
[0x2000] %s %d %x → Format string
```

**JSON mode:**

```json
{
  "matches": [
    {
      "text": "https://api.example.com/v1/",
      "offset": 4096,
      "encoding": "utf-8",
      "tags": ["url"],
      "score": 95
    }
  ]
}
```

---

## Roadmap

-

---

## License

Apache 2.0

---

## Acknowledgements

- Inspired by `strings(1)` and `libmagic`
- Built with Rust ecosystem crates: `goblin`, `bstr`, `regex`, `rustc-demangle`
- My coworkers, for selecting the name and abusing my willingness to trust democracy and their maturity

---

*Remember: it’s **`StringyMcStringFace`** on GitHub, but just **`stringy`** on your command line.*
