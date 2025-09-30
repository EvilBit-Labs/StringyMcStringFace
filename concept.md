# Stringy - A Smarter Strings Tool

A smarter alternative to the standard `strings` command that uses binary analysis to extract meaningful strings from executables, focusing on data structures rather than arbitrary byte runs.

## Core Principles

Stringy focuses on extracting meaningful strings by being:

- **Data-structure aware**: Only strings that are part of the binary's actual data structures, not arbitrary byte runs
- **Section-aware**: Prioritizes `.rodata`/`.rdata`/`__cstring`, resources, and version info; de-emphasizes writable `.data`; avoids `.bss`
- **Encoding-aware**: Supports ASCII/UTF-8, UTF-16LE (PE), and UTF-16BE; detects null-interleaved text
- **Semantically tagged**: Identifies URLs, domains, IPs, file paths, registry keys, GUIDs, user agents, format strings, Base64 runs, crypto constants, and cloud metadata
- **Runtime-specific**: Handles import/export names, demangled Rust symbols, section names, Go build info, .NET metadata, and PE resources
- **Ranked**: Presents the most relevant strings first

## Architecture

### 1. Container Detection & Parsing

- Use `goblin` to detect ELF/PE/Mach-O formats
- Collect sections/segments, imports/exports, resources (PE), load commands (Mach-O)

### 2. Targeted String Extraction

- **ELF**: `.rodata`, `.data.rel.ro`, `.comment` (light), `.gnu.version_r` (careful), DWARF (optional)
- **PE**: `.rdata`, `.data` (lower weight), VERSIONINFO, STRINGTABLE, manifest, imports, exports
- **Mach-O**: `__TEXT,__cstring`, `__TEXT,__const`, `__DATA_CONST`, load command strings
- Extract ASCII/UTF-8, then UTF-16LE (even-length, low byte mostly printable)
- Configurable minimum length (default 4 ASCII / 3 wide)
- De-duplicate and canonicalize, keeping offset + section + size

### 3. Classification

- Regex/automata buckets: `url`, `domain`, `ipv4/6`, `filepath` (POSIX/Win), `regpath`, `guid`, `email`, `jwt-ish`, `b64`, `fmt` (printf-style), `user-agent-ish`
- Demangle Rust symbols with `rustc-demangle`
- Optional: detect Go build info & key strings (build paths)

### 4. Ranking Algorithm

```text
Score = SectionWeight + EncodingConfidence + SemanticBoost – NoisePenalty
```

- **SectionWeight**: `__cstring/.rdata/.rodata` > resources > `.data` >> everything else
- **SemanticBoost**: URL/GUID/registry/path/format string +2..+5
- **NoisePenalty**: high entropy, giant length, repeated pad bytes, obvious table data
- Import/export names get a boost

### 5. Output Formats

- **JSONL**: One record per string with `{text, offset, rva, section, encoding, tags[], score}`
- **Human view**: Sorted table with `--only urls,paths,fmt`
- **YARA-friendly**: `--yara candidates.txt` (escapes, truncation rules)

### 6. CLI Interface

```bash
smartstrings foo.bin --min-len 4 --enc ascii,utf16 --only rodata,resources --top 200 --json
```

- Filters: `--only-tags url,domain,guid,fmt`, `--notags b64`
- **PE features**: `--pe-version`, `--pe-manifest`, `--utf16-only`
- **Mach-O**: `--lc-strings` (collect load command strings)

## Future Enhancements (v2+)

- **Light XREF hinting**: For ELF, check relocations targeting `.rodata` addresses; strings with inbound relocs rank higher
- **Capstone-lite pass**: Scan for immediates in `.text` that point into string pools; mark as "referenced"
- **Resource deep dive (PE)**: Icons, dialogs, stringtables with language IDs
- **UPX detection**: Detect packers; offer `--expect-upx` mode to reduce false negatives (no unpacking by default)
- **DWARF skim**: Function/file names (with `gimli`) to augment context
- **PDB integration**: Use `pdb` crate to enrich imports/func names (no symbol server fetch)

## Dependencies

All recommended crates are safe or use encapsulated unsafe:

- **Container parsing**: `goblin`
- **Demangling (Rust)**: `rustc-demangle`
- **PE resources**: `pelite` (great for VERSIONINFO/STRINGTABLE)
- **DWARF**: `gimli` (optional)
- **Mach-O details**: `object` (pairs well with goblin for some formats)
- **Disasm (optional)**: `capstone` via `capstone-rs`
- **Mmap**: `memmap2` (fast, read-only)
- **Regex**: `regex` / `aho-corasick` for fast tagging
- **CLI/serde**: `clap`, `serde`, `serde_json`

## Data Model

```rust
#[derive(Serialize)]
struct FoundString {
    text: String,
    encoding: Encoding,      // Ascii, Utf8, Utf16Le, Utf16Be
    offset: u64,             // file offset
    rva: Option<u64>,        // image RVA if available
    section: Option<String>, // ".rdata" / "__cstring" / ...
    length: u32,
    tags: Vec<Tag>, // Url, Path, Domain, Reg, Guid, Fmt, B64, Import, Export, Version, Manifest, Resource
    score: i32,
    source: Source, // Literal, ImportName, ExportName, Resource, Debug, LoadCmd
}
```

## Advantages Over Standard `strings`

- **Eliminates noise**: Stops dumping padding, tables, and interleaved garbage
- **UTF-16 support**: Surfaces UTF-16 (crucial for PE) cleanly
- **Actionable buckets**: Provides categorized results (URLs, keys, UAs, registry paths) first
- **Provenance tracking**: Keeps offset/section info for pivoting to other tools
- **YARA integration**: Feeds only high-signal candidates

## Limitations

- **No reachability proof**: Without real xrefs, the "referenced" flag remains opportunistic
- **Packed binaries**: VM-protected binaries will still be thin until unpacked
- **Scope management**: Go/.NET have richer metadata—support is doable, but avoid scope creep turning this into "Ghidra with jokes"

## Development Roadmap

- **MVP (weekend)**: goblin + section list → ASCII/UTF-16 extract → tag+rank → JSONL + TTY view
- **v0.2**: PE resources + Rust demangle + import/export names
- **v0.3**: Reloc-hinted "referenced" + simple Capstone pass (flag only, no CFG)
- **v0.4**: DWARF skim + Mach-O load-command strings + Go build info detection

## Red Team Features

- `--diff old.bin new.bin` to highlight string deltas (operators love this)
- `--mask common` to drop common libc/CRT strings
- `--emit ndjson` to integrate into pipelines; schema stable for jq/jq-like tools
- `--profile malware` to enhance tags (suspicious keywords, cloud endpoints, telemetry beacons)
