# String Extraction

Stringy's string extraction engine is designed to find meaningful strings while avoiding noise and false positives. The extraction process is encoding-aware, section-aware, and configurable.

## Extraction Pipeline

```text
Binary Data → Section Analysis → Encoding Detection → String Scanning → Deduplication → Classification
```

## Encoding Support

### ASCII/UTF-8 Extraction

The most common encoding in most binaries.

#### Algorithm

1. **Scan for printable sequences**: Characters in range 0x20-0x7E plus common whitespace
2. **Length filtering**: Configurable minimum length (default: 4 characters)
3. **Null termination**: Respect null terminators but don't require them
4. **Context awareness**: Consider section type for validation

#### Implementation Details

```rust
fn extract_ascii_strings(data: &[u8], min_len: usize) -> Vec<RawString> {
    let mut strings = Vec::new();
    let mut current_string = Vec::new();
    let mut start_offset = 0;

    for (i, &byte) in data.iter().enumerate() {
        if is_printable_ascii(byte) {
            if current_string.is_empty() {
                start_offset = i;
            }
            current_string.push(byte);
        } else {
            if current_string.len() >= min_len {
                strings.push(RawString {
                    data: current_string.clone(),
                    offset: start_offset,
                    encoding: Encoding::Ascii,
                });
            }
            current_string.clear();
        }
    }

    strings
}
```

#### Noise Filtering

- **Padding detection**: Skip sequences of repeated characters
- **Table data**: Avoid extracting from obvious data tables
- **Binary interleaving**: Skip strings with excessive binary data

### UTF-16 Extraction

Critical for Windows binaries and some resources.

#### UTF-16LE (Little Endian)

Most common on Windows platforms.

**Detection heuristics**:

- Even-length sequences
- Low byte printable, high byte mostly zero
- Null termination patterns (0x00 0x00)

#### UTF-16BE (Big Endian)

Less common but found in some formats.

**Detection heuristics**:

- Even-length sequences
- High byte printable, low byte mostly zero
- Reverse byte order from UTF-16LE

#### Implementation Strategy

```rust
fn extract_utf16_strings(data: &[u8], endian: Endianness, min_len: usize) -> Vec<RawString> {
    let mut strings = Vec::new();
    let mut i = 0;

    while i + 1 < data.len() {
        let mut char_count = 0;
        let start = i;

        // Scan for UTF-16 sequence
        while i + 1 < data.len() {
            let (low, high) = match endian {
                Endianness::Little => (data[i], data[i + 1]),
                Endianness::Big => (data[i + 1], data[i]),
            };

            if is_printable_utf16_char(low, high) {
                char_count += 1;
                i += 2;
            } else if low == 0 && high == 0 && char_count >= min_len {
                // Null terminator found
                break;
            } else {
                break;
            }
        }

        if char_count >= min_len {
            strings.push(extract_utf16_string(&data[start..i], endian));
        }

        i += 2;
    }

    strings
}
```

#### Confidence Scoring

UTF-16 detection uses confidence scoring to avoid false positives:

- **High confidence**: >90% printable characters, proper null termination
- **Medium confidence**: >70% printable, reasonable length
- **Low confidence**: >50% printable, may be coincidental

## Section-Aware Extraction

Different sections have different string extraction strategies.

### High-Priority Sections

#### ELF: `.rodata` and variants

- **Strategy**: Aggressive extraction, low noise filtering
- **Encodings**: ASCII/UTF-8 primary, UTF-16 secondary
- **Minimum length**: 3 characters

#### PE: `.rdata`

- **Strategy**: Balanced extraction
- **Encodings**: ASCII and UTF-16LE equally
- **Minimum length**: 4 characters

#### Mach-O: `__TEXT,__cstring`

- **Strategy**: High confidence, null-terminated focus
- **Encodings**: UTF-8 primary
- **Minimum length**: 3 characters

### Medium-Priority Sections

#### ELF: `.data.rel.ro`

- **Strategy**: Conservative extraction
- **Noise filtering**: Enhanced
- **Minimum length**: 5 characters

#### PE: `.data` (read-only)

- **Strategy**: Moderate extraction
- **Context checking**: Enhanced validation

### Low-Priority Sections

#### Writable data sections

- **Strategy**: Very conservative
- **High noise filtering**: Skip obvious runtime data
- **Minimum length**: 6+ characters

### Resource Sections

#### PE Resources (`.rsrc`)

- **VERSIONINFO**: Extract version strings, product names
- **STRINGTABLE**: Localized UI strings
- **RT_MANIFEST**: XML manifest data

```rust
fn extract_pe_resources(pe: &PE, data: &[u8]) -> Vec<RawString> {
    let mut strings = Vec::new();

    // Extract version info
    if let Some(version_info) = extract_version_info(pe, data) {
        strings.extend(version_info);
    }

    // Extract string tables
    if let Some(string_tables) = extract_string_tables(pe, data) {
        strings.extend(string_tables);
    }

    strings
}
```

## Deduplication Strategy

### Canonicalization

Strings are canonicalized while preserving important metadata:

1. **Normalize whitespace**: Convert tabs/newlines to spaces
2. **Trim boundaries**: Remove leading/trailing whitespace
3. **Case preservation**: Maintain original case for analysis
4. **Encoding normalization**: Convert to UTF-8 for comparison

### Metadata Preservation

When duplicates are found:

```rust
struct DeduplicatedString {
    canonical_text: String,
    occurrences: Vec<StringOccurrence>,
    primary_encoding: Encoding,
    best_section: Option<String>,
}

struct StringOccurrence {
    offset: u64,
    section: Option<String>,
    encoding: Encoding,
    length: u32,
}
```

### Deduplication Algorithm

```rust
fn deduplicate_strings(strings: Vec<RawString>) -> Vec<DeduplicatedString> {
    let mut map: HashMap<String, DeduplicatedString> = HashMap::new();

    for string in strings {
        let canonical = canonicalize(&string.text);

        map.entry(canonical.clone())
            .or_insert_with(|| DeduplicatedString::new(canonical))
            .add_occurrence(string);
    }

    map.into_values().collect()
}
```

## Configuration Options

### Length Filtering

```rust
pub struct ExtractionConfig {
    pub min_ascii_len: usize,  // Default: 4
    pub min_utf16_len: usize,  // Default: 3
    pub max_string_len: usize, // Default: 1024
}
```

### Encoding Selection

```rust
pub enum EncodingFilter {
    All,
    Specific(Vec<Encoding>),
    AsciiOnly,
    Utf16Only,
}
```

### Section Filtering

```rust
pub struct SectionFilter {
    pub include_sections: Option<Vec<String>>,
    pub exclude_sections: Option<Vec<String>>,
    pub include_debug: bool,
    pub include_resources: bool,
}
```

## Performance Optimizations

### Memory Mapping

Large files use memory mapping for efficient access:

```rust
use memmap2::Mmap;

fn extract_from_large_file(path: &Path) -> Result<Vec<RawString>> {
    let file = File::open(path)?;
    let mmap = unsafe { Mmap::map(&file)? };

    extract_strings(&mmap[..])
}
```

### Parallel Processing

Section extraction can be parallelized:

```rust
use rayon::prelude::*;

fn extract_parallel(sections: &[SectionInfo], data: &[u8]) -> Vec<RawString> {
    sections
        .par_iter()
        .flat_map(|section| extract_from_section(section, data))
        .collect()
}
```

### Regex Caching

Pattern matching uses cached regex compilation:

```rust
lazy_static! {
    static ref URL_REGEX: Regex = Regex::new(r"https?://[^\s]+").unwrap();
    static ref GUID_REGEX: Regex = Regex::new(r"\{[0-9a-fA-F-]{36}\}").unwrap();
}
```

## Quality Assurance

### Validation Heuristics

- **Entropy checking**: Skip high-entropy strings likely to be binary data
- **Language detection**: Prefer strings with common English patterns
- **Context validation**: Consider surrounding bytes for legitimacy

### False Positive Reduction

- **Padding detection**: Skip repeated character sequences
- **Table data**: Avoid structured binary data
- **Alignment checking**: Consider memory alignment patterns

This comprehensive extraction system ensures high-quality string extraction while maintaining performance and minimizing false positives.
