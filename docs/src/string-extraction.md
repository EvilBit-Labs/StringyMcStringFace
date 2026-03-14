# String Extraction

Stringy's string extraction engine is designed to find meaningful strings while avoiding noise and false positives. The extraction process is encoding-aware, section-aware, and configurable.

## Extraction Pipeline

```text
Binary Data → Section Analysis → Encoding Detection → String Scanning → Deduplication → Classification
```

## Encoding Support

### ASCII Extraction

The most common encoding in most binaries. ASCII extraction provides foundational string extraction with configurable minimum length thresholds.

### UTF-16LE Extraction

UTF-16LE extraction is now implemented and available for Windows PE binary string extraction. It provides UTF-16LE string extraction with confidence scoring and noise filtering integration.

#### Algorithm

1. **Scan for printable sequences**: Characters in range 0x20-0x7E (strict printable ASCII)
2. **Length filtering**: Configurable minimum length (default: 4 characters)
3. **Null termination**: Respect null terminators but don't require them
4. **Section awareness**: Integrate with section metadata for context-aware filtering

#### Basic Extraction

```text
use stringy::extraction::{extract_ascii_strings, AsciiExtractionConfig};

let data = b"Hello\0World\0Test123";
let config = AsciiExtractionConfig::default();
let strings = extract_ascii_strings(data, &config);

for string in strings {
    println!("Found: {} at offset {}", string.text, string.offset);
}
```

#### Configuration

```text
use stringy::extraction::AsciiExtractionConfig;

// Default configuration (min_length: 4, no max_length)
let config = AsciiExtractionConfig::default();

// Custom minimum length
let config = AsciiExtractionConfig::new(8);

// Custom minimum and maximum length
let mut config = AsciiExtractionConfig::default();
config.max_length = Some(256);
```

### UTF-8 Extraction

UTF-8 extraction builds on ASCII extraction and handles multi-byte characters. See the main extraction module for UTF-8 support.

#### Implementation Details

```text
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

## Noise Filtering

Stringy implements a multi-layered heuristic filtering system to reduce false positives and identify noise in extracted strings. The filtering system uses a combination of entropy analysis, character distribution, linguistic patterns, length checks, repetition detection, and context-aware filtering.

### Filter Architecture

The noise filtering system consists of multiple independent filters that can be combined with configurable weights:

1. **Character Distribution Filter**: Detects abnormal character frequency distributions
2. **Entropy Filter**: Uses Shannon entropy to detect padding/repetition and random binary
3. **Linguistic Pattern Filter**: Analyzes vowel-to-consonant ratios and common bigrams
4. **Length Filter**: Penalizes excessively long strings and very short strings in low-weight sections
5. **Repetition Filter**: Detects repeated character patterns and repeated substrings
6. **Context-Aware Filter**: Boosts confidence for strings in high-weight sections

### Character Distribution Analysis

Detects strings with abnormal character distributions:

- **Excessive punctuation** (>80%): Low confidence (0.2)
- **Excessive repetition** (>90% same character): Very low confidence (0.1)
- **Excessive non-alphanumeric** (>70%): Low confidence (0.3)
- **Reasonable distribution**: High confidence (1.0)

### Entropy-Based Filtering

Uses Shannon entropy (bits per byte) to classify strings:

- **Very low entropy** (\<1.5 bits/byte): Likely padding or repetition (confidence: 0.1)
- **Very high entropy** (>7.5 bits/byte): Likely random binary (confidence: 0.2)
- **Optimal range** (3.5-6.0 bits/byte): High confidence (1.0)
- **Acceptable range** (2.0-7.0 bits/byte): Moderate confidence (0.4-0.7)

### Linguistic Pattern Detection

Analyzes text for word-like patterns:

- **Vowel-to-consonant ratio**: Reasonable range 0.2-0.8 for English
- **Common bigrams**: Detects common English patterns (th, he, in, er, an, re, on, at, en, nd)
- **Handles non-English**: Gracefully handles non-English strings without over-penalizing

### Length-Based Filtering

Applies penalties based on string length:

- **Excessively long** (>200 characters): Low confidence (0.3) - likely table data
- **Very short in low-weight sections** (\<4 chars, weight \<0.5): Moderate confidence (0.5)
- **Normal length** (4-100 characters): High confidence (1.0)

### Repetition Detection

Identifies repetitive patterns:

- **Repeated characters** (e.g., "AAAA", "0000"): Very low confidence (0.1)
- **Repeated substrings** (e.g., "abcabcabc"): Low confidence (0.2)
- **Normal strings**: High confidence (1.0)

### Context-Aware Filtering

Boosts or reduces confidence based on section context:

- **String data sections** (.rodata, .rdata, \_\_cstring): High confidence (0.9-1.0)
- **Read-only data sections**: High confidence (0.9)
- **Resource sections**: Maximum confidence (1.0) - known-good sources
- **Code sections**: Lower confidence (0.3-0.5)
- **Writable data sections**: Moderate confidence (0.6)

### Configuration

```text
use stringy::extraction::config::{NoiseFilterConfig, FilterWeights};

// Default configuration
let config = NoiseFilterConfig::default();

// Customize thresholds
let mut config = NoiseFilterConfig::default();
config.entropy_min = 2.0;
config.entropy_max = 7.0;
config.max_length = 150;

// Customize filter weights
config.filter_weights = FilterWeights {
    entropy_weight: 0.3,
    char_distribution_weight: 0.25,
    linguistic_weight: 0.2,
    length_weight: 0.15,
    repetition_weight: 0.05,
    context_weight: 0.05,
};
```

### Using Noise Filters

```text
use stringy::extraction::config::NoiseFilterConfig;
use stringy::extraction::filters::{CompositeNoiseFilter, FilterContext};
use stringy::types::SectionType;

let filter_config = NoiseFilterConfig::default();
let filter = CompositeNoiseFilter::new(&filter_config);
let context = FilterContext::default();

let confidence = filter.calculate_confidence("Hello, World!", &context);
if confidence >= 0.5 {
    // String passed filtering threshold
}
```

### Confidence Scoring

Each string is assigned a confidence score (0.0-1.0) indicating how likely it is to be legitimate:

- **1.0**: Maximum confidence (strings from known-good sources like imports, exports, resources)
- **0.7-0.9**: High confidence (likely legitimate strings)
- **0.5-0.7**: Moderate confidence (may need review)
- **0.0-0.5**: Low confidence (likely noise, filtered out by default)

The confidence score is separate from the `score` field used for final ranking. Confidence specifically represents the noise filtering assessment.

### Performance

Noise filtering is designed to add minimal overhead (\<10% per acceptance criteria). Individual filters are optimized for performance, and the composite filter allows enabling/disabling specific filters to balance accuracy and speed.

### UTF-16 Extraction

Critical for Windows binaries and some resources. Supports both UTF-16LE (Little-Endian) and UTF-16BE (Big-Endian) with automatic byte order detection.

#### UTF-16LE (Little-Endian)

Most common on Windows platforms. Default 3 character minimum.

**Detection heuristics**:

- Even-length sequences (2-byte alignment required)
- Low byte printable, high byte mostly zero
- Null termination patterns (0x00 0x00)
- Advanced confidence scoring with multiple heuristics

#### UTF-16BE (Big-Endian)

Found in Java .class files, network protocols, some cross-platform binaries.

**Detection heuristics**:

- Even-length sequences
- High byte printable, low byte mostly zero
- Reverse byte order from UTF-16LE
- Same advanced confidence scoring as UTF-16LE

#### Automatic Byte Order Detection

The `ByteOrder::Auto` mode automatically detects and extracts both UTF-16LE and UTF-16BE strings from the same data, avoiding duplicates and correctly identifying the encoding of each string.

#### Implementation

UTF-16 extraction is implemented in `src/extraction/utf16.rs` following the pattern established in the ASCII extractor. The implementation provides:

- `extract_utf16_strings()`: Main extraction function supporting both byte orders
- `extract_utf16le_strings()`: UTF-16LE-specific extraction (backward compatibility)
- `extract_from_section()`: Section-aware extraction with proper metadata population
- `Utf16ExtractionConfig`: Configuration for minimum/maximum character count, byte order selection, and confidence thresholds
- `ByteOrder` enum: Control which byte order(s) to scan (LE, BE, Auto)

**Usage Example**:

```text
use stringy::extraction::utf16::{extract_utf16_strings, Utf16ExtractionConfig, ByteOrder};

// Extract UTF-16LE strings from Windows PE binary
let config = Utf16ExtractionConfig {
    byte_order: ByteOrder::LE,
    min_length: 3,
    confidence_threshold: 0.6,
    ..Default::default()
};
let strings = extract_utf16_strings(data, &config);

// Extract both UTF-16LE and UTF-16BE with auto-detection
let config = Utf16ExtractionConfig {
    byte_order: ByteOrder::Auto,
    ..Default::default()
};
let strings = extract_utf16_strings(data, &config);
```

**Configuration**:

```text
use stringy::extraction::utf16::{Utf16ExtractionConfig, ByteOrder};

// Default configuration (min_length: 3, byte_order: Auto, confidence_threshold: 0.5)
let config = Utf16ExtractionConfig::default();

// Custom minimum character length
let config = Utf16ExtractionConfig::new(5);

// Custom configuration
let mut config = Utf16ExtractionConfig::default();
config.min_length = 3;
config.max_length = Some(256);
config.byte_order = ByteOrder::LE;
config.confidence_threshold = 0.6;
```

#### UTF-16-Specific Confidence Scoring

UTF-16 extraction uses advanced confidence scoring to detect false positives from null-interleaved binary data. The confidence score combines multiple heuristics:

1. **Valid Unicode range check**: Validates code points are in valid Unicode ranges (U+0020-U+D7FF, U+E000-U+FFFD, U+10000-U+10FFFF), penalizes private use areas and invalid surrogates

2. **Printable character ratio**: Calculates ratio of printable characters including common Unicode ranges

3. **ASCII ratio**: Boosts confidence for ASCII-heavy strings (>50% characters in ASCII printable range)

4. **Null pattern detection**: Flags suspicious patterns like:

   - Excessive nulls (>30% of characters)
   - Regular null intervals (every 2nd, 4th, 8th position)
   - Fixed-offset nulls indicating structured binary data

5. **Byte order consistency**: Verifies byte order is consistent throughout the string (for Auto mode)

**Confidence Formula**:

```
confidence = (valid_unicode_weight × valid_ratio)
           + (printable_weight × printable_ratio)
           + (ascii_weight × ascii_ratio)
           - (null_pattern_penalty)
           - (invalid_range_penalty)
```

The result is clamped to 0.0-1.0 range.

**Examples**:

- **High confidence**: "Microsoft Corporation" (>90% printable, valid Unicode, no null patterns)
- **Medium confidence**: "Test123" (>70% printable, valid Unicode)
- **Low confidence**: Null-interleaved binary table data (excessive nulls, regular patterns)

The UTF-16-specific confidence score is combined with general noise filtering confidence when noise filtering is enabled, using the minimum of both scores.

#### False Positive Prevention

UTF-16 extraction is prone to false positives because binary data with null bytes can look like UTF-16 strings. The confidence scoring system mitigates this by:

- **Detecting null-interleaved patterns**: Binary tables with numeric data (e.g., `[0x01, 0x00, 0x02, 0x00]`) are flagged as suspicious
- **Penalizing regular null patterns**: Data with nulls at fixed intervals (every 2nd, 4th, 8th byte) receives lower confidence
- **Validating Unicode ranges**: Invalid code points and surrogate pairs reduce confidence
- **Configurable threshold**: The `utf16_confidence_threshold` (default 0.5) can be tuned to balance recall and precision

**Recommendations**:

- For Windows PE binaries: Use `ByteOrder::LE` with `confidence_threshold: 0.6`
- For Java .class files: Use `ByteOrder::BE` with `confidence_threshold: 0.5`
- For unknown formats: Use `ByteOrder::Auto` with `confidence_threshold: 0.5`
- For high-precision extraction: Increase `confidence_threshold` to 0.7-0.8

#### Performance Considerations

UTF-16 scanning adds overhead compared to ASCII/UTF-8 extraction:

- **Scanning both byte orders**: Auto mode doubles the work by scanning for both LE and BE
- **Confidence scoring**: The multi-heuristic confidence calculation adds computational cost
- **Recommendations**:
  - Use specific byte order (LE or BE) when the target format is known
  - Auto mode is best for unknown or mixed-format binaries
  - Consider disabling UTF-16 extraction for formats that don't use it (e.g., pure ELF binaries)

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

```text
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

```text
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

```text
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

### Extraction Configuration

```text
use stringy::extraction::{ByteOrder, Encoding, ExtractionConfig};

pub struct ExtractionConfig {
    pub min_ascii_length: usize,          // Default: 4
    pub min_wide_length: usize,           // Default: 3 (for UTF-16)
    pub enabled_encodings: Vec<Encoding>, // Default: ASCII, UTF-8
    pub noise_filtering_enabled: bool,    // Default: true
    pub min_confidence_threshold: f32,    // Default: 0.5
    pub utf16_min_confidence: f32,        // Default: 0.7 (for UTF-16LE)
    pub utf16_byte_order: ByteOrder,      // Default: Auto
    pub utf16_confidence_threshold: f32,  // Default: 0.5 (UTF-16-specific)
}
```

**UTF-16 Configuration Examples**:

```text
use stringy::extraction::{ExtractionConfig, Encoding, ByteOrder};

// Extract UTF-16LE strings from Windows PE binary
let mut config = ExtractionConfig::default();
config.min_wide_length = 3;
config.utf16_confidence_threshold = 0.6;
config.utf16_byte_order = ByteOrder::LE;
config.enabled_encodings.push(Encoding::Utf16Le);

// Extract both UTF-16LE and UTF-16BE with auto-detection
let mut config = ExtractionConfig::default();
config.enabled_encodings.push(Encoding::Utf16Le);
config.enabled_encodings.push(Encoding::Utf16Be);
config.utf16_byte_order = ByteOrder::Auto;
```

### Noise Filter Configuration

```text
use stringy::extraction::config::NoiseFilterConfig;

pub struct NoiseFilterConfig {
    pub entropy_min: f32,              // Default: 1.5
    pub entropy_max: f32,              // Default: 7.5
    pub max_length: usize,             // Default: 200
    pub max_repetition_ratio: f32,     // Default: 0.7
    pub min_vowel_ratio: f32,          // Default: 0.1
    pub max_vowel_ratio: f32,          // Default: 0.9
    pub filter_weights: FilterWeights, // Default: balanced weights
}
```

### Filter Weights

```text
use stringy::extraction::config::FilterWeights;

pub struct FilterWeights {
    pub entropy_weight: f32,           // Default: 0.25
    pub char_distribution_weight: f32, // Default: 0.20
    pub linguistic_weight: f32,        // Default: 0.20
    pub length_weight: f32,            // Default: 0.15
    pub repetition_weight: f32,        // Default: 0.10
    pub context_weight: f32,           // Default: 0.10
}
```

All weights must sum to 1.0. The configuration validates this automatically.

### Encoding Selection

```text
#[non_exhaustive]
pub enum EncodingFilter {
    /// Match a specific encoding exactly
    Exact(Encoding),
    /// Match any UTF-16 variant (UTF-16LE or UTF-16BE)
    Utf16Any,
}
```

### Section Filtering

```text
pub struct SectionFilter {
    pub include_sections: Option<Vec<String>>,
    pub exclude_sections: Option<Vec<String>>,
    pub include_debug: bool,
    pub include_resources: bool,
}
```

## Performance Optimizations

### Memory Mapping

Large files use memory mapping for efficient access via `mmap-guard`:

```text
fn extract_from_large_file(path: &Path) -> Result<Vec<RawString>> {
    let data = mmap_guard::map_file(path)?;
    // data implements Deref<Target = [u8]>
    extract_strings(&data[..])
}
```

Note: The `Pipeline::run` API handles memory mapping automatically.

### Parallel Processing

Parallel processing is not yet implemented. Section extraction currently runs sequentially.

### Regex Caching

Pattern matching uses cached regex compilation:

```text
lazy_static! {
    static ref URL_REGEX: Regex = Regex::new(r"https?://[^\s]+").unwrap();
    static ref GUID_REGEX: Regex = Regex::new(r"\{[0-9a-fA-F-]{36}\}").unwrap();
}
```

## Quality Assurance

### Validation Heuristics

The noise filtering system implements comprehensive validation:

- **Entropy checking**: Uses Shannon entropy to detect padding/repetition and random binary data
- **Language detection**: Analyzes vowel-to-consonant ratios and common bigrams
- **Context validation**: Considers section type, weight, and permissions
- **Character distribution**: Detects abnormal frequency distributions
- **Repetition detection**: Identifies repeated patterns and padding

### False Positive Reduction

The multi-layered filtering system targets common sources of false positives:

- **Padding detection**: Identifies repeated character sequences (e.g., "AAAA", "\\x00\\x00\\x00\\x00")
- **Table data**: Filters excessively long strings likely to be structured data
- **Binary noise**: High-entropy strings are flagged as likely random binary
- **Context awareness**: Strings in code sections receive lower confidence scores

### Performance Characteristics

Noise filtering is designed for minimal overhead:

- **Target overhead**: \<10% compared to extraction without filtering
- **Optimized filters**: Each filter is independently optimized
- **Configurable**: Can enable/disable individual filters to balance accuracy and speed
- **Scalable**: Handles large binaries efficiently

### Examples

#### Basic Extraction with Filtering

```text
use stringy::extraction::{extract_ascii_strings, AsciiExtractionConfig};
use stringy::extraction::config::NoiseFilterConfig;
use stringy::extraction::filters::{CompositeNoiseFilter, FilterContext};

let data = b"Hello World\0AAAA\0Test123";
let config = AsciiExtractionConfig::default();
let strings = extract_ascii_strings(data, &config);

let filter_config = NoiseFilterConfig::default();
let filter = CompositeNoiseFilter::new(&filter_config);
let context = FilterContext::default();

let filtered: Vec<_> = strings
    .into_iter()
    .filter(|s| filter.calculate_confidence(&s.text, &context) >= 0.5)
    .collect();
```

#### Custom Filter Configuration

```text
use stringy::extraction::config::{NoiseFilterConfig, FilterWeights};

let mut config = NoiseFilterConfig::default();
config.entropy_min = 2.0;
config.entropy_max = 7.0;
config.max_length = 150;

config.filter_weights = FilterWeights {
    entropy_weight: 0.4,
    char_distribution_weight: 0.3,
    linguistic_weight: 0.15,
    length_weight: 0.1,
    repetition_weight: 0.03,
    context_weight: 0.02,
};
```

This comprehensive extraction system ensures high-quality string extraction while maintaining performance and minimizing false positives through multi-layered noise filtering.
