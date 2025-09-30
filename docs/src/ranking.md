# Ranking Algorithm

Stringy's ranking system prioritizes strings by relevance, helping analysts focus on the most important findings first. The algorithm combines multiple factors to produce a comprehensive relevance score.

## Scoring Formula

```text
Final Score = SectionWeight + EncodingConfidence + SemanticBoost - NoisePenalty
```

Each component contributes to the overall relevance assessment.

## Section Weight

Different sections have varying likelihood of containing meaningful strings.

### Weight Values

| Section Type | Weight | Rationale                                       |
| ------------ | ------ | ----------------------------------------------- |
| StringData   | 40     | Dedicated string storage (.rodata, \_\_cstring) |
| Resources    | 35     | PE resources, version info, manifests           |
| ReadOnlyData | 25     | Read-only after loading (.data.rel.ro)          |
| Debug        | 15     | Debug symbols, build info                       |
| WritableData | 10     | Runtime data, less reliable                     |
| Code         | 5      | Occasional embedded strings                     |
| Other        | 0      | Unknown or irrelevant sections                  |

### Format-Specific Adjustments

```rust
fn calculate_section_weight(
    section_type: SectionType,
    format: BinaryFormat,
    section_name: &str,
) -> i32 {
    let base_weight = match section_type {
        SectionType::StringData => 40,
        SectionType::Resources => 35,
        SectionType::ReadOnlyData => 25,
        SectionType::Debug => 15,
        SectionType::WritableData => 10,
        SectionType::Code => 5,
        SectionType::Other => 0,
    };

    // Format-specific bonuses
    let format_bonus = match (format, section_name) {
        (BinaryFormat::Elf, ".rodata.str1.1") => 5, // Aligned strings
        (BinaryFormat::Pe, ".rsrc") => 5,           // Rich resources
        (BinaryFormat::MachO, "__TEXT,__cstring") => 5, // Dedicated strings
        _ => 0,
    };

    base_weight + format_bonus
}
```

## Encoding Confidence

Different encodings have varying reliability indicators.

### Confidence Factors

#### ASCII/UTF-8

- **High confidence (10 points)**: All printable, reasonable length
- **Medium confidence (7 points)**: Mostly printable, some control chars
- **Low confidence (3 points)**: Mixed printable/non-printable

#### UTF-16

- **High confidence (8 points)**: >90% valid chars, proper null termination
- **Medium confidence (5 points)**: >70% valid chars, reasonable length
- **Low confidence (2 points)**: >50% valid chars, may be coincidental

```rust
fn calculate_encoding_confidence(string: &FoundString) -> i32 {
    match string.encoding {
        Encoding::Ascii | Encoding::Utf8 => {
            let printable_ratio = calculate_printable_ratio(&string.text);
            if printable_ratio > 0.95 {
                10
            } else if printable_ratio > 0.80 {
                7
            } else {
                3
            }
        }
        Encoding::Utf16Le | Encoding::Utf16Be => {
            let confidence = calculate_utf16_confidence(&string);
            if confidence > 0.90 {
                8
            } else if confidence > 0.70 {
                5
            } else {
                2
            }
        }
    }
}
```

## Semantic Boost

Strings with semantic meaning receive significant score boosts.

### Boost Values

| Tag Category                    | Boost | Examples                       |
| ------------------------------- | ----- | ------------------------------ |
| Network (URL, Domain, IP)       | +25   | `https://api.evil.com`         |
| Identifiers (GUID, Email)       | +20   | `{12345678-1234-...}`          |
| File System (Path, Registry)    | +15   | `C:\Windows\System32\evil.dll` |
| Code Artifacts (Format, Base64) | +10   | `Error: %s at line %d`         |
| Symbols (Import, Export)        | +8    | `CreateFileW`, `main`          |
| Version/Manifest                | +12   | `MyApp v1.2.3`                 |

### Multi-Tag Bonuses

Strings with multiple semantic tags receive additional boosts:

```rust
fn calculate_semantic_boost(tags: &[Tag]) -> i32 {
    let mut boost = 0;

    for tag in tags {
        boost += match tag {
            Tag::Url | Tag::Domain | Tag::IPv4 | Tag::IPv6 => 25,
            Tag::Guid | Tag::Email => 20,
            Tag::FilePath | Tag::RegistryPath => 15,
            Tag::Version | Tag::Manifest => 12,
            Tag::FormatString | Tag::Base64 => 10,
            Tag::Import | Tag::Export => 8,
            Tag::UserAgent => 15,
            Tag::Resource => 5,
        };
    }

    // Multi-tag bonus (diminishing returns)
    if tags.len() > 1 {
        boost += (tags.len() as i32 - 1) * 3;
    }

    boost
}
```

### Context-Aware Boosts

Semantic boosts are adjusted based on context:

```rust
fn apply_context_boost(base_boost: i32, context: &StringContext) -> i32 {
    let mut adjusted_boost = base_boost;

    // Boost for strings in high-value sections
    if matches!(
        context.section_type,
        SectionType::StringData | SectionType::Resources
    ) {
        adjusted_boost = (adjusted_boost as f32 * 1.2) as i32;
    }

    // Boost for import/export context
    if context.is_symbol_context {
        adjusted_boost += 5;
    }

    adjusted_boost
}
```

## Noise Penalty

Various factors indicate low-quality or noisy strings.

### Penalty Categories

#### High Entropy

Strings with high randomness are likely binary data:

```rust
fn calculate_entropy_penalty(text: &str) -> i32 {
    let entropy = calculate_shannon_entropy(text);

    if entropy > 4.5 {
        -15 // Very high entropy
    } else if entropy > 3.8 {
        -8 // High entropy
    } else {
        0 // Normal entropy
    }
}
```

#### Excessive Length

Very long strings are often noise:

```rust
fn calculate_length_penalty(length: usize) -> i32 {
    match length {
        0..=50 => 0,
        51..=200 => -2,
        201..=500 => -5,
        501..=1000 => -10,
        _ => -20,
    }
}
```

#### Repeated Patterns

Strings with excessive repetition:

```rust
fn calculate_repetition_penalty(text: &str) -> i32 {
    let repetition_ratio = detect_repetition_ratio(text);

    if repetition_ratio > 0.7 {
        -12 // Highly repetitive
    } else if repetition_ratio > 0.5 {
        -6 // Moderately repetitive
    } else {
        0 // Normal variation
    }
}
```

#### Common Noise Patterns

Known noise patterns receive penalties:

```rust
fn calculate_noise_pattern_penalty(text: &str) -> i32 {
    // Padding patterns
    if text.chars().all(|c| c == ' ' || c == '\0' || c == '\x20') {
        return -20;
    }

    // Hex dump patterns
    if text.matches(char::is_ascii_hexdigit).count() as f32 / text.len() as f32 > 0.8 {
        return -10;
    }

    // Table-like data
    if text.matches('\t').count() > 3 || text.matches(',').count() > 5 {
        return -8;
    }

    0
}
```

## Complete Scoring Implementation

```rust
pub struct RankingEngine {
    config: RankingConfig,
}

impl RankingEngine {
    pub fn calculate_score(&self, string: &FoundString, context: &StringContext) -> i32 {
        let section_weight = self.calculate_section_weight(context);
        let encoding_confidence = self.calculate_encoding_confidence(string);
        let semantic_boost = self.calculate_semantic_boost(&string.tags, context);
        let noise_penalty = self.calculate_noise_penalty(string);

        let raw_score = section_weight + encoding_confidence + semantic_boost + noise_penalty;

        // Clamp to valid range
        raw_score.max(0).min(100)
    }

    fn calculate_noise_penalty(&self, string: &FoundString) -> i32 {
        let entropy_penalty = calculate_entropy_penalty(&string.text);
        let length_penalty = calculate_length_penalty(string.length as usize);
        let repetition_penalty = calculate_repetition_penalty(&string.text);
        let pattern_penalty = calculate_noise_pattern_penalty(&string.text);

        entropy_penalty + length_penalty + repetition_penalty + pattern_penalty
    }
}
```

## Score Interpretation

### Score Ranges

| Range  | Interpretation | Typical Content                |
| ------ | -------------- | ------------------------------ |
| 90-100 | Extremely High | URLs, GUIDs in .rdata          |
| 80-89  | Very High      | File paths, API names          |
| 70-79  | High           | Format strings, version info   |
| 60-69  | Medium-High    | Import names, long strings     |
| 50-59  | Medium         | Short strings in good sections |
| 40-49  | Medium-Low     | Strings in data sections       |
| 30-39  | Low            | Short or noisy strings         |
| 0-29   | Very Low       | Likely false positives         |

### Filtering Recommendations

- **Interactive analysis**: Show scores ≥ 50
- **Automated processing**: Use scores ≥ 70
- **YARA rules**: Focus on scores ≥ 80
- **High-confidence indicators**: Scores ≥ 90

## Configuration Options

```rust
pub struct RankingConfig {
    pub section_weights: HashMap<SectionType, i32>,
    pub semantic_boosts: HashMap<Tag, i32>,
    pub entropy_threshold: f32,
    pub length_penalty_threshold: usize,
    pub repetition_threshold: f32,
}

impl Default for RankingConfig {
    fn default() -> Self {
        Self {
            section_weights: default_section_weights(),
            semantic_boosts: default_semantic_boosts(),
            entropy_threshold: 4.5,
            length_penalty_threshold: 200,
            repetition_threshold: 0.5,
        }
    }
}
```

## Performance Considerations

### Caching

- Pre-calculate entropy for reused strings
- Cache regex matches for pattern detection
- Memoize expensive calculations

### Batch Processing

```rust
pub fn rank_strings_batch(strings: &mut [FoundString], contexts: &[StringContext]) {
    strings
        .par_iter_mut()
        .zip(contexts.par_iter())
        .for_each(|(string, context)| {
            string.score = self.calculate_score(string, context);
        });

    // Sort by score (highest first)
    strings.sort_by(|a, b| b.score.cmp(&a.score));
}
```

This comprehensive ranking system ensures that the most relevant and actionable strings appear first in Stringy's output, dramatically improving analysis efficiency.
