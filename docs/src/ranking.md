# Ranking Algorithm

Stringy's ranking system prioritizes strings by relevance, helping analysts focus on the most important findings first. The algorithm combines multiple factors to produce a comprehensive relevance score.

## Scoring Formula

```text
Final Score = SectionWeight + SemanticBoost - NoisePenalty
```

Each component contributes to the overall relevance assessment. The resulting internal score is then mapped to a display score (0-100) via band mapping.

> **Note:** Section weights use a 1.0-10.0 scale, and semantic boosts add to the internal score. The pipeline's normalizer then maps the combined internal score to a 0-100 display score using the band table shown in [Display Score Mapping](#display-score-mapping) below.

## Section Weight

Different sections have varying likelihood of containing meaningful strings. Container parsers assign weights (1.0-10.0) to each section based on its type and name.

### Weight Ranges

| Section Type             | Typical Weight | Examples                               |
| ------------------------ | -------------- | -------------------------------------- |
| Dedicated string storage | 8.0-10.0       | `.rodata`, `__TEXT,__cstring`, `.rsrc` |
| Read-only data           | 7.0            | `.data.rel.ro`, `__DATA_CONST`         |
| General data             | 5.0            | `.data`                                |
| Code sections            | 1.0            | `.text`                                |

Format-specific adjustments are applied based on section names. For example, ELF `.rodata.str1.1` (aligned strings) and PE `.rsrc` (rich resources) receive additional priority.

## Semantic Boost

Strings with recognized semantic meaning receive score boosts based on their tags.

### Boost Categories

| Tag Category                            | Boost Level | Examples                       |
| --------------------------------------- | ----------- | ------------------------------ |
| Network (URL, Domain, IP)               | High        | `https://api.evil.com`         |
| Identifiers (GUID, Email)               | High        | `{12345678-1234-...}`          |
| File System (Path, Registry)            | Medium-High | `C:\Windows\System32\evil.dll` |
| User-Agent-like strings                 | Medium-High | `Mozilla/5.0 ...`              |
| Version/Manifest                        | Medium      | `MyApp v1.2.3`                 |
| Code Artifacts (Format strings, Base64) | Medium      | `Error: %s at line %d`         |
| Symbols (Import, Export)                | Low-Medium  | `CreateFileW`, `main`          |

Strings with multiple semantic tags receive additional (diminishing) bonuses for each extra tag.

## Noise Penalty

Various factors indicate low-quality or noisy strings, and receive penalties. The penalty is derived from each string's confidence value (0.0-1.0): lower confidence produces a larger penalty.

### Penalty Categories

- **High Entropy**: Strings with high Shannon entropy (randomness) are likely binary data or encoded content and receive significant penalties.

- **Excessive Length**: Very long strings are often noise (padding, embedded data). Longer strings receive progressively larger penalties.

- **Repeated Patterns**: Strings with excessive character repetition (e.g., `AAAAAAA...`) are penalized based on the repetition ratio.

- **Common Noise Patterns**: Known noise patterns receive penalties, including padding characters, hex dump patterns, and table-like data with excessive delimiters.

### Encoding Quality

Encoding-quality signals also feed the confidence value (and therefore the noise penalty) -- there is no separate encoding term in the scoring formula:

- **UTF-16 strings**: Extraction computes an encoding-specific confidence (unicode validity, printability, interior-null patterns) and combines it with the noise-filter confidence by taking the minimum.

- **Narrow (ASCII/UTF-8) strings**: A string cut off by a non-null byte has its confidence capped at 0.9, since real C strings in string-bearing sections are normally null-terminated. Null-terminated strings and strings running to the end of a section are unaffected. The cap is deliberately small: binaries that store strings without terminators (length-prefixed or packed data) are nudged, never buried.

UTF-16 termination-byte quality is not evaluated; the UTF-16 null terminator is used only to trim string bytes.

## Display Score Mapping

The internal score is mapped to a display score (0-100) using bands:

| Internal Score | Display Score | Meaning       |
| -------------- | ------------- | ------------- |
| \<= 0          | 0             | Low relevance |
| 1-79           | 1-49          | Low relevance |
| 80-119         | 50-69         | Moderate      |
| 120-159        | 70-89         | Meaningful    |
| 160-220        | 90-100        | High-value    |
| > 220          | 100 (clamped) | High-value    |

### Filtering Recommendations

- **Interactive analysis**: Show display scores >= 50
- **Automated processing**: Use display scores >= 70
- **YARA rules**: Focus on display scores >= 80
- **High-confidence indicators**: Display scores >= 90
