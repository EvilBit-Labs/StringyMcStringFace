# Classification System

Stringy's classification system applies semantic analysis to extracted strings, identifying patterns that indicate specific types of data. This helps analysts quickly focus on the most relevant information.

## Classification Pipeline

```text
Raw String → Pattern Matching → Context Analysis → Tag Assignment → Confidence Scoring
```

## Semantic Categories

### Network Indicators

#### URLs

- **Pattern**: `https?://[^\s]+`
- **Examples**: `https://api.example.com/v1/users`, `http://malware.com/payload`
- **Confidence factors**: Valid TLD, path structure, parameter format
- **Security relevance**: High - indicates network communication

#### Domain Names

- **Pattern**: `[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`
- **Examples**: `api.example.com`, `malware-c2.net`
- **Validation**: TLD checking, DNS format compliance
- **Security relevance**: High - C2 domains, legitimate services

#### IP Addresses

- **IPv4 Pattern**: `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`
- **IPv6 Pattern**: `\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b`
- **Examples**: `192.168.1.1`, `2001:db8::1`
- **Validation**: Range checking, reserved address detection
- **Security relevance**: High - infrastructure indicators

### File System Indicators

#### File Paths

- **POSIX Pattern**: `/[^\0\n\r]*`
- **Windows Pattern**: `[A-Za-z]:\\[^\0\n\r]*`
- **Examples**: `/usr/bin/malware`, `C:\Windows\System32\evil.dll`
- **Context**: Section type, surrounding strings
- **Security relevance**: Medium-High - persistence locations

#### Registry Paths

- **Pattern**: `HKEY_[A-Z_]+\\[^\0\n\r]*`
- **Examples**: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- **Security relevance**: High - persistence mechanisms

### Identifiers

#### GUIDs/UUIDs

- **Pattern**: `\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}`
- **Examples**: `{12345678-1234-1234-1234-123456789abc}`
- **Validation**: Format compliance, version checking
- **Security relevance**: Medium - component identification

#### Email Addresses

- **Pattern**: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`
- **Examples**: `admin@malware.com`, `support@legitimate.org`
- **Validation**: RFC compliance, domain validation
- **Security relevance**: Medium - contact information

### Code Artifacts

#### Format Strings

- **Pattern**: `%[sdxo]|%\d+[sdxo]|\{\d+\}`
- **Examples**: `Error: %s at line %d`, `User {0} logged in`
- **Context**: Proximity to other format strings
- **Security relevance**: Low-Medium - debugging information

#### Base64 Data

- **Pattern**: `[A-Za-z0-9+/]{20,}={0,2}`
- **Examples**: `SGVsbG8gV29ybGQ=`
- **Validation**: Length divisibility, padding correctness
- **Security relevance**: Variable - encoded payloads

### User Agents

- **Pattern**: `Mozilla/[0-9.]+|Chrome/[0-9.]+|Safari/[0-9.]+`
- **Examples**: `Mozilla/5.0 (Windows NT 10.0; Win64; x64)`
- **Security relevance**: Medium - network fingerprinting

## Implementation Details

### Pattern Matching Engine

```rust
pub struct SemanticClassifier {
    url_regex: Regex,
    domain_regex: Regex,
    ipv4_regex: Regex,
    ipv6_regex: Regex,
    guid_regex: Regex,
    email_regex: Regex,
    format_regex: Regex,
    base64_regex: Regex,
}

impl SemanticClassifier {
    pub fn classify(&self, text: &str, context: &StringContext) -> Vec<Tag> {
        let mut tags = Vec::new();

        // Network indicators
        if self.url_regex.is_match(text) {
            tags.push(Tag::Url);
        }

        if self.domain_regex.is_match(text) && !tags.contains(&Tag::Url) {
            tags.push(Tag::Domain);
        }

        // File system
        if self.is_file_path(text) {
            tags.push(Tag::FilePath);
        }

        if self.is_registry_path(text) {
            tags.push(Tag::RegistryPath);
        }

        // Continue for other patterns...

        tags
    }
}
```

### Context-Aware Classification

Classification considers the context where strings are found:

```rust
pub struct StringContext {
    pub section_type: SectionType,
    pub section_name: Option<String>,
    pub surrounding_strings: Vec<String>,
    pub binary_format: BinaryFormat,
    pub encoding: Encoding,
}

impl SemanticClassifier {
    fn classify_with_context(&self, text: &str, context: &StringContext) -> Vec<Tag> {
        let mut tags = self.classify_patterns(text);

        // Boost confidence based on context
        match context.section_type {
            SectionType::Resources => {
                if self.looks_like_version_string(text) {
                    tags.push(Tag::Version);
                }
            }
            SectionType::StringData => {
                // Higher confidence for semantic patterns
                self.boost_pattern_confidence(&mut tags);
            }
            _ => {}
        }

        tags
    }
}
```

### Symbol Classification

Import and export symbols get special handling:

```rust
pub struct SymbolClassifier {
    known_apis: HashSet<String>,
    crypto_apis: HashSet<String>,
    network_apis: HashSet<String>,
}

impl SymbolClassifier {
    pub fn classify_symbol(&self, name: &str, is_import: bool) -> Vec<Tag> {
        let mut tags = Vec::new();

        if is_import {
            tags.push(Tag::Import);
        } else {
            tags.push(Tag::Export);
        }

        // Add semantic tags based on API name
        if self.crypto_apis.contains(name) {
            tags.push(Tag::Crypto);
        }

        if self.network_apis.contains(name) {
            tags.push(Tag::Network);
        }

        tags
    }
}
```

### Rust Symbol Demangling

```rust
use rustc_demangle::demangle;

pub fn classify_rust_symbol(mangled: &str) -> Vec<Tag> {
    let mut tags = vec![Tag::Export];

    if let Ok(demangled) = demangle(mangled) {
        let demangled_str = demangled.to_string();

        // Look for common Rust patterns
        if demangled_str.contains("::main") {
            tags.push(Tag::EntryPoint);
        }

        if demangled_str.contains("panic") {
            tags.push(Tag::ErrorHandling);
        }
    }

    tags
}
```

## Confidence Scoring

Each classification receives a confidence score:

```rust
pub struct ClassificationResult {
    pub tag: Tag,
    pub confidence: f32, // 0.0 to 1.0
    pub evidence: Vec<String>,
}

impl SemanticClassifier {
    fn calculate_confidence(&self, text: &str, tag: &Tag, context: &StringContext) -> f32 {
        let mut confidence = 0.5; // Base confidence

        match tag {
            Tag::Url => {
                if text.starts_with("https://") {
                    confidence += 0.3;
                }
                if self.has_valid_tld(text) {
                    confidence += 0.2;
                }
            }
            Tag::FilePath => {
                if context.section_type == SectionType::StringData {
                    confidence += 0.2;
                }
                if self.has_valid_path_structure(text) {
                    confidence += 0.2;
                }
            } // ... other tag-specific confidence calculations
        }

        confidence.min(1.0)
    }
}
```

## Advanced Classification Features

### Multi-Pattern Matching

Some strings match multiple patterns:

```rust
fn classify_multi_pattern(&self, text: &str) -> Vec<Tag> {
    let mut tags = Vec::new();

    // A string can be both a URL and contain Base64
    if self.url_regex.is_match(text) {
        tags.push(Tag::Url);

        // Check if URL contains Base64 parameters
        if let Some(query) = self.extract_url_query(text) {
            if self.base64_regex.is_match(query) {
                tags.push(Tag::Base64);
            }
        }
    }

    tags
}
```

### Language-Specific Patterns

Different programming languages have distinct string patterns:

```rust
pub enum LanguageHint {
    Rust,
    Go,
    DotNet,
    Native,
}

impl SemanticClassifier {
    fn classify_with_language_hint(&self, text: &str, hint: LanguageHint) -> Vec<Tag> {
        match hint {
            LanguageHint::Rust => self.classify_rust_patterns(text),
            LanguageHint::Go => self.classify_go_patterns(text),
            LanguageHint::DotNet => self.classify_dotnet_patterns(text),
            LanguageHint::Native => self.classify_native_patterns(text),
        }
    }
}
```

### False Positive Reduction

Several techniques reduce false positives:

1. **Length thresholds**: Very short matches are filtered out
2. **Context validation**: Surrounding data must make sense
3. **Entropy checking**: High-entropy strings are likely binary data
4. **Whitelist/blacklist**: Known good/bad patterns

```rust
fn is_likely_false_positive(&self, text: &str, tag: &Tag) -> bool {
    match tag {
        Tag::Domain => {
            // Too short or invalid TLD
            text.len() < 4 || !self.has_valid_tld(text)
        }
        Tag::Base64 => {
            // Too short or invalid padding
            text.len() < 8 || !self.valid_base64_padding(text)
        }
        _ => false,
    }
}
```

## Performance Considerations

### Regex Compilation Caching

```rust
lazy_static! {
    static ref COMPILED_PATTERNS: SemanticClassifier = SemanticClassifier::new();
}
```

### Parallel Classification

```rust
use rayon::prelude::*;

fn classify_batch(strings: &[RawString]) -> Vec<ClassifiedString> {
    strings.par_iter().map(|s| classify_single(s)).collect()
}
```

### Memory Efficiency

- Reuse regex objects across classifications
- Use string interning for common patterns
- Lazy evaluation for expensive validations

This comprehensive classification system enables Stringy to automatically identify and categorize the most relevant strings in binary files, significantly improving analysis efficiency.
