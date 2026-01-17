# Classification System

Stringy's classification system applies semantic analysis to extracted strings, identifying patterns that indicate specific types of data. This helps analysts quickly focus on the most relevant information.

## Classification Pipeline

```text
Raw String -> Pattern Matching -> Tag Assignment
```

## Semantic Categories

### Network Indicators

#### URLs

- **Pattern**: `` https?://[^\s<>"{}|\\^\[\]\`]+ ``
- **Examples**: `https://api.example.com/v1/users`, `http://malware.com/payload`
- **Validation**: URL format check with safe character filtering
- **Security relevance**: High - indicates network communication

#### Domain Names

- **Pattern**: `\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b`
- **Examples**: `api.example.com`, `malware-c2.net`
- **Validation**: TLD checking, DNS format compliance
- **Security relevance**: High - C2 domains, legitimate services

#### IP Addresses

- **IPv4 Pattern**: `\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`
- **IPv6 Pattern**: Comprehensive pattern supporting full notation, compressed notation (`::1`), and mixed notation (`::ffff:192.0.2.1`)
- **Examples**: `192.168.1.1`, `2001:db8::1`, `[::1]:8080`
- **Validation**: Two-stage validation using regex pre-filter followed by `std::net::IpAddr` parsing for correctness
- **Port Handling**: IP addresses with ports (e.g., `192.168.1.1:8080`) are supported by automatically stripping the port suffix before validation
- **IPv6 Bracket Handling**: Bracketed IPv6 addresses (e.g., `[::1]` and `[::1]:8080`) are supported
- **False Positive Mitigation**: Version numbers like `1.2.3.4` are accepted as IPv4 addresses by design
- **Implementation**: See `src/classification/semantic.rs` for the complete implementation
- **Security relevance**: High - infrastructure indicators

### File System Indicators

#### File Paths

- **POSIX Pattern**: `^/[^\0\n\r]*`
- **Windows Pattern**: `^[A-Za-z]:\\[^\0\n\r]*`
- **UNC Pattern**: `^\\\\[a-zA-Z0-9.-]+\\[^\0\n\r]*`
- **Examples**: `/usr/bin/malware`, `C:\\Windows\\System32\\evil.dll`, `\\\\server\\share\\file.txt`
- **Validation rules**: Rejects null bytes, newlines, carriage returns; rejects consecutive path separators in POSIX paths (`//`) and consecutive backslashes in Windows paths (for example, `folder\\\\file.txt`), while allowing UNC paths that start with `\\\\`; applies a reasonable length limit (4096 max, stricter for unknown prefixes); POSIX paths must be absolute (start with `/`); Windows paths must use backslashes and a valid drive letter
- **Suspicious path examples**: `/etc/cron.d/`, `/etc/init.d/`, `/usr/local/bin/`, `/tmp/`, `/var/tmp/`; `C:\\Windows\\System32\\`, `C:\\Windows\\Temp\\`, `...\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\`
- **Security relevance**: Medium-High - persistence and execution locations

#### Registry Paths

- **Full root pattern**: `^HKEY_[A-Z_]+\\[^\0\n\r]*`
- **Abbreviated root pattern**: `^HK(LM|CU|CR|U|CC)\\[^\0\n\r]*`
- **Supported root keys**:
  - `HKEY_LOCAL_MACHINE`
  - `HKEY_CURRENT_USER`
  - `HKEY_CLASSES_ROOT`
  - `HKEY_USERS`
  - `HKEY_CURRENT_CONFIG`
- **Supported abbreviations**:
  - `HKLM`, `HKCU`, `HKCR`, `HKU`, `HKCC`
- **Suspicious registry paths**:
  - `\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run`
  - `\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce`
  - `\\System\\CurrentControlSet\\Services`
  - `\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon`
- **Examples**:
  - `HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run`
  - `HKCU\\Software\\Microsoft`
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

### Pattern Matching Engine

The semantic classifier uses cached regex patterns via `lazy_static!` and applies validation checks to reduce false positives.

```rust
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref URL_REGEX: Regex = Regex::new(r#"https?://[^\s<>"{}|\\^\[\]\`]+"#).unwrap();
}

impl SemanticClassifier {
    pub fn classify(&self, string: &FoundString) -> Vec<Tag> {
        let mut tags = Vec::new();

        if self.classify_url(&string.text).is_some() {
            tags.push(Tag::Url);
        }

        if self.classify_domain(&string.text).is_some() {
            tags.push(Tag::Domain);
        }

        tags.extend(self.classify_ip_addresses(&string.text));

        if self.classify_posix_path(&string.text).is_some()
            || self.classify_windows_path(&string.text).is_some()
            || self.classify_unc_path(&string.text).is_some()
        {
            tags.push(Tag::FilePath);
        }

        if self.classify_registry_path(&string.text).is_some() {
            tags.push(Tag::RegistryPath);
        }

        tags
    }
}
```

## Implementation Details

The classifier relies on `lazy_static!` to compile regex patterns once and reuse them across classification calls. Helper methods validate strings before assigning tags.

### Method Signatures

Key method signatures:

```rust
pub fn classify(&self, string: &FoundString) -> Vec<Tag>;
pub fn classify_posix_path(&self, text: &str) -> Option<Tag>;
pub fn classify_windows_path(&self, text: &str) -> Option<Tag>;
pub fn classify_unc_path(&self, text: &str) -> Option<Tag>;
pub fn classify_registry_path(&self, text: &str) -> Option<Tag>;
```

## Using the Classification System

```rust
use stringy::classification::SemanticClassifier;
use stringy::types::{Encoding, FoundString, StringSource, Tag};

let classifier = SemanticClassifier::new();
let found_string = FoundString {
    text: "C:\\Windows\\System32\\cmd.exe".to_string(),
    encoding: Encoding::Ascii,
    offset: 0,
    rva: None,
    section: None,
    length: 27,
    tags: Vec::new(),
    score: 0,
    source: StringSource::SectionData,
    confidence: 1.0,
};

let tags = classifier.classify(&found_string);
if tags.contains(&Tag::FilePath) {
    // Handle file path indicator
}
```

## Confidence Scoring

The current implementation returns tags without explicit confidence scores. Confidence is implicit in the validation and matching logic. A future update may introduce explicit confidence values per tag.

## Planned Enhancements (implementation pending)

- Context-aware classification
- Symbol classification
- Additional semantic patterns (GUIDs, email addresses, base64, format strings) - documented above, implementation pending

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
