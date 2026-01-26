# Classification System

Stringy applies semantic analysis to extracted strings, identifying patterns that indicate specific types of data. This helps analysts focus on the most relevant information quickly.

## Classification Pipeline

```text
Raw String -> Pattern Matching -> Validation -> Tag Assignment
```

## Semantic Categories

### URLs

- Pattern: `https?://[^\s<>"{}|\\\^\[\]\`\]+\`
- Examples: `https://example.com/path`, `http://malware.site/payload`
- Validation: Must start with `http://` or `https://`

### Domain Names

- Pattern: RFC 1035 compliant domain format
- Examples: `example.com`, `subdomain.evil.site`
- Validation: Valid TLD from known list, not a URL or email

### IP Addresses

- IPv4 Pattern: Standard dotted-decimal notation
- IPv6 Pattern: Full and compressed formats
- Examples: `192.168.1.1`, `::1`, `2001:db8::1`
- Validation: Valid octet ranges for IPv4, proper format for IPv6

### File Paths

- POSIX Pattern: Paths starting with `/`
- Windows Pattern: Drive letters (`C:\`) or relative paths
- UNC Pattern: `\\server\share` format
- Examples: `/etc/passwd`, `C:\Windows\System32`, `\\server\share\file`

### Registry Paths

- Pattern: `HKEY_*` or `HK*\` prefixes
- Examples: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft`
- Validation: Must start with valid registry root key

### GUIDs

- Pattern: `\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}`
- Examples: `{12345678-1234-1234-1234-123456789abc}`
- Validation: Strict format compliance with braces required

### Email Addresses

- Pattern: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`
- Examples: `admin@malware.com`, `user.name+tag@example.co.uk`
- Validation: Single `@`, valid TLD length and characters, no empty parts

### Base64 Data

- Pattern: `[A-Za-z0-9+/]{20,}={0,2}`
- Examples: `U29tZSBsb25nZXIgYmFzZTY0IHN0cmluZw==`
- Validation: Length >= 20, length divisible by 4, padding rules, entropy threshold

### Format Strings

- Pattern: `%[sdxofcpn]|%\d+[sdxofcpn]|\{\d+\}`
- Examples: `Error: %s at line %d`, `User {0} logged in`
- Validation: Reasonable specifier count, context-aware thresholds

### User Agents

- Pattern: `Mozilla/[0-9.]+|Chrome/[0-9.]+|Safari/[0-9.]+|AppleWebKit/[0-9.]+`
- Examples: `Mozilla/5.0 (Windows NT 10.0; Win64; x64)`, `Chrome/117.0.5938.92`
- Validation: Known browser identifiers and minimum length

## Pattern Matching Engine

The semantic classifier uses cached regex patterns via `once_cell::sync::Lazy` and applies validation checks to reduce false positives.

```rust
use once_cell::sync::Lazy;
use regex::Regex;

static GUID_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$")
        .expect("Invalid GUID regex")
});
```

## Using the Classification System

```rust
use stringy::classification::SemanticClassifier;
use stringy::types::{BinaryFormat, Encoding, SectionType, StringContext, StringSource, Tag};

let classifier = SemanticClassifier::new();
let context = StringContext::new(
    SectionType::StringData,
    BinaryFormat::Elf,
    Encoding::Ascii,
    StringSource::SectionData,
)
.with_section_name(".rodata".to_string());

let tags = classifier.classify("{12345678-1234-1234-1234-123456789abc}", &context);
if tags.contains(&Tag::Guid) {
    // Handle GUID indicator
}
```

## Validation Rules

- GUID: Braced, hyphenated, hex-only format.
- Email: TLD length must be between 2 and 24 and alphabetic; domain must include a dot.
- Base64: Length must be divisible by 4, padding allowed only at the end, entropy threshold applied.
- Format String: Must contain at least one specifier and pass context-aware length checks.
- User Agent: Must contain a known browser token and meet minimum length.

## Performance Notes

- Regexes are compiled once via `once_cell::sync::Lazy` and reused across calls.
- Minimum length checks avoid unnecessary regex work on short inputs.
- The classifier is stateless and thread-safe.

## Testing

- Unit tests: `tests/classification_tests.rs`
- Integration tests: `tests/classification_integration_tests.rs`

Run tests with:

```text
just test
```
