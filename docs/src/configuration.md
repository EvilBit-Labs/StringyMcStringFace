# Configuration

Stringy provides extensive configuration options to customize string extraction, classification, and output formatting. Configuration can be provided through command-line arguments, configuration files, or programmatically via the API.

## Configuration File

**Note**: Configuration file support is planned for future releases.

### Default Location

```text
~/.config/stringy/config.toml
```

### Example Configuration

```toml
[extraction]
min_ascii_len = 4
min_utf16_len = 3
max_string_len = 1024
encodings = ["ascii", "utf16le"]
include_debug = false
include_symbols = true

[classification]
detect_urls = true
detect_domains = true
detect_ips = true
detect_paths = true
detect_guids = true
detect_emails = true
detect_base64 = true
detect_format_strings = true
min_confidence = 0.7

[output]
format = "human"
max_results = 100
show_scores = true
show_offsets = true
color = true

[ranking]
section_weight_multiplier = 1.0
semantic_boost_multiplier = 1.0
noise_penalty_multiplier = 1.0

# Profile-specific configurations
[profiles.security]
encodings = ["ascii", "utf8", "utf16le"]
min_ascii_len = 6
only_tags = ["url", "domain", "ipv4", "ipv6", "filepath", "regpath"]
min_score = 70

[profiles.yara]
format = "yara"
min_ascii_len = 8
exclude_tags = ["import", "export"]
min_score = 80

[profiles.development]
include_debug = true
include_symbols = true
max_results = 500
```

## Extraction Configuration

### String Length Limits

Control the minimum and maximum string lengths:

```toml
[extraction]
min_ascii_len = 4     # Minimum ASCII string length
min_utf16_len = 3     # Minimum UTF-16 string length
max_string_len = 1024 # Maximum string length (prevents memory issues)
```

**CLI equivalent:**

```bash
stringy --min-len 6 --max-len 500 binary
```

### Encoding Selection

Choose which encodings to extract:

```toml
[extraction]
encodings = ["ascii", "utf8", "utf16le", "utf16be"]
```

**Available encodings:**

- `ascii`: 7-bit ASCII
- `utf8`: UTF-8 (includes ASCII)
- `utf16le`: UTF-16 Little Endian
- `utf16be`: UTF-16 Big Endian

**CLI equivalent:**

```bash
stringy --enc ascii,utf16le binary
```

### Section Filtering

Control which sections to analyze:

```toml
[extraction]
include_sections = [".rodata", ".rdata", "__cstring"]
exclude_sections = [".debug_info", ".comment"]
include_debug = false
include_resources = true
```

**CLI equivalent:**

```bash
stringy --sections .rodata,.rdata --no-debug binary
```

### Symbol Processing

Configure import/export symbol handling:

```toml
[extraction]
include_symbols = true
demangle_rust = true
demangle_cpp = false   # Future feature
```

**CLI equivalent:**

```bash
stringy --no-symbols --no-demangle binary
```

## Classification Configuration

### Pattern Detection

Enable/disable specific semantic patterns:

```toml
[classification]
detect_urls = true
detect_domains = true
detect_ips = true
detect_paths = true
detect_guids = true
detect_emails = true
detect_base64 = true
detect_format_strings = true
detect_user_agents = true
```

### Confidence Thresholds

Set minimum confidence levels:

```toml
[classification]
min_confidence = 0.7         # Overall minimum confidence
url_min_confidence = 0.8     # URL-specific threshold
domain_min_confidence = 0.75 # Domain-specific threshold
path_min_confidence = 0.6    # File path threshold
```

### Custom Patterns

Add custom regex patterns:

```toml
[classification.custom_patterns]
api_key = 'api[_-]?key["\s]*[:=]["\s]*[a-zA-Z0-9]{20,}'
crypto_address = '(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}'
jwt_token = 'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
```

## Ranking Configuration

### Weight Adjustments

Customize section and semantic weights:

```toml
[ranking.section_weights]
string_data = 40
resources = 35
readonly_data = 25
debug = 15
writable_data = 10
code = 5
other = 0

[ranking.semantic_boosts]
url = 25
domain = 20
guid = 20
filepath = 15
format_string = 10
import = 8
export = 8
```

### Penalty Configuration

Adjust noise detection penalties:

```toml
[ranking.penalties]
high_entropy_threshold = 4.5
high_entropy_penalty = -15
length_penalty_threshold = 200
max_length_penalty = -20
repetition_threshold = 0.7
repetition_penalty = -12
```

## Output Configuration

### Format Selection

Choose default output format:

```toml
[output]
format = "human"  # human, json, yara
max_results = 100 # Limit number of results
show_all = false  # Override max_results limit
```

### Display Options

Customize what information to show:

```toml
[output]
show_scores = true
show_offsets = true
show_sections = true
show_encodings = true
show_tags = true
color = true                   # Enable colored output
truncate_long_strings = true
max_string_display_length = 80
```

### Filtering

Set default filters:

```toml
[output]
min_score = 50
only_tags = []         # Empty = show all tags
exclude_tags = ["b64"] # Exclude Base64 by default
```

## Format-Specific Configuration

### PE Configuration

Windows PE-specific options:

```toml
[formats.pe]
extract_version_info = true
extract_manifests = true
extract_string_tables = true
prefer_utf16 = true
include_resource_names = true
```

### ELF Configuration

Linux ELF-specific options:

```toml
[formats.elf]
include_build_id = true
include_gnu_version = true
process_dynamic_strings = true
include_note_sections = false
```

### Mach-O Configuration

macOS Mach-O-specific options:

```toml
[formats.macho]
process_load_commands = true
include_framework_paths = true
process_fat_binaries = "first" # first, all, or specific arch
```

## Performance Configuration

### Memory Management

Control memory usage:

```toml
[performance]
use_memory_mapping = true
memory_map_threshold = 10485760 # 10MB
max_memory_usage = 1073741824   # 1GB
```

### Parallel Processing

Configure parallelization:

```toml
[performance]
enable_parallel = true
max_threads = 0        # 0 = auto-detect
chunk_size = 1048576   # 1MB chunks
```

### Caching

Enable various caches:

```toml
[performance]
cache_regex_compilation = true
cache_section_analysis = true
cache_string_hashes = true
```

## Environment Variables

Override configuration with environment variables:

| Variable              | Description            | Example           |
| --------------------- | ---------------------- | ----------------- |
| `STRINGY_CONFIG`      | Config file path       | `~/.stringy.toml` |
| `STRINGY_MIN_LEN`     | Minimum string length  | `6`               |
| `STRINGY_FORMAT`      | Output format          | `json`            |
| `STRINGY_MAX_RESULTS` | Result limit           | `50`              |
| `NO_COLOR`            | Disable colored output | `1`               |

## Profiles

Use predefined configuration profiles:

### Security Analysis Profile

```bash
stringy --profile security malware.exe
```

Equivalent to:

```toml
min_ascii_len = 6
encodings = ["ascii", "utf8", "utf16le"]
only_tags = ["url", "domain", "ipv4", "ipv6", "filepath", "regpath"]
min_score = 70
```

### YARA Development Profile

```bash
stringy --profile yara suspicious.dll
```

Equivalent to:

```toml
format = "yara"
min_ascii_len = 8
exclude_tags = ["import", "export"]
min_score = 80
max_results = 50
```

### Development Profile

```bash
stringy --profile dev application
```

Equivalent to:

```toml
include_debug = true
include_symbols = true
max_results = 500
show_all_metadata = true
```

## Validation

Configuration validation ensures settings are compatible:

```toml
# This would generate a warning
[extraction]
min_ascii_len = 10
max_string_len = 5 # Invalid: min > max
```

## Migration

When upgrading Stringy versions, configuration migration is handled automatically:

```bash
# Backup current config
cp ~/.config/stringy/config.toml ~/.config/stringy/config.toml.backup

# Stringy will migrate on first run
stringy --version
```

## Examples

### Minimal Configuration

```toml
[extraction]
min_ascii_len = 6

[output]
format = "json"
max_results = 50
```

### Comprehensive Security Analysis

```toml
[extraction]
min_ascii_len = 6
min_utf16_len = 4
encodings = ["ascii", "utf8", "utf16le"]
include_debug = false

[classification]
detect_urls = true
detect_domains = true
detect_ips = true
detect_paths = true
detect_guids = true
min_confidence = 0.8

[output]
format = "json"
min_score = 70
only_tags = ["url", "domain", "ipv4", "ipv6", "filepath", "regpath", "guid"]

[ranking.semantic_boosts]
url = 30
domain = 25
ipv4 = 25
ipv6 = 25
filepath = 20
regpath = 20
guid = 20
```

This flexible configuration system allows Stringy to be adapted for various use cases, from interactive analysis to automated security pipelines.
