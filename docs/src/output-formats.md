# Output Formats

Stringy supports multiple output formats optimized for different use cases. Each format presents the same underlying data with different emphasis and structure.

## Human-Readable Format (Default)

The default format provides an interactive table view optimized for manual analysis.

### Example Output

```text
Score  Offset    Section    Encoding  Tags           String
-----  ------    -------    --------  ----           ------
  95   0x1000    .rdata     utf-8     url,https      https://api.example.com/v1/users
  87   0x2000    .rdata     utf-8     guid           {12345678-1234-1234-1234-123456789abc}
  82   0x3000    __cstring  utf-8     filepath       /usr/local/bin/application
  78   0x4000    .rdata     utf-8     fmt            Error: %s at line %d
  75   0x5000    .rsrc      utf-16le  version        MyApplication v1.2.3
```

### Features

- **Color coding**: High scores in green, medium in yellow, low in red
- **Truncation**: Long strings are truncated with `...` indicator
- **Sorting**: Results sorted by score (highest first)
- **Alignment**: Columns properly aligned for readability

### Usage

```bash
stringy binary                    # Default format
stringy --format human binary     # Explicit format
```

## JSON Lines Format

Machine-readable format with one JSON object per line, ideal for automation and pipeline integration.

### Example Output

```json
{"text":"https://api.example.com/v1/users","encoding":"utf-8","offset":4096,"rva":4096,"section":".rdata","length":31,"tags":["url"],"score":95,"source":"SectionData"}
{"text":"{12345678-1234-1234-1234-123456789abc}","encoding":"utf-8","offset":8192,"rva":8192,"section":".rdata","length":38,"tags":["guid"],"score":87,"source":"SectionData"}
```

### Schema

Each JSON object contains:

| Field      | Type         | Description                                             |
| ---------- | ------------ | ------------------------------------------------------- |
| `text`     | string       | The extracted string                                    |
| `encoding` | string       | Encoding used: `ascii`, `utf-8`, `utf-16le`, `utf-16be` |
| `offset`   | number       | File offset in bytes                                    |
| `rva`      | number\|null | Relative Virtual Address (if available)                 |
| `section`  | string\|null | Section name where found                                |
| `length`   | number       | String length in bytes                                  |
| `tags`     | array        | Semantic classification tags                            |
| `score`    | number       | Relevance score (0-100)                                 |
| `source`   | string       | Source type: `SectionData`, `ImportName`, etc.          |

### Usage

```bash
stringy --json binary             # JSON Lines format
stringy --format json binary      # Explicit format
```

### Processing Examples

```bash
# Extract only URLs
stringy --json binary | jq 'select(.tags[] == "url") | .text'

# High-confidence strings only
stringy --json binary | jq 'select(.score > 80)'

# Group by section
stringy --json binary | jq -r '.section' | sort | uniq -c

# Find strings in specific section
stringy --json binary | jq 'select(.section == ".rdata")'
```

## YARA Format

Specialized format for creating YARA detection rules, with proper escaping and metadata.

### Example Output

```yara
/*
 * Stringy extraction from: binary.exe
 * Generated: 2024-01-15 10:30:00 UTC
 * High-confidence strings (score >= 80)
 */

rule binary_exe_strings {
    meta:
        description = "Strings extracted from binary.exe"
        generated_by = "stringy"

    strings:
        // URLs (score: 95)
        $url_1 = "https://api.example.com/v1/users" ascii wide

        // GUIDs (score: 87)
        $guid_1 = "{12345678-1234-1234-1234-123456789abc}" ascii wide

        // File paths (score: 82)
        $path_1 = "/usr/local/bin/application" ascii

        // Format strings (score: 78)
        $fmt_1 = "Error: %s at line %d" ascii

    condition:
        any of them
}
```

### Features

- **Proper escaping**: Handles special characters and binary data
- **Hex encoding**: Binary strings converted to hex format
- **Metadata**: Includes extraction timestamp and source file
- **Grouping**: Strings grouped by semantic category
- **Comments**: Score and classification information in comments
- **Modifiers**: Appropriate `ascii`/`wide` modifiers based on encoding

### Usage

```bash
stringy --yara binary             # YARA format
stringy --format yara binary      # Explicit format
stringy --yara --min-len 8 binary # Longer strings only
```

## Format Comparison

| Feature             | Human | JSON | YARA |
| ------------------- | ----- | ---- | ---- |
| **Interactive use** | ✅    | ❌   | ❌   |
| **Automation**      | ❌    | ✅   | ⚠️   |
| **Rule creation**   | ❌    | ⚠️   | ✅   |
| **Filtering**       | ✅    | ✅   | ✅   |
| **Metadata**        | ⚠️    | ✅   | ⚠️   |
| **Readability**     | ✅    | ❌   | ✅   |

## Output Customization

### Filtering Output

All formats support the same filtering options:

```bash
# Limit results
stringy --top 50 --format json binary

# Filter by tags
stringy --only url,domain --format yara binary

# Minimum score threshold
stringy --json binary | jq 'select(.score >= 70)'
```

### Redirection and Files

```bash
# Save to file
stringy --json binary > strings.jsonl
stringy --yara binary > rules.yar

# Pipe to other tools
stringy --json binary | jq '.[] | select(.tags[] == "url")' | less
```

## Future Formats

Planned additional output formats:

### CSV Format

```csv
text,encoding,offset,section,tags,score
"https://api.example.com",utf-8,4096,.rdata,"url",95
```

### XML Format

```xml
<strings>
  <string offset="4096" section=".rdata" encoding="utf-8" score="95">
    <text>https://api.example.com</text>
    <tags>
      <tag>url</tag>
    </tags>
  </string>
</strings>
```

### Markdown Format

```markdown
# String Analysis Report

## High Confidence (Score >= 80)

### URLs
- `https://api.example.com` (score: 95, offset: 0x1000, section: .rdata)

### GUIDs
- `{12345678-1234-1234-1234-123456789abc}` (score: 87, offset: 0x2000, section: .rdata)
```

This variety of output formats ensures Stringy can integrate into any workflow, from interactive analysis to automated security pipelines.
