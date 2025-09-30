# Requirements Document

## Introduction

Stringy is a smarter alternative to the standard `strings` command that leverages format-specific knowledge to distinguish meaningful strings from random garbage data. The core innovation is understanding enough about each file format to know what constitutes a legitimate string versus noise, padding, or binary data that happens to contain printable characters. Initially focused on executable binaries (ELF, PE, Mach-O), the tool is designed to be extensible to support additional structured file formats through feature gates, always applying the same principle: format awareness enables intelligent string detection.

## Requirements

### Requirement 1

**User Story:** As a security researcher, I want to extract only legitimate strings by leveraging format-specific knowledge, so that I can distinguish meaningful data from random garbage, padding, and binary noise.

#### Acceptance Criteria

1. WHEN a user provides an ELF binary THEN the system SHALL use format knowledge to identify string-containing sections (.rodata, .data.rel.ro, .comment) and ignore code sections, padding, and binary tables
2. WHEN a user provides a PE binary THEN the system SHALL use format knowledge to extract strings from appropriate sections (.rdata, .data) and resources (VERSIONINFO, STRINGTABLE) while ignoring executable code and binary structures
3. WHEN a user provides a Mach-O binary THEN the system SHALL use format knowledge to target string sections (\_\_TEXT,\_\_cstring, \_\_TEXT,\_\_const, \_\_DATA_CONST) and avoid load commands, code segments, and binary metadata
4. WHEN the system encounters printable characters in non-string sections THEN it SHALL apply format-specific heuristics to determine if they represent legitimate strings or coincidental binary data
5. WHEN the system encounters an unsupported file format THEN it SHALL return an error message indicating the format is not supported
6. WHEN future file format support is added THEN the system SHALL use feature gates to enable/disable specific format parsers

### Requirement 2

**User Story:** As a malware analyst, I want to extract strings in multiple encodings including UTF-16, so that I can analyze Windows executables that contain wide character strings.

#### Acceptance Criteria

1. WHEN extracting strings THEN the system SHALL support ASCII/UTF-8 encoding with configurable minimum length (default 4 characters)
2. WHEN extracting strings THEN the system SHALL support UTF-16LE encoding with configurable minimum length (default 3 characters)
3. WHEN extracting strings THEN the system SHALL support UTF-16BE encoding detection
4. WHEN a string contains null-interleaved text THEN the system SHALL properly detect and extract the string
5. WHEN duplicate strings are found THEN the system SHALL deduplicate while preserving offset, section, and size information

### Requirement 3

**User Story:** As a reverse engineer, I want strings to be semantically tagged and categorized, so that I can quickly identify URLs, file paths, registry keys, and other meaningful data.

#### Acceptance Criteria

01. WHEN a string matches a URL pattern THEN the system SHALL tag it as "url"
02. WHEN a string matches a domain pattern THEN the system SHALL tag it as "domain"
03. WHEN a string matches an IPv4 or IPv6 pattern THEN the system SHALL tag it as "ipv4" or "ipv6"
04. WHEN a string matches a file path pattern (POSIX or Windows) THEN the system SHALL tag it as "filepath"
05. WHEN a string matches a Windows registry path pattern THEN the system SHALL tag it as "regpath"
06. WHEN a string matches a GUID pattern THEN the system SHALL tag it as "guid"
07. WHEN a string matches an email pattern THEN the system SHALL tag it as "email"
08. WHEN a string matches a Base64 pattern THEN the system SHALL tag it as "b64"
09. WHEN a string matches a printf-style format string THEN the system SHALL tag it as "fmt"
10. WHEN a string matches a user agent pattern THEN the system SHALL tag it as "user-agent-ish"

### Requirement 4

**User Story:** As a developer, I want Rust symbols to be demangled and import/export names to be identified, so that I can understand the binary's functionality and dependencies.

#### Acceptance Criteria

1. WHEN the system encounters mangled Rust symbols THEN it SHALL demangle them using rustc-demangle
2. WHEN the system processes import names THEN it SHALL tag them as "Import" and boost their ranking score
3. WHEN the system processes export names THEN it SHALL tag them as "Export" and boost their ranking score
4. WHEN the system encounters section names THEN it SHALL include them in the analysis with appropriate tagging

### Requirement 5

**User Story:** As a security analyst, I want strings to be ranked by relevance and importance, so that I can focus on the most meaningful data first.

#### Acceptance Criteria

1. WHEN calculating string scores THEN the system SHALL apply section weights where .rodata/.rdata/\_\_cstring sections receive higher scores than .data sections
2. WHEN calculating string scores THEN the system SHALL apply semantic boosts where URLs, GUIDs, registry paths, file paths, and format strings receive +2 to +5 point bonuses
3. WHEN calculating string scores THEN the system SHALL apply noise penalties for high entropy strings, excessively long strings, repeated padding bytes, and obvious table data
4. WHEN calculating string scores THEN the system SHALL boost import/export names in the final ranking
5. WHEN presenting results THEN the system SHALL sort strings by score in descending order

### Requirement 6

**User Story:** As a researcher, I want multiple output formats including JSON and human-readable tables, so that I can integrate the tool into automated workflows and also review results manually.

#### Acceptance Criteria

1. WHEN the user requests JSONL output THEN the system SHALL provide one record per string with fields: text, offset, rva, section, encoding, tags, score, source
2. WHEN the user requests human-readable output THEN the system SHALL display results in a sorted table format
3. WHEN the user requests YARA-friendly output THEN the system SHALL format strings with proper escaping and truncation rules suitable for YARA rule creation
4. WHEN outputting results THEN the system SHALL include provenance information (offset, section, RVA when available)

### Requirement 7

**User Story:** As a command-line user, I want flexible filtering and configuration options, so that I can customize the analysis for different use cases.

#### Acceptance Criteria

1. WHEN the user specifies --min-len parameter THEN the system SHALL only extract strings meeting the minimum length requirement
2. WHEN the user specifies --enc parameter THEN the system SHALL only extract strings in the specified encodings (ascii, utf16, etc.)
3. WHEN the user specifies --only-tags parameter THEN the system SHALL filter results to only include strings with specified tags
4. WHEN the user specifies --notags parameter THEN the system SHALL exclude strings with specified tags
5. WHEN the user specifies --top parameter THEN the system SHALL limit output to the specified number of highest-scoring strings
6. WHEN the user specifies --json parameter THEN the system SHALL output results in JSONL format
7. WHEN no output format is specified THEN the system SHALL default to human-readable table format

### Requirement 8

**User Story:** As a performance-conscious user, I want the tool to handle large binaries efficiently, so that I can analyze files without excessive memory usage or processing time.

#### Acceptance Criteria

1. WHEN processing large binary files THEN the system SHALL use memory mapping for efficient file access
2. WHEN optional features like DWARF parsing are available THEN the system SHALL use lazy evaluation to avoid unnecessary processing
3. WHEN compiling regular expressions for tagging THEN the system SHALL cache compiled patterns for reuse
4. WHEN processing binaries THEN the system SHALL complete analysis within reasonable time bounds for files up to 100MB

### Requirement 9

**User Story:** As a developer, I want the tool to be extensible to support additional file formats beyond executables, so that I can analyze various structured data formats as new features are added.

#### Acceptance Criteria

1. WHEN the system is designed THEN it SHALL use a modular architecture that allows adding new file format parsers
2. WHEN new file format support is added THEN it SHALL be controlled by feature flags to keep the core binary lightweight
3. WHEN a compressed archive parser is added THEN it SHALL extract table of contents and embedded file metadata
4. WHEN a database parser is added THEN it SHALL extract schema information and metadata strings
5. WHEN adding new format support THEN the system SHALL maintain consistent string extraction, tagging, and ranking interfaces
6. WHEN feature gates are disabled THEN the system SHALL not include the corresponding parser code in the binary
