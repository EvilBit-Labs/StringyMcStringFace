# Complete semantic classification with new patterns and symbol demangling

## Objective

Extend the semantic classification system to detect all required patterns (GUIDs, emails, Base64, format strings, user agents) and integrate Rust symbol demangling.

## Scope

**In Scope:**

- Extend file:src/classification/semantic.rs with new pattern detection:
  - GUID pattern matching
  - Email address validation
  - Base64 pattern detection (marked as broad/ambiguous)
  - Printf-style format string detection
  - User agent pattern matching
- Create file:src/classification/symbols.rs for symbol demangling:
  - Integrate rustc-demangle crate
  - Detect mangled Rust symbols
  - Demangle and preserve original in original_text field
  - Tag demangled symbols appropriately
- Migrate regex caching from lazy_static to once_cell
- Add comprehensive unit tests for all new patterns
- Handle tag specificity (specific vs broad tags)
- Split file:src/classification/semantic.rs if it exceeds 500 lines

**Out of Scope:**

- Ranking/scoring logic (separate ticket)
- CLI integration (separate ticket)
- Output formatting (separate ticket)

## Acceptance Criteria

- [ ] All new semantic patterns implemented with regex matching
- [ ] Symbol demangling working for Rust symbols (rustc-demangle)
- [ ] Original mangled form preserved in original_text field
- [ ] Demangled text replaces FoundString.text
- [ ] All regex patterns migrated to once_cell
- [ ] Tag specificity documented (specific vs broad)
- [ ] Comprehensive unit tests for each pattern (positive and negative cases)
- [ ] File size under 500 lines (split into submodules if needed)
- [ ] Zero clippy warnings

## References

- spec:f7d1261c-26d8-423a-8211-2cead3688bb0/24940fed-1cc7-4d17-bc4b-fb5558c6f827 (Epic Brief - Problem 2: Cryptic Symbols)
- spec:f7d1261c-26d8-423a-8211-2cead3688bb0/04e2c976-db88-4de2-b59f-72f841ef2767 (Technical Plan - Components 2 & 3)
- file:src/classification/semantic.rs
- file:.kiro/specs/stringy-binary-analyzer/tasks.md (Tasks 9.1-9.4, 10)

## Dependencies

- Ticket: "Extend FoundString data model" (needs original_text field)
