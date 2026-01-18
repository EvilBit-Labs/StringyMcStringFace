# Implement enum-based output formatters (Table, JSON, YARA)

## Objective

Create output formatters for human-readable tables, JSONL, and YARA rules using an enum-based approach.

## Scope

**In Scope:**
- Create file:src/output/mod.rs with OutputFormat enum and format_output() function
- Create file:src/output/table.rs:
  - TTY detection using std::io::IsTerminal
  - Table formatting with columns: String | Tags | Score | Section
  - Non-TTY plain text output (one string per line)
  - Primary tag display with comma-separation for same-priority tags
- Create file:src/output/json.rs:
  - JSONL output (one JSON object per line)
  - Include all FoundString fields
  - Include original_text if present
  - Include breakdown fields only if populated
- Create file:src/output/yara.rs:
  - Complete YARA rule template generation
  - Binary filename sanitization for rule names
  - String escaping for YARA syntax
  - Skip strings over 200 chars with comment
  - Include metadata section (description, tool, date)
- Add comprehensive unit tests for each formatter
- Add integration tests with insta snapshots

**Out of Scope:**
- CLI integration (separate ticket)
- Summary statistics formatting (handled in pipeline ticket)
- Progress feedback (separate ticket)

## Acceptance Criteria

- [ ] OutputFormat enum with Table, Json, Yara variants
- [ ] format_output() function with enum-based dispatch
- [ ] Table formatter with TTY detection and proper column alignment
- [ ] JSON formatter with complete field serialization
- [ ] YARA formatter with proper escaping and rule template
- [ ] All formatters handle edge cases (empty results, very long strings, special characters)
- [ ] Comprehensive unit tests for each formatter
- [ ] Integration tests with insta snapshots
- [ ] Each file under 500 lines
- [ ] Zero clippy warnings

## References

- spec:f7d1261c-26d8-423a-8211-2cead3688bb0/24940fed-1cc7-4d17-bc4b-fb5558c6f827 (Epic Brief - Problem 4: Integration Barriers)
- spec:f7d1261c-26d8-423a-8211-2cead3688bb0/dbfae449-b832-46a9-8fe7-748d7c5f5a20 (Core Flows - Flows 4, 5, 6)
- spec:f7d1261c-26d8-423a-8211-2cead3688bb0/04e2c976-db88-4de2-b59f-72f841ef2767 (Technical Plan - Component 4)
- file:.kiro/specs/stringy-binary-analyzer/tasks.md (Task 12)

## Dependencies

- Ticket: "Extend FoundString data model" (needs all fields for serialization)
- Ticket: "Implement ranking system" (needs scores for output)