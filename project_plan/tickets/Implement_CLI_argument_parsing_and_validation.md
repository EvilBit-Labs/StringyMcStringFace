# Implement CLI argument parsing and validation

## Objective

Complete the CLI interface with all filtering flags, output format selection, and proper validation.

## Scope

**In Scope:**
- Extend Cli struct in file:src/main.rs with all flags:
  - --min-len N
  - --enc ENCODING (accept: ascii, utf8, utf16, utf16le, utf16be)
  - --only-tags TAGS (comma-separated)
  - --notags TAGS (comma-separated)
  - --top N
  - --json
  - --yara
  - --summary
  - --debug
- Implement flag validation:
  - Validate encoding values
  - Validate tag names (show suggestions for invalid tags)
  - Detect conflicting output format flags (--json + --yara)
- Build FilterConfig from CLI arguments
- Update --help text to include available tags
- Add CLI argument parsing tests
- Wire CLI to Pipeline

**Out of Scope:**
- Pipeline implementation (separate ticket)
- Filter execution logic (handled in Pipeline)
- Output formatting (separate ticket)

## Acceptance Criteria

- [ ] All CLI flags implemented using clap derive macros
- [ ] Flag validation with helpful error messages
- [ ] Conflicting output format detection (exit with error)
- [ ] Invalid tag names show suggestions
- [ ] --help includes complete list of available tags
- [ ] FilterConfig correctly built from CLI arguments
- [ ] CLI tests covering valid and invalid argument combinations
- [ ] Zero clippy warnings

## References

- spec:f7d1261c-26d8-423a-8211-2cead3688bb0/dbfae449-b832-46a9-8fe7-748d7c5f5a20 (Core Flows - CLI Flag Reference, Flow 8: Error Handling)
- spec:f7d1261c-26d8-423a-8211-2cead3688bb0/04e2c976-db88-4de2-b59f-72f841ef2767 (Technical Plan - Component 5)
- file:.kiro/specs/stringy-binary-analyzer/tasks.md (Task 13)

## Dependencies

- Ticket: "Extend FoundString data model" (needs to know about new fields)