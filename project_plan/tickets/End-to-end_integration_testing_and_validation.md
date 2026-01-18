# End-to-end integration testing and validation

## Objective

Create comprehensive integration tests that validate the complete pipeline with real binaries and all output formats.

## Scope

**In Scope:**
- Expand tests/fixtures/ with diverse test binaries:
  - ELF binaries with various string types
  - PE binaries with resources and imports
  - Mach-O binaries with load commands
  - Binaries with mangled symbols
- Create end-to-end integration tests:
  - Test complete pipeline with each binary format
  - Test all output formats (table, JSON, YARA)
  - Test filtering combinations
  - Test error scenarios (corrupted binaries, unsupported formats)
  - Test edge cases (no strings, all strings filtered out)
- Add insta snapshot tests for output validation
- Add CLI integration tests
- Validate against all requirements from file:.kiro/specs/stringy-binary-analyzer/requirements.md
- Add performance benchmarks for complete pipeline

**Out of Scope:**
- Unit tests for individual components (handled in component tickets)
- Implementation of components (separate tickets)

## Acceptance Criteria

- [ ] Comprehensive test fixtures for all binary formats
- [ ] End-to-end integration tests covering all user flows
- [ ] Snapshot tests for all output formats
- [ ] Error scenario tests (corrupted binaries, invalid inputs)
- [ ] Edge case tests (empty results, filter mismatches)
- [ ] Performance benchmarks for complete pipeline
- [ ] All requirements validated with tests
- [ ] All tests passing
- [ ] Zero clippy warnings

## References

- spec:f7d1261c-26d8-423a-8211-2cead3688bb0/dbfae449-b832-46a9-8fe7-748d7c5f5a20 (Core Flows - All flows)
- spec:f7d1261c-26d8-423a-8211-2cead3688bb0/04e2c976-db88-4de2-b59f-72f841ef2767 (Technical Plan - Testing Strategy)
- file:.kiro/specs/stringy-binary-analyzer/requirements.md
- file:.kiro/specs/stringy-binary-analyzer/tasks.md (Task 15)

## Dependencies

- All other tickets (this validates the complete implementation)