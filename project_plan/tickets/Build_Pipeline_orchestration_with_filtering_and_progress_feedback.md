# Build Pipeline orchestration with filtering and progress feedback

## Objective

Create the Pipeline struct that orchestrates the entire analysis workflow, including filtering, error recovery, and progress feedback.

## Scope

**In Scope:**

- Create Pipeline struct in file:src/main.rs with PipelineConfig
- Implement 14-step workflow:
  01. Progress indicator setup (indicatif)
  02. Memory-mapped file reading via mmap-guard
  03. Format detection and container parsing (fail fast)
  04. String extraction (fail fast on critical errors)
  05. Semantic classification (graceful degradation)
  06. Symbol demangling (graceful degradation)
  07. Ranking with optional debug breakdown
  08. Filtering (min-len, encoding, tags)
  09. Sorting and top-N limiting
  10. Output formatting
- Implement FilterConfig struct for CLI filter parameters
- Implement stage-specific error recovery:
  - Critical stages: fail fast with clear errors
  - Optional stages: graceful degradation with warnings
- Integrate indicatif for progress feedback (Parsing... Extracting... Classifying... Ranking...)
- Add memory mapping via mmap-guard
- Add comprehensive integration tests
- Keep main.rs under 500 lines

**Out of Scope:**

- CLI argument parsing (handled in same file but separate concern)
- Individual component implementations (separate tickets)
- Output formatter implementations (separate ticket)

## Acceptance Criteria

- [ ] Pipeline struct with new() and run() methods
- [ ] PipelineConfig with all necessary configuration
- [ ] FilterConfig for CLI filter parameters
- [ ] 14-step workflow implemented with proper error handling
- [ ] Stage-specific error recovery (fail fast vs graceful degradation)
- [ ] `mmap-guard` used; empty files return empty buffer; I/O errors propagate as `StringyError::IoError`
- [ ] Progress feedback using indicatif (messages to stderr)
- [ ] Filtering logic using iterator adapters
- [ ] Integration tests covering success and failure scenarios
- [ ] main.rs under 500 lines
- [ ] Zero clippy warnings

## References

- spec:f7d1261c-26d8-423a-8211-2cead3688bb0/dbfae449-b832-46a9-8fe7-748d7c5f5a20 (Core Flows - All flows)
- spec:f7d1261c-26d8-423a-8211-2cead3688bb0/04e2c976-db88-4de2-b59f-72f841ef2767 (Technical Plan - Component 5)
- file:.kiro/specs/stringy-binary-analyzer/tasks.md (Task 16)

## Dependencies

- Ticket: "Complete semantic classification" (needs classification logic)
- Ticket: "Implement ranking system" (needs RankingEngine)
- Ticket: "Implement output formatters" (needs formatters)
