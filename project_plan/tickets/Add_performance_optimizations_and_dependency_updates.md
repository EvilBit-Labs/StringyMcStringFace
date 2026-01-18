# Add performance optimizations and dependency updates

## Objective

Integrate performance optimizations including memory mapping with fallback, regex caching migration, and progress feedback library.

## Scope

**In Scope:**

- Add dependencies to Cargo.toml:
  - memmap2 for memory-mapped file I/O
  - once_cell for modern lazy initialization
  - indicatif for progress bars
  - rustc-demangle for symbol demangling
- Implement memory mapping with fallback in Pipeline:
  - Attempt memmap2::Mmap first
  - Fall back to std::fs::read() on failure
  - Log fallback for user awareness
- Migrate all lazy_static usage to once_cell::sync::Lazy
- Integrate indicatif progress indicators in Pipeline
- Add benchmarks for performance validation
- Update documentation with performance characteristics

**Out of Scope:**

- Pipeline implementation (separate ticket, but this ticket provides the tools)
- Classification implementation (separate ticket, but this ticket provides regex caching)

## Acceptance Criteria

- [ ] All dependencies added to Cargo.toml with appropriate versions
- [ ] Memory mapping with fallback implemented and tested
- [ ] All lazy_static migrated to once_cell
- [ ] indicatif integrated for progress feedback
- [ ] Benchmarks added for memory mapping and regex performance
- [ ] Documentation updated with performance notes
- [ ] Zero clippy warnings
- [ ] All tests passing

## References

- spec:f7d1261c-26d8-423a-8211-2cead3688bb0/04e2c976-db88-4de2-b59f-72f841ef2767 (Technical Plan - Performance Optimizations section)
- file:.kiro/specs/stringy-binary-analyzer/tasks.md (Task 14)
- file:Cargo.toml

## Dependencies

None - this ticket provides infrastructure for other tickets but can be implemented independently.
