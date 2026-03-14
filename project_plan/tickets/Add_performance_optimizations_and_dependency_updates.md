# Add performance optimizations and dependency updates

## Objective

Integrate performance optimizations including memory mapping via mmap-guard, regex caching migration, and progress feedback library.

## Scope

**In Scope:**

- Add dependencies to Cargo.toml:
  - mmap-guard for safe memory-mapped file I/O (wraps memmap2 with advisory locking and empty-file handling)
  - once_cell for modern lazy initialization
  - indicatif for progress bars
  - rustc-demangle for symbol demangling
- Implement memory mapping via mmap-guard in Pipeline:
  - Use `mmap_guard::map_file()` for zero-copy read-only access
  - Empty files short-circuit to empty buffer (InvalidInput branch)
  - Other I/O errors wrapped in StringyError::IoError with file path context
- Migrate all lazy_static usage to once_cell::sync::Lazy
- Integrate indicatif progress indicators in Pipeline
- Add benchmarks for performance validation
- Update documentation with performance characteristics

**Out of Scope:**

- Pipeline implementation (separate ticket, but this ticket provides the tools)
- Classification implementation (separate ticket, but this ticket provides regex caching)

## Acceptance Criteria

- [ ] All dependencies added to Cargo.toml with appropriate versions (mmap-guard, once_cell, indicatif, rustc-demangle)
- [ ] Memory mapping via mmap-guard implemented and tested (happy path mmap, empty file -> empty Vec, other IO -> StringyError::IoError)
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
