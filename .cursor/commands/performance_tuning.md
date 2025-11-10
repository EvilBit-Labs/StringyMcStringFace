# Performance Tuning

## Description

Analyze diff for performance, apply safe micro-optimizations, produce report.

## FOCUS CATEGORIES

Analyze ONLY changed files (diff scope) for runtime performance characteristics while preserving correctness, public APIs, and security constraints. Apply only clearly safe micro-optimizations.

01. Algorithmic Complexity (unnecessary O(n^2), repeated scans, avoidable clones)
02. Allocation Behavior (temporary allocations, Vec growth patterns, reserve vs push, string churn)
03. Binary Parsing Efficiency (zero-copy operations, memory-mapped files for large binaries, efficient section iteration)
04. I/O Efficiency (redundant reads, memory-mapped I/O for large files, efficient file handling)
05. Data Structures (better fit: map vs vec scan, small vec, newtype for clarity/perf)
06. Caching & Reuse (recomputing constants, repeated serialization, repeated formatting)
07. Hot Path Error Handling (avoidable string formatting, cheap early exits)
08. String Extraction (efficient UTF-8/UTF-16 parsing, slice-based operations, avoid unnecessary allocations)
09. Memory Footprint (unbounded growth, retain vs shrink_to_fit decisions, large temporary clones, memory-mapped files)
10. Instrumentation (where benchmarks would help future perf investigations)

## Steps

1 Diff list → 2 Perf analysis per category → 3 Classify (`safe-edit` / `deferred` / `requires-approval`) → 4 Apply only mechanical, behavior-preserving micro-optimizations (e.g., remove redundant clone, pre-allocate capacity, use zero-copy parsing, optimize string extraction) → 5 Run `just lint` & `just test` → 6 Revert failing hunk if gates fail → 7 Report (summary, applied, deferred, approval-needed, perf notes, next steps) → 8 Output unified diff (no commit).

If zero safe edits: state "No safe performance edits applied" and still produce full report.

## SAFE PERFORMANCE EDIT EXAMPLES

- Replace `clone()` with reference when ownership not required
- Preallocate Vec with `with_capacity` when length is known
- Convert repeated `format!` in loop to pre-built prefix + push_str
- Hoist constant regex / hashers / serializers
- Short-circuit early on empty input slices
- Use iterators instead of temporary Vec collects where semantic match
- Use slice-based string extraction to avoid allocations
- Use memory-mapped files for large binary processing
- Prefer zero-copy parsing with goblin
- Avoid converting to String just to log when `Display` exists

## AUTO-EDIT CONSTRAINTS (STRICT)

Scope: diff-only | Gates: `just lint` + tests must pass | No commits | No public signature/visibility changes | Validate after edits | No semantic changes

## CRITICAL REQUIREMENTS

- Do not trade readability or security for micro perf
- Never introduce unsafe
- Provide benchmarks only as recommendations (do not add heavy harness automatically)
- Defer structural refactors (module splits) unless trivial & internal
- Avoid premature caching introducing invalidation complexity

## REPO RULES (REINFORCED)

Zero warnings | No unsafe | Precise typing | Trait-based parsers | thiserror for errors | CLI-first | Memory efficiency | Zero-copy parsing | rustdoc for public APIs

## EXECUTION CHECKLIST

1 Diff scan 2 Analyze perf 3 Classify 4 Apply safe micro-optimizations 5 Gates pass 6 Report 7 Output diff | On blocker: report & remediate guidance.

## QUICK PERFORMANCE MATRIX

Category → Sample Safe Edit:

- Complexity → Replace nested loop with `HashSet` membership check
- Allocation → Pre-size Vec for known iteration length
- Binary Parsing → Use memory-mapped files for large binaries, zero-copy section access
- I/O → Use memory-mapped I/O for large file processing
- Data Structure → Use `SmallVec` for typical \<=8 elements (internal)
- Caching → Hoist constant serialization of static JSON template
- String Extraction → Use slice-based operations, avoid unnecessary String allocations
- Memory Footprint → Replace accumulating Vec with sliding window bound, use memory-mapped files
- Instrumentation → Add benchmark tests for hot path performance

Ambiguous? Defer and document.

## Completion Checklist

- [ ] Code conforms to Stringy project rules and standards
- [ ] Tests pass (`just test`)
- [ ] Linting is clean (`just lint`)
- [ ] Full CI validation passes (`just ci-check`)
- [ ] A short summary of what was done is reported
