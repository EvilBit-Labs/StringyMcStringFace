# Security Hardening

## Description

Analyze diff for security posture, apply safe internal hardening edits, produce report.

Analyze ONLY changed files (diff scope) for security posture and apply clearly safe hardening improvements while preserving all public APIs.

## FOCUS CATEGORIES

01. Memory Safety (no unsafe code, no added unsafe, boundary adherence)
02. Input Validation & Parsing (CLI args, binary format detection, paths) – reject invalid early, no silent defaults
03. Data Handling (no secrets logged, path validation, safe binary parsing, bounds checking)
04. Binary Parsing Safety (validate offsets, check bounds, handle malformed binaries gracefully)
05. Error Handling & Logging Hygiene (no sensitive leakage, structured context, no println! for operational info)
06. Dependency & Surface Minimization (avoid unnecessary crates/features, dead code removal)
07. Defense-in-Depth Opportunities (bounds checking, resource limits, memory usage bounds)
08. Security Regression Risks (stubs flagged, TODOs categorized, unimplemented sections clearly documented)
09. Supply Chain & Build Hygiene (forbid unsafe, clippy -D warnings, deny unknown features)
10. File I/O Safety (validate file paths, handle large files safely, prevent path traversal)

## Steps

1 Diff list → 2 Security analysis per category → 3 Classify findings (`safe-edit` / `deferred` / `requires-approval`) → 4 Apply only mechanical non-breaking hardening edits (logging normalization, path validation + bound checks, converting println!/eprintln! to proper error handling, adding `#[deny(unsafe_code)]` locally if missing, adding missing error context, bounds checking for binary parsing) → 5 Run `just lint` & `just test` → 6 Revert any failing hunk → 7 Report (summary, applied, deferred, approval-needed, risk notes, roadmap) → 8 Output unified diff (no commit).

If zero safe edits: state "No safe security edits applied" and still emit full report.

## SAFE HARDENING EDIT EXAMPLES

- Replace `println!/eprintln!` with proper error handling and structured output
- Add bounds checking for binary parsing operations
- Inline guard clauses for obvious panics or unchecked unwraps (if internal)
- Validate file paths and prevent path traversal
- Remove dead code exposing potential attack surface
- Strengthen error messages (no raw system paths if sensitive)
- Add length / size / iteration bounds for unbounded growth structures
- Replace stringly-typed mode flags with private enums
- Ensure all public API doc comments mention security considerations where relevant
- Validate binary format headers before parsing
- Check section offsets and sizes before accessing binary data

## AUTO-EDIT CONSTRAINTS (STRICT)

Scope: diff-only | Gates: `just lint` + tests must pass | No commits | No public signature/visibility changes | Validate after edits

## CRITICAL REQUIREMENTS

- Preserve functional behavior while reducing risk
- No new dependencies unless strictly necessary for safety
- Avoid speculative rewrites—minimal surface change
- Avoid perf regressions; if added checks are non-trivial mark as deferred
- Do not mask existing errors—surface with context instead

## REPO RULES (REINFORCED)

Zero warnings | No unsafe | Precise typing | Trait-based parsers | thiserror for errors | CLI-first | Memory efficiency | Safe binary parsing | Path validation | rustdoc for public APIs

## EXECUTION CHECKLIST

1 Diff scan 2 Analyze security 3 Classify 4 Apply safe hardening edits 5 Gates pass 6 Report 7 Output diff | On blocker: report with remediation.

## QUICK SECURITY MATRIX

Category → Sample Safe Edit:

- Memory Safety → Remove unsafe code, add bounds checking
- Input Validation → Add numeric range check before use, validate binary format headers
- Data Handling → Validate file paths, check bounds before binary access
- Binary Parsing → Add offset/size validation, handle malformed binaries gracefully
- Error Handling → Replace raw error chain with safe error messages
- Resource Bounds → Add comment + bound to vector growth pattern, limit memory usage
- Stub Sections → Mark with `SECURITY_TODO:` prefix for tracking

Ambiguous? Defer and document.

## Completion Checklist

- [ ] Code conforms to Stringy project rules and standards
- [ ] Tests pass (`just test`)
- [ ] Linting is clean (`just lint`)
- [ ] Full CI validation passes (`just ci-check`)
- [ ] A short summary of what was done is reported
