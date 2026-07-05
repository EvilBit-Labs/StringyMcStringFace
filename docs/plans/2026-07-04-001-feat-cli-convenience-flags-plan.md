---
title: CLI Convenience Flags (--imports / --exports / --symbols) - Plan
type: feat
date: 2026-07-04
topic: cli-convenience-flags
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
product_contract_source: ce-brainstorm
execution: code
---

# CLI Convenience Flags (--imports / --exports / --symbols) - Plan

## Goal Capsule

- **Objective:** Add three convenience CLI flags that shorthand the most common reverse-engineering tag filters, so users don't need to know exact `Tag` spellings.
- **Product authority:** Issue [#208](https://github.com/EvilBit-Labs/Stringy/issues/208) (follow-up to #40 Feature 3); scope confirmed via brainstorm.
- **Execution profile:** CLI-only change in `src/main.rs`, test-first per the repo TDD policy. No pipeline, extraction, classification, or `Tag` enum changes.
- **Open blockers:** None. Design decisions resolved.

---

## Product Contract

### Summary

Add `--imports`, `--exports`, and `--symbols` as boolean shorthands for `--only-tags import` / `export` / `demangled`. The set is deliberately closed and reverse-engineering-focused; each flag's help text points to `--only-tags` for the full tag vocabulary.

### Problem Frame

Imports, exports, and demangled symbols are already extracted, tagged, classified, and ranked. They are filterable today only through `--only-tags <TAG>`, which forces the user to know the canonical tag spelling. The mismatch bites hardest for symbols: the tag is `demangled`, but analysts reach for the word "symbols." These three queries ("what does this binary import / export / expose") are the highest-frequency RE tasks, so the vocabulary friction lands on the most-used paths.

### Key Decisions

- **Closed, RE-focused set of three.** These three earn flags because their tag names don't match user vocabulary and they are the top-frequency RE queries -- not because "tags deserve flags." The other ~22 tags (`url`, `ipv4`, `crypto`, `network`, ...) stay on `--only-tags`, which already reads self-evidently. This avoids `--help` bloat and per-tag conflict-matrix churn.
- **`--symbols` maps to `DemangledSymbol` only.** Keeping it distinct from `--imports`/`--exports` makes all three orthogonal, so `--imports --exports --symbols` yields a clean union rather than overlapping sets.
- **Conflict with `--only-tags` and `--raw`; compatible with `--no-tags`.** Both convenience flags and `--only-tags` populate the include set, so mixing them is ambiguous and forbidden at parse time. `--raw` skips classification and clears tags, so any tag filter is meaningless there. `--no-tags` (exclusion) composes cleanly, reusing the existing include/exclude overlap check.
- **Help-text pointer signals the closed-set intent.** Each flag notes it is a shorthand for a common analysis tag and points to `--only-tags`, so the absence of `--urls`/`--crypto` reads as deliberate rather than an oversight.

### Requirements

**Behavior**

- R1. `--imports`, `--exports`, and `--symbols` are boolean flags that filter output to strings tagged `Import`, `Export`, and `DemangledSymbol` respectively -- behaviorally equivalent to the corresponding `--only-tags` value.
- R2. `--symbols` maps to `DemangledSymbol` only; it does not also include `Import` or `Export`.
- R3. The three flags combine with each other as OR (union), matching repeated `--only-tags`.

**Conflicts and composition**

- R4. The three flags conflict with `--only-tags` and with `--raw`, enforced by clap at parse time.
- R5. The three flags are compatible with `--no-tags`; the existing runtime overlap validation applies to the resolved include set, so a contradiction such as `--imports --no-tags import` still errors.

**Surface**

- R6. Each flag's help text identifies it as a shorthand for a common analysis tag and points to `--only-tags` for the full tag set.
- R7. Flags are long-only, with no short aliases -- consistent with `--enc`/`--yara`/`--raw`.

### Acceptance Examples

- AE1. **Covers R3.** Given a binary, when the user runs `--imports --exports`, then output includes both import- and export-tagged strings (union), exit success.
- AE2. **Covers R4.** When the user runs `--imports --only-tags url`, then clap rejects with a conflict error (non-zero exit).
- AE3. **Covers R4.** When the user runs `--symbols --raw`, then clap rejects with a conflict error.
- AE4. **Covers R5.** When the user runs `--imports --no-tags import`, then the run fails the overlap validation with a clear message.
- AE5. **Covers R5.** When the user runs `--imports --no-tags version`, then the run succeeds (no contradiction).

### Scope Boundaries

- Convenience flags for any other tag (`url`, `ipv4`, `crypto`, `network`, `guid`, ...) -- out; use `--only-tags`.
- Short aliases for the new flags -- out (R7).
- A tag-alias mechanism that makes `--only-tags symbols` resolve to `demangled` -- out; the decision is top-level flags, not alias resolution.
- Changes to extraction, classification, ranking, or the `Tag` enum -- out; this is CLI-only ergonomics.

---

## Planning Contract

**Product Contract preservation:** Product Contract unchanged. This enrichment adds the Planning Contract, Implementation Units, Verification Contract, and Definition of Done only; all R/AE IDs and product-scope text are preserved verbatim.

### Key Technical Decisions

- KTD1. **Resolve the include set through a single `Cli::resolved_include_tags()` helper.** The helper returns `only_tags` plus any convenience flags mapped to their `Tag` variant. `run()` computes it once and reuses it for both the overlap check and the filter build, so there is one authoritative include set. Keeping the mapping in the helper (rather than inline branches in `run()`) holds the added lines in `run()` to a single call plus reuse -- `run()` is already ~87 lines, so avoid inflating it further. Convenience flags conflict with `--only-tags` at parse time, so in practice only one source populates the set, but merging is harmless and future-proof. Follows the existing `From<CliEncoding>`-style mapping and `FilterConfig` builder conventions in `src/main.rs`.
- KTD2. **Push all mutual exclusion into clap `conflicts_with_all`.** Each new field carries `conflicts_with_all = ["only_tags", "raw"]`, mirroring the existing `--raw` field. clap conflicts are symmetric, so `--raw` automatically conflicts with the three new flags; adding the three names to `--raw`'s existing `conflicts_with_all` list is optional readability polish, not a correctness requirement. Keep the include-vs-exclude (`--no-tags`) check in `run()` as runtime validation, since clap cannot express "same tag on both sides."
- KTD3. **Generalize the overlap error message so it is accurate for both include sources.** The current message names "`--only-tags` and `--no-tags`", which would be misleading for an `--imports --no-tags import` contradiction. Reword it to describe an include/exclude contradiction without hard-coding `--only-tags` (e.g., name the conflicting tag and that it is both included and excluded via `--no-tags`). This is a deliberate, in-scope co-change: the existing `cli_overlapping_tags_rejected` test asserts the old substring and must be updated to a stable substring that holds for both paths.

### Assumptions

- A fixture with import-tagged strings exists for the behavioral-equivalence test (`tests/fixtures/test_binary_pe.exe` is the expected source). If the chosen fixture yields zero import-tagged strings, the equivalence assertion still holds (both sides empty) but proves less; U1 notes selecting a fixture with known imports and treating an empty-both result as a weak pass.
- Clap conflict errors exit with code 2 (consistent with `cli_json_and_yara_conflict`), so conflict tests may assert `.code(2)`.

### Sequencing

U1 (tests, RED) is authored first, then U2 (implementation, GREEN) makes them pass, then U3 (docs) closes the AGENTS.md co-change. U3 depends only on the final flag surface from U2.

---

## Implementation Units

### U1. Integration tests for the three convenience flags

- **Goal:** Add the failing integration tests that pin down flag behavior, conflicts, composition, help surface, and behavioral equivalence before any implementation exists.
- **Requirements:** R1, R2, R3, R4, R5, R6.
- **Dependencies:** none.
- **Files:** `tests/integration_cli.rs`
- **Approach:** Mirror the existing `assert_cmd` patterns (`cli_only_tags_filter`, `cli_json_and_yara_conflict`, `cli_raw_conflicts_with_yara`, `cli_overlapping_tags_rejected`, `cli_help_lists_all_canonical_tags`). Tests invoke the built binary and do not reference internal symbols, so they compile before U2 lands and fail at runtime until it does. Update `cli_overlapping_tags_rejected` to assert a stable substring compatible with the generalized message from KTD3 (assert on the tag name plus an include/exclude phrase, not the literal "`--only-tags and --no-tags`").
- **Execution note:** Author this unit first (RED). Run it and confirm each new test fails for the right reason (unknown flag / missing behavior) before starting U2.
- **Patterns to follow:** `tests/integration_cli.rs` existing conflict and success tests; use `tests/fixtures/test_binary_elf` for success/conflict cases and `tests/fixtures/test_binary_pe.exe` for import-bearing equivalence.
- **Test scenarios:**
  - `--imports` on an ELF fixture exits success (happy path).
  - `--exports` on an ELF fixture exits success (happy path).
  - `--symbols` on an ELF fixture exits success (happy path).
  - Covers AE1 / R3. `--imports --exports --json` exits success and every emitted JSON row carries `Import` or `Export` (union), asserting no row lacks both -- and that the combined line count is greater than or equal to `--imports` alone (OR, not AND).
  - Covers AE2 / R4. `--imports --only-tags url` fails at parse time with exit code 2 and stderr containing "cannot be used with".
  - Covers AE3 / R4. `--symbols --raw` fails at parse time with exit code 2 and stderr containing "cannot be used with".
  - Covers AE4 / R5. `--imports --no-tags import` fails the runtime overlap check with a clear message naming the `import` tag.
  - Covers AE5 / R5. `--imports --no-tags version` exits success.
  - Covers R2. `--symbols --json` output rows all carry the `demangled` tag and none is emitted solely for an `Import`/`Export` tag (symbols maps to `DemangledSymbol` only).
  - Covers R6. `--help` output lists `--imports`, `--exports`, and `--symbols` and each references `--only-tags`.
  - Behavioral equivalence (the confirmed call-out): on `tests/fixtures/test_binary_pe.exe`, `--imports --json` output equals `--only-tags import --json` output. Select a fixture with known imports; treat an empty-both result as a weak pass and note it.
  - Update: `cli_overlapping_tags_rejected` still fails `--only-tags url --no-tags url` but now asserts the generalized-message substring.
- **Verification:** `cargo nextest run --test integration_cli` shows the new tests present and failing (before U2), then passing (after U2). `assert_cmd` runs non-TTY -- do not assert TTY table formatting here.

### U2. Implement the flags and include-tag resolution in `src/main.rs`

- **Goal:** Add the three boolean clap fields, the `resolved_include_tags()` helper, and rewire `run()` so U1 passes.
- **Requirements:** R1, R2, R3, R4, R5, R6, R7.
- **Dependencies:** U1.
- **Files:** `src/main.rs`
- **Approach:**
  - Add three `bool` fields to `struct Cli`, each `#[arg(long, conflicts_with_all = ["only_tags", "raw"])]`, with doc comments that name the shorthand and point to `--only-tags` (satisfies R6; long-only satisfies R7). Optionally add `"imports"`, `"exports"`, `"symbols"` to the `--raw` field's existing `conflicts_with_all` for help readability (symmetric, not required for correctness).
  - Add `Cli::resolved_include_tags(&self) -> Vec<Tag>`: clone `only_tags`, then push `Tag::Import` / `Tag::Export` / `Tag::DemangledSymbol` for each set flag (KTD1). `--symbols` pushes only `DemangledSymbol` (R2). Multiple flags append, giving OR/union (R3).
  - In `run()`: compute the include set once (`let include_tags = cli.resolved_include_tags();`) near the top. Replace the overlap-check source (currently `cli.only_tags.iter()`, main.rs:155-159) with `include_tags`, and generalize the error message per KTD3. Replace the filter-build guard (currently `if !cli.only_tags.is_empty()`, main.rs:208-210) with the resolved set.
- **Execution note:** Implement to turn U1 green (GREEN). `run()` is already ~87 lines, so keep the added footprint to the single `resolved_include_tags()` call plus its reuse; do not inline per-flag branches into `run()`. If the include-resolution or validation grows, lift it into a helper rather than growing `run()`.
- **Patterns to follow:** existing `--only-tags`/`--no-tags`/`--raw` clap attributes and the `FilterConfig` builder chain in `run()`; `From<CliEncoding> for EncodingFilter` as the mapping-style precedent.
- **Test scenarios:** none new -- U1 is the authoritative behavioral spec for this unit. (Any pure-refactor helper extraction is covered transitively by U1.)
- **Verification:** `just check` (fmt + clippy `-D warnings` + nextest) is clean; all U1 tests pass; no new clippy warnings; `#![forbid(unsafe_code)]` preserved.

### U3. Update the AGENTS.md CLI-flag table

- **Goal:** Keep the documented flag surface in sync with the implemented flags (repo co-change policy).
- **Requirements:** supports R6 discoverability; satisfies the AGENTS.md flag-table item in the Definition of Done.
- **Dependencies:** U2.
- **Files:** `AGENTS.md`
- **Approach:** Add `--imports`, `--exports`, `--symbols` rows to the "Current CLI Flags (main.rs)" table: long-only, `bool`, note each is a shorthand for the corresponding `--only-tags` value and conflicts with `--only-tags`/`--raw`, compatible with `--no-tags`. Match the existing table's column shape and tone. Also update the existing `--no-tags` row -- its note currently says the runtime overlap check is "with `--only-tags`", which KTD3 generalizes; reword it to say the overlap check applies to the resolved include set (`--only-tags` plus the convenience flags).
- **Test expectation:** none -- documentation-only change with no behavioral surface.
- **Verification:** table renders correctly and the three rows accurately describe the shipped flags; `just format` leaves the Markdown clean.

---

## Verification Contract

| Gate                     | Command                                          | Applies to | Done signal                                               |
| ------------------------ | ------------------------------------------------ | ---------- | --------------------------------------------------------- |
| Unit + integration tests | `cargo nextest run` (via `just test`)            | U1, U2     | All tests pass, including the new `integration_cli` cases |
| Format                   | `cargo fmt --check` (via `just check`)           | U2, U3     | No diff                                                   |
| Lint                     | `cargo clippy -- -D warnings` (via `just check`) | U2         | Zero warnings                                             |
| Full pre-commit          | `just check`                                     | U1-U3      | Exit 0                                                    |
| Full CI locally          | `just ci-check`                                  | U1-U3      | Exit 0 (final gate before declaring done)                 |

Behavioral equivalence gate: `--imports` output equals `--only-tags import` output on a PE fixture with known imports (asserted in U1).

---

## Definition of Done

- [ ] `--imports`, `--exports`, `--symbols` implemented as long-only clap `bool` flags (R1, R7).
- [ ] `--symbols` maps to `DemangledSymbol` only; `--imports --exports --symbols` yields the union (R2, R3).
- [ ] Conflicts with `--only-tags` and `--raw` enforced by clap at parse time (R4).
- [ ] Compatible with `--no-tags`; the resolved include set drives the runtime overlap check so `--imports --no-tags import` errors and `--imports --no-tags version` succeeds (R5).
- [ ] Each flag's help text points to `--only-tags` (R6).
- [ ] `tests/integration_cli.rs` covers success, each conflict, combine-together, `--no-tags` contradiction, `--help` listing, and behavioral equivalence; `cli_overlapping_tags_rejected` updated for the generalized message.
- [ ] `AGENTS.md` "Current CLI Flags" table gains the three rows, and the existing `--no-tags` row reflects the generalized (resolved-include-set) overlap check.
- [ ] `just ci-check` passes.

---

## Sources / Research

- `src/main.rs` -- `Cli` struct (fields at lines 89-151); existing `--only-tags`/`--no-tags`/`--raw` clap patterns; `run()` overlap check (lines 155-167) and filter build (lines 208-213) are the two rewire points; `From<CliEncoding>` mapping precedent.
- `src/types/mod.rs` -- `Tag::Import`, `Tag::Export`, `Tag::DemangledSymbol` variants and `Tag::from_str`.
- `tests/integration_cli.rs` -- `cli_only_tags_filter`, `cli_json_and_yara_conflict`, `cli_raw_conflicts_with_yara`, `cli_overlapping_tags_rejected`, `cli_help_lists_all_canonical_tags` are the patterns to mirror.
- `AGENTS.md` -- "Current CLI Flags" table and the GOTCHAS note that CLI flag changes must co-change tests and the table.
- `GOTCHAS.md` (CLI section) -- clap conflict exit codes are 2 for config/validation; `--raw` early-exit semantics; help-text/`from_str` sync test.
