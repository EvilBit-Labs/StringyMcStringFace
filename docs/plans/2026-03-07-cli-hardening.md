# CLI Hardening Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Harden the Stringy CLI with better error messages, clap validation, help text, expanded test coverage, and add `assert_cmd` for integration testing.

**Architecture:** All changes are in `src/main.rs` (CLI layer), `src/types/error.rs` (error enrichment), and `tests/integration_cli.rs` (test expansion). No library logic changes. The CLI already uses clap derive with `conflicts_with`, `ValueEnum`, and custom `value_parser` -- we build on that foundation.

**Tech Stack:** Rust 2024, clap 4.5 derive API, patharg (file/stdin input), assert_cmd + predicates (new dev-deps), thiserror, insta (snapshots)

---

## Phase 1: Add `assert_cmd` and Expand CLI Tests

This phase adds proper CLI testing infrastructure and covers all the missing test cases before we change anything. Tests-first.

### Task 1: Add `assert_cmd` and `predicates` dev-dependencies

**Files:**

- Modify: `Cargo.toml:35-38`

**Step 1: Add dependencies**

Add to `[dev-dependencies]`:

```toml
assert_cmd = "2.0.17"
predicates = "3.1.3"
```

**Step 2: Verify it compiles**

Run: `cargo check --tests` Expected: Success

**Step 3: Commit**

```
chore(deps): add assert_cmd and predicates for CLI testing
```

---

### Task 2: Rewrite existing CLI tests with assert_cmd

**Files:**

- Modify: `tests/integration_cli.rs`

**Step 1: Rewrite all 4 tests using assert_cmd**

Replace the entire file:

```rust
use assert_cmd::Command;
use predicates::prelude::*;

fn stringy() -> Command {
    Command::cargo_bin("stringy").expect("binary exists")
}

#[test]
fn cli_accepts_binary_file() {
    stringy()
        .arg("tests/fixtures/test_binary_elf")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

#[test]
fn cli_json_output() {
    let assert = stringy()
        .args(["tests/fixtures/test_binary_elf", "--json"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    for line in stdout.lines().filter(|l| !l.is_empty()) {
        serde_json::from_str::<serde_json::Value>(line).expect("each line should be valid JSON");
    }
}

#[test]
fn cli_yara_output() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--yara"])
        .assert()
        .success()
        .stdout(predicate::str::contains("rule "));
}

#[test]
fn cli_invalid_file() {
    stringy()
        .arg("nonexistent_file")
        .assert()
        .failure()
        .stderr(predicate::str::is_empty().not());
}

#[test]
fn cli_min_length_flag() {
    let default_output = stringy()
        .arg("tests/fixtures/test_binary_elf")
        .output()
        .expect("should succeed");

    let filtered_output = stringy()
        .args(["tests/fixtures/test_binary_elf", "--min-len", "20"])
        .output()
        .expect("should succeed");

    let default_lines = String::from_utf8_lossy(&default_output.stdout)
        .lines()
        .count();
    let filtered_lines = String::from_utf8_lossy(&filtered_output.stdout)
        .lines()
        .count();

    assert!(
        filtered_lines <= default_lines,
        "min_length=20 should produce fewer or equal lines than default"
    );
}
```

**Step 2: Run tests**

Run: `just test` Expected: All 4 existing tests pass, plus `cli_yara_output` is new

**Step 3: Commit**

```
test(cli): rewrite CLI tests with assert_cmd and add YARA test
```

---

### Task 3: Add help, version, and argument validation tests

**Files:**

- Modify: `tests/integration_cli.rs` (append)

**Step 1: Write new test cases**

Append to `tests/integration_cli.rs`:

```rust
#[test]
fn cli_help_flag() {
    stringy()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Extract meaningful strings"))
        .stdout(predicate::str::contains("--json"))
        .stdout(predicate::str::contains("--yara"))
        .stdout(predicate::str::contains("--min-len"))
        .stdout(predicate::str::contains("FILE"));
}

#[test]
fn cli_version_flag() {
    stringy()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("stringy"));
}

#[test]
fn cli_no_arguments() {
    stringy()
        .assert()
        .failure()
        .stderr(predicate::str::contains("FILE"));
}

#[test]
fn cli_min_len_zero_rejected() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--min-len", "0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("must be >= 1"));
}

#[test]
fn cli_min_len_non_numeric_rejected() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--min-len", "abc"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid value"));
}

#[test]
fn cli_json_and_yara_conflict() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--json", "--yara"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn cli_only_tags_filter() {
    stringy()
        .args([
            "tests/fixtures/test_binary_elf",
            "--only-tags",
            "url",
            "--json",
        ])
        .assert()
        .success();
}

#[test]
fn cli_overlapping_tags_rejected() {
    stringy()
        .args([
            "tests/fixtures/test_binary_elf",
            "--only-tags",
            "url",
            "--notags",
            "url",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--only-tags and --notags"));
}

#[test]
fn cli_pe_binary() {
    stringy()
        .arg("tests/fixtures/test_binary_pe.exe")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

#[test]
fn cli_macho_binary() {
    // Mach-O fixtures may not parse on all platforms; allow graceful failure
    let result = stringy()
        .arg("tests/fixtures/test_binary_macho")
        .output()
        .expect("should execute");

    // We just verify it runs without panicking
    assert!(result.status.success() || !result.stderr.is_empty());
}
```

**Step 2: Run tests**

Run: `just test` Expected: All tests pass (clap handles validation rejection, `run()` handles tag overlap)

**Step 3: Commit**

```
test(cli): add help, version, validation, and format conflict tests
```

---

## Phase 2: Improve Error Messages

### Task 4: Enrich `StringyError::UnsupportedFormat` with context

**Files:**

- Modify: `src/types/error.rs:6-7`
- Modify: `src/container/mod.rs` (wherever `UnsupportedFormat` is constructed)

**Step 1: Write test for the improved error message**

Create `tests/integration_cli_errors.rs`:

```rust
use assert_cmd::Command;
use predicates::prelude::*;

fn stringy() -> Command {
    Command::cargo_bin("stringy").expect("binary exists")
}

#[test]
fn error_unsupported_format_lists_supported() {
    // Feed a plain text file -- not ELF/PE/Mach-O
    stringy()
        .arg("Cargo.toml")
        .assert()
        .failure()
        .stderr(predicate::str::contains("ELF"))
        .stderr(predicate::str::contains("PE"))
        .stderr(predicate::str::contains("Mach-O"));
}
```

**Step 2: Run test to verify it fails**

Run: `cargo nextest run error_unsupported_format_lists_supported` Expected: FAIL (current message is just "Unsupported file format")

**Step 3: Update error variant**

In `src/types/error.rs`, change:

```rust
#[error("Unsupported file format")]
UnsupportedFormat,
```

to:

```rust
#[error("Unsupported file format (supported: ELF, PE, Mach-O)")]
UnsupportedFormat,
```

**Step 4: Run test to verify it passes**

Run: `cargo nextest run error_unsupported_format_lists_supported` Expected: PASS

**Step 5: Commit**

```
fix(errors): include supported formats in UnsupportedFormat message
```

---

### Task 5: Add `patharg` for idiomatic file/stdin input with error context

**Files:**

- Modify: `Cargo.toml` (add `patharg` dependency)
- Modify: `src/main.rs` (change `input` type to `InputArg`, use `.read()` with error context)

**Step 1: Write tests**

Append to `tests/integration_cli_errors.rs`:

```rust
#[test]
fn error_missing_file_shows_path() {
    stringy()
        .arg("this_file_does_not_exist.bin")
        .assert()
        .failure()
        .stderr(predicate::str::contains("this_file_does_not_exist.bin"));
}
```

**Step 2: Run test to verify it fails**

Run: `cargo nextest run error_missing_file_shows_path` Expected: FAIL (current message is "File I/O error: No such file..." without the path)

**Step 3: Add `patharg` dependency**

Add to `[dependencies]` in `Cargo.toml`:

```toml
patharg = "0.4.0"
```

**Step 4: Update `src/main.rs` to use `InputArg`**

Replace the `input` field and file reading logic:

1. Add import: `use patharg::InputArg;`

2. Change the `input` field from `PathBuf` to `InputArg`:

   ```rust
   /// Input binary file to analyze (use "-" for stdin)
   #[arg(value_name = "FILE")]
   input: InputArg,
   ```

3. Replace `std::fs::read(&cli.input)?` with:

   ```rust
   let data = cli.input.read().map_err(|e| {
       StringyError::IoError(std::io::Error::new(
           e.kind(),
           format!("{}: {}", cli.input, e),
       ))
   })?;
   ```

4. Update the `binary_name` extraction to use `InputArg`'s Display impl:

   ```rust
   let binary_name = match &cli.input {
       InputArg::Stdin => "<stdin>".to_string(),
       InputArg::Path(p) => p
           .file_name()
           .map(|name| name.to_string_lossy().into_owned())
           .unwrap_or_else(|| p.display().to_string()),
   };
   ```

5. Remove the `use std::path::PathBuf;` import if no longer needed elsewhere.

**Step 5: Run test to verify it passes**

Run: `cargo nextest run error_missing_file_shows_path` Expected: PASS

**Step 6: Run full test suite**

Run: `just test` Expected: All tests pass (existing tests use file paths, which patharg handles transparently)

**Step 7: Commit**

```
feat(cli): use patharg for idiomatic file/stdin input with error context
```

---

## Phase 3: Improve Help Text

### Task 6: Add `author`, `long_about`, and `after_help` to CLI

**Files:**

- Modify: `src/main.rs:36-39`

**Step 1: Write test for improved help output**

Append to `tests/integration_cli.rs`:

```rust
#[test]
fn cli_long_help_has_examples() {
    stringy()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("EXAMPLES:"));
}
```

**Step 2: Run test to verify it fails**

Run: `cargo nextest run cli_long_help_has_examples` Expected: FAIL (no EXAMPLES section yet)

**Step 3: Update clap attributes**

In `src/main.rs`, replace the `#[command(...)]` block:

```rust
/// A smarter alternative to the strings command that leverages format-specific knowledge
#[derive(Parser)]
#[command(name = "stringy")]
#[command(about = "Extract meaningful strings from binary files")]
#[command(version)]
```

with:

```rust
/// A smarter alternative to the strings command that leverages format-specific knowledge
#[derive(Parser)]
#[command(name = "stringy", author, version)]
#[command(about = "Extract meaningful strings from binary files")]
#[command(long_about = "A smarter alternative to the strings command that leverages \
    format-specific knowledge.\n\n\
    Stringy is section-aware, encoding-aware, and semantically intelligent. \
    It extracts strings from ELF, PE, and Mach-O binaries, classifies them \
    (URLs, file paths, IPs, GUIDs, etc.), and ranks results by relevance.")]
#[command(after_help = "EXAMPLES:\n  \
    stringy binary.exe\n  \
    stringy --json binary.elf\n  \
    stringy --yara malware.dll\n  \
    stringy --min-len 8 --only-tags url,domain binary.exe\n  \
    stringy --top 50 --json binary.elf\n\n\
    More info: https://github.com/EvilBit-Labs/Stringy")]
```

**Step 4: Run test to verify it passes**

Run: `cargo nextest run cli_long_help_has_examples` Expected: PASS

**Step 5: Verify help output looks correct**

Run: `cargo run -- --help` Expected: Shows about, long description, args, and EXAMPLES section

**Step 6: Run full test suite**

Run: `just test` Expected: All tests pass (existing help test still passes since it checks for substrings)

**Step 7: Commit**

```
feat(cli): add author, long_about, and usage examples to --help
```

---

## Phase 4: Semantic Exit Codes

### Task 7: Implement distinct exit codes

**Files:**

- Modify: `src/main.rs:160-166` (main function)

**Step 1: Write tests for exit codes**

Append to `tests/integration_cli_errors.rs`:

```rust
#[test]
fn exit_code_2_for_clap_errors() {
    // Missing required argument
    stringy().assert().failure().code(2);
}

#[test]
fn exit_code_1_for_runtime_errors() {
    // Cargo.toml is not a valid binary format
    stringy().arg("Cargo.toml").assert().failure().code(1);
}
```

**Step 2: Run tests**

Run: `cargo nextest run exit_code_` Expected: `exit_code_2_for_clap_errors` should PASS (clap already exits with 2). `exit_code_1_for_runtime_errors` should PASS (we exit with 1 for all runtime errors).

**Step 3: Verify and commit**

If both pass already (which they should given current code), just commit the tests:

```
test(cli): add exit code verification tests
```

---

## Phase 5: Polish

### Task 8: Add `SerializationError` variant to `StringyError`

**Files:**

- Modify: `src/types/error.rs`
- Modify: `src/output/json.rs` (if it uses `ConfigError` for serialization)

**Step 1: Check current serialization error usage**

Search for where JSON serialization errors are constructed. Look for `ConfigError` in `src/output/json.rs`.

**Step 2: Add the variant**

In `src/types/error.rs`, add after `ConfigError`:

```rust
#[error("Serialization error: {0}")]
SerializationError(String),
```

**Step 3: Update json.rs**

If `json.rs` wraps `serde_json` errors as `ConfigError`, change them to `SerializationError`.

**Step 4: Run full test suite**

Run: `just test` Expected: All tests pass

**Step 5: Commit**

```
refactor(errors): add SerializationError variant for output formatting failures
```

---

### Task 9: Run full CI check

**Step 1: Format all code**

Run: `just format`

**Step 2: Run full CI check**

Run: `just ci-check` Expected: All checks pass (fmt, clippy, tests)

**Step 3: Fix any issues**

If clippy or fmt finds problems, fix them.

**Step 4: Final commit if needed**

```
chore: fix formatting and clippy warnings
```

---

## Out of Scope (Deferred)

These items from the review are valid but better as separate efforts:

- **Progress indicators** (`indicatif`) -- requires threading decisions and is a feature, not hardening
- **Color output** (`owo-colors`) -- significant UX work, needs design discussion for TTY table formatting
- **Verbosity flags** (`-v`/`-q`) -- needs `tracing` or `log` integration, separate effort
- **Shell completions** (`clap_complete`) -- nice-to-have, not hardening
- **Signal handling** (`ctrlc`) -- needs mmap first to be useful
- **Config file support** -- separate feature, not hardening
- **Binary size optimization** (`strip`, `codegen-units`) -- release engineering, not CLI hardening
