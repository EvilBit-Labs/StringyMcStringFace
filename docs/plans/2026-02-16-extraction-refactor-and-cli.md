# Extraction Module Refactor & CLI Wire-Up Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Split all extraction module files exceeding 500 lines into focused submodules, then wire up the CLI to use the full extraction pipeline.

**Architecture:** Each oversized file becomes a module directory (`foo.rs` -> `foo/mod.rs` + submodules). Tests are extracted to separate files. The public API (lib.rs re-exports) remains unchanged -- this is a purely internal refactor for Phase 1-2. Phase 3 extends main.rs to use the library's public API for the full binary -> output pipeline.

**Tech Stack:** Rust 2024 edition, clap (CLI), goblin/pelite (binary parsing), thiserror (errors), insta (snapshot tests), cargo-nextest (test runner)

---

## Phase 1: Split `extraction/mod.rs` (1,576 lines -> 5 files)

This is the most critical split. The file mixes trait definitions, the core extractor implementation, helper functions, and 570 lines of tests.

### Task 1: Verify baseline -- all tests pass

**Step 1: Run full test suite**

Run: `just test-ci`
Expected: All tests pass

**Step 2: Record line counts for tracking**

Run: `wc -l src/extraction/mod.rs src/extraction/ascii.rs src/extraction/utf16.rs src/extraction/pe_resources.rs src/extraction/dedup.rs src/extraction/filters.rs`

---

### Task 2: Extract `extraction/traits.rs`

**Files:**
- Create: `src/extraction/traits.rs`
- Modify: `src/extraction/mod.rs`

**What moves to `traits.rs`:**
- `ExtractionConfig` struct + `impl Default` + `validate()` method (lines ~196-336)
- `StringExtractor` trait definition (lines ~338-429)
- `BasicExtractor` struct + `impl BasicExtractor::new()` + `impl Default` (lines ~431-486)

**Step 1: Create `src/extraction/traits.rs`**

Copy the trait definitions, config struct, and BasicExtractor struct definition from mod.rs. Add necessary `use` imports at the top. Keep all items `pub` or `pub(crate)` as they were.

**Step 2: Update `src/extraction/mod.rs`**

- Add `mod traits;` declaration
- Add `pub use traits::{ExtractionConfig, StringExtractor, BasicExtractor};`
- Remove the moved code from mod.rs
- Keep `impl StringExtractor for BasicExtractor` in mod.rs for now (it depends on submodule functions)

**Step 3: Run tests**

Run: `just test-ci`
Expected: All tests pass (public API unchanged via re-exports)

**Step 4: Commit**

```
git add src/extraction/traits.rs src/extraction/mod.rs
git commit -s -m "refactor(extraction): extract traits and config to traits.rs"
```

---

### Task 3: Extract `extraction/helpers.rs`

**Files:**
- Create: `src/extraction/helpers.rs`
- Modify: `src/extraction/mod.rs`

**What moves to `helpers.rs`:**
- `apply_semantic_enrichment()` function (lines ~155-194)
- `is_printable_text_byte()` function (lines ~894-912)
- `could_be_utf8_byte()` function (lines ~914-920)
- `extract_ascii_utf8_strings()` function (lines ~922-1006)

**Step 1: Create `src/extraction/helpers.rs`**

Move the helper functions. Use `pub(crate)` visibility for internal helpers (`is_printable_text_byte`, `could_be_utf8_byte`). Keep `apply_semantic_enrichment` and `extract_ascii_utf8_strings` at their current visibility.

**Step 2: Update mod.rs**

- Add `mod helpers;`
- Add appropriate `pub use` / `pub(crate) use` re-exports
- Remove moved code

**Step 3: Run tests**

Run: `just test-ci`
Expected: All tests pass

**Step 4: Commit**

```
git add src/extraction/helpers.rs src/extraction/mod.rs
git commit -s -m "refactor(extraction): extract helper functions to helpers.rs"
```

---

### Task 4: Extract `extraction/basic_extractor.rs`

**Files:**
- Create: `src/extraction/basic_extractor.rs`
- Modify: `src/extraction/mod.rs`

**What moves to `basic_extractor.rs`:**
- `impl StringExtractor for BasicExtractor` block containing:
  - `extract()` method (lines ~488-594)
  - `extract_canonical()` method (lines ~596-709)
  - `extract_from_section()` method (lines ~711-891)

**Step 1: Create `src/extraction/basic_extractor.rs`**

Move the impl block. Add imports for all dependencies: `BasicExtractor`, `StringExtractor`, `ExtractionConfig` from `super::traits`, helper functions from `super::helpers`, and submodule functions (ascii, utf16, pe_resources, dedup, etc.).

**Step 2: Update mod.rs**

- Add `mod basic_extractor;`
- Remove the `impl StringExtractor for BasicExtractor` block

**Step 3: Run tests**

Run: `just test-ci`
Expected: All tests pass

**Step 4: Commit**

```
git add src/extraction/basic_extractor.rs src/extraction/mod.rs
git commit -s -m "refactor(extraction): extract BasicExtractor impl to basic_extractor.rs"
```

---

### Task 5: Extract `extraction/tests.rs`

**Files:**
- Create: `src/extraction/tests.rs`
- Modify: `src/extraction/mod.rs`

**What moves:**
- Entire `#[cfg(test)] mod tests` block (lines ~1008-1576, ~568 lines)

**Step 1: Create `src/extraction/tests.rs`**

Move the test module contents (without the outer `mod tests {}` wrapper -- the file IS the module). Add `use super::*;` and any needed imports.

**Step 2: Update mod.rs**

Replace the inline test module with:
```rust
#[cfg(test)]
mod tests;
```

**Step 3: Run tests**

Run: `just test-ci`
Expected: All tests pass

**Step 4: Verify mod.rs is now under 500 lines**

Run: `wc -l src/extraction/mod.rs`
Expected: ~150 lines (docs + imports + mod declarations + re-exports)

**Step 5: Commit**

```
git add src/extraction/tests.rs src/extraction/mod.rs
git commit -s -m "refactor(extraction): extract tests to tests.rs"
```

---

## Phase 2: Split remaining large extraction files

Each file follows the same pattern: convert `foo.rs` to `foo/mod.rs` + submodules, extracting tests and large logical sections.

### Task 6: Split `extraction/filters.rs` (702 lines)

**Files:**
- Rename: `src/extraction/filters.rs` -> `src/extraction/filters/mod.rs`
- Create: `src/extraction/filters/implementations.rs`
- Create: `src/extraction/filters/tests.rs`

**Split strategy:**
- `mod.rs` (~130 lines): FilterContext struct + impl, NoiseFilter trait, CompositeNoiseFilter struct + impl
- `implementations.rs` (~340 lines): All 6 filter structs (CharDistributionFilter, EntropyFilter, LinguisticFilter, LengthFilter, RepetitionFilter, ContextFilter) + their NoiseFilter impls
- `tests.rs` (~130 lines): All test code

**Step 1: Create `src/extraction/filters/` directory**

Run: `mkdir -p src/extraction/filters`

**Step 2: Split the file**

Move FilterContext, NoiseFilter trait, and CompositeNoiseFilter to `mod.rs`. Move all 6 filter implementations to `implementations.rs`. Move tests to `tests.rs`.

**Step 3: Run tests**

Run: `just test-ci`
Expected: All tests pass

**Step 4: Verify all files under 500 lines**

Run: `wc -l src/extraction/filters/*.rs`

**Step 5: Commit**

```
git add src/extraction/filters/
git commit -s -m "refactor(extraction): split filters.rs into module directory"
```

---

### Task 7: Split `extraction/ascii.rs` (832 lines)

**Files:**
- Rename: `src/extraction/ascii.rs` -> `src/extraction/ascii/mod.rs`
- Create: `src/extraction/ascii/extraction.rs`
- Create: `src/extraction/ascii/tests.rs`

**Split strategy:**
- `mod.rs` (~150 lines): AsciiExtractionConfig struct + impl, is_printable_ascii(), re-exports
- `extraction.rs` (~300 lines): extract_ascii_strings() + extract_from_section()
- `tests.rs` (~380 lines): All test code

**Steps:** Same pattern as Task 6: create directory, split, run tests, verify line counts, commit.

```
git commit -s -m "refactor(extraction): split ascii.rs into module directory"
```

---

### Task 8: Split `extraction/utf16.rs` (1,273 lines)

**Files:**
- Rename: `src/extraction/utf16.rs` -> `src/extraction/utf16/mod.rs`
- Create: `src/extraction/utf16/config.rs`
- Create: `src/extraction/utf16/validation.rs`
- Create: `src/extraction/utf16/confidence.rs`
- Create: `src/extraction/utf16/extraction.rs`
- Create: `src/extraction/utf16/tests.rs`

**Split strategy:**
- `mod.rs` (~120 lines): ByteOrder enum, re-exports, main extract_utf16_strings orchestrator
- `config.rs` (~70 lines): Utf16ExtractionConfig + impl
- `validation.rs` (~130 lines): is_valid_utf16_sequence, check_valid_unicode_range, check_null_pattern, printable checks
- `confidence.rs` (~200 lines): All confidence scoring functions (check_ascii_ratio, check_printable_ratio, calculate_utf16_confidence, etc.)
- `extraction.rs` (~250 lines): Internal extraction functions + extract_from_section
- `tests.rs` (~240 lines): All test code

**Steps:** Create directory, split into 6 files, run tests, verify, commit.

```
git commit -s -m "refactor(extraction): split utf16.rs into module directory"
```

---

### Task 9: Split `extraction/dedup.rs` (838 lines)

**Files:**
- Rename: `src/extraction/dedup.rs` -> `src/extraction/dedup/mod.rs`
- Create: `src/extraction/dedup/scoring.rs`
- Create: `src/extraction/dedup/tests.rs`

**Split strategy:**
- `mod.rs` (~230 lines): CanonicalString, StringOccurrence structs, deduplicate(), merge_tags(), found_string_to_occurrence(), CanonicalString::to_found_string()
- `scoring.rs` (~50 lines): calculate_combined_score()
- `tests.rs` (~555 lines): All test code

**Steps:** Create directory, split, run tests, verify, commit.

```
git commit -s -m "refactor(extraction): split dedup.rs into module directory"
```

---

### Task 10: Split `extraction/pe_resources.rs` (1,449 lines)

**Files:**
- Rename: `src/extraction/pe_resources.rs` -> `src/extraction/pe_resources/mod.rs`
- Create: `src/extraction/pe_resources/detection.rs`
- Create: `src/extraction/pe_resources/version_info.rs`
- Create: `src/extraction/pe_resources/string_tables.rs`
- Create: `src/extraction/pe_resources/manifests.rs`
- Create: `src/extraction/pe_resources/tests.rs`

**Split strategy:**
- `mod.rs` (~130 lines): Constants, extract_resources entry point, enumerate_resources, extract_resource_strings orchestrator, decode_utf16le helper
- `detection.rs` (~200 lines): detect_version_info, detect_string_tables, detect_manifests
- `version_info.rs` (~70 lines): extract_version_info_strings
- `string_tables.rs` (~110 lines): parse_string_table_block, extract_string_table_strings
- `manifests.rs` (~150 lines): detect_manifest_encoding, decode_manifest, extract_manifest_strings
- `tests.rs` (~610 lines): All test code

**Steps:** Create directory, split into 6 files, run tests, verify, commit.

```
git commit -s -m "refactor(extraction): split pe_resources.rs into module directory"
```

---

### Task 11: Final verification and line count audit

**Step 1: Run full test suite**

Run: `just ci-check`
Expected: All checks pass

**Step 2: Verify all files under 500 lines**

Run: `find src/ -name '*.rs' -exec wc -l {} + | sort -rn | head -20`
Expected: No non-test file exceeds 500 lines

**Step 3: Verify public API unchanged**

Run: `cargo doc --no-deps 2>&1 | grep -c warning`
Expected: 0 warnings (no broken doc links)

**Step 4: Commit any remaining fixes**

---

## Phase 3: Wire Up CLI (`main.rs`)

### Task 12: Write failing test for CLI file reading

**Files:**
- Create: `tests/integration_cli.rs`
- Modify: `src/main.rs`

**Step 1: Write failing integration test**

```rust
use std::process::Command;

#[test]
fn cli_accepts_binary_file() {
    let output = Command::new(env!("CARGO_BIN_EXE_stringy"))
        .arg("tests/fixtures/test_binary_elf")
        .output()
        .expect("Failed to execute stringy");

    assert!(output.status.success(), "Exit code: {}", output.status);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("coming soon"), "CLI still shows stub message");
    assert!(!stdout.is_empty(), "No output produced");
}
```

**Step 2: Run test to verify it fails**

Run: `cargo nextest run --test integration_cli`
Expected: FAIL (main.rs still prints "coming soon")

**Step 3: Commit failing test**

```
git commit -s -m "test(cli): add failing integration test for binary file processing"
```

---

### Task 13: Implement basic CLI pipeline

**Files:**
- Modify: `src/main.rs`

**Step 1: Extend Cli struct with output format**

```rust
#[derive(Parser)]
#[command(name = "stringy")]
#[command(about = "Extract meaningful strings from binary files")]
#[command(version)]
struct Cli {
    /// Input binary file to analyze
    #[arg(value_name = "FILE")]
    input: PathBuf,

    /// Output format: table, json, yara
    #[arg(short, long, default_value = "table")]
    format: String,

    /// Minimum string length
    #[arg(short = 'l', long, default_value = "4")]
    min_length: usize,
}
```

**Step 2: Implement pipeline in main()**

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let data = std::fs::read(&cli.input)?;
    let format = stringy::container::detect_format(&data);
    let parser = stringy::container::create_parser(format)?;
    let container_info = parser.parse(&data)?;

    let config = stringy::ExtractionConfig {
        min_length: cli.min_length,
        ..Default::default()
    };
    config.validate()?;

    let extractor = stringy::BasicExtractor::new();
    let strings = extractor.extract(&data, &container_info, &config)?;

    let output_format = match cli.format.as_str() {
        "json" => stringy::OutputFormat::Json,
        "yara" => stringy::OutputFormat::Yara,
        _ => stringy::OutputFormat::Table,
    };

    let binary_name = cli.input
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    let metadata = stringy::OutputMetadata::new(binary_name, format, strings.len(), strings.len());
    let output = stringy::format_output(&strings, &metadata, output_format)?;
    print!("{output}");

    Ok(())
}
```

**Step 3: Run test to verify it passes**

Run: `cargo nextest run --test integration_cli`
Expected: PASS

**Step 4: Commit**

```
git commit -s -m "feat(cli): wire up extraction pipeline in main.rs"
```

---

### Task 14: Add CLI tests for output formats

**Files:**
- Modify: `tests/integration_cli.rs`

**Step 1: Write tests for JSON and YARA output**

```rust
#[test]
fn cli_json_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_stringy"))
        .args(["tests/fixtures/test_binary_elf", "--format", "json"])
        .output()
        .expect("Failed to execute stringy");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // JSONL format: each line is valid JSON
    for line in stdout.lines().filter(|l| !l.is_empty()) {
        serde_json::from_str::<serde_json::Value>(line)
            .expect("Each line should be valid JSON");
    }
}

#[test]
fn cli_yara_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_stringy"))
        .args(["tests/fixtures/test_binary_elf", "--format", "yara"])
        .output()
        .expect("Failed to execute stringy");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("rule"), "YARA output should contain rule keyword");
}

#[test]
fn cli_invalid_file() {
    let output = Command::new(env!("CARGO_BIN_EXE_stringy"))
        .arg("nonexistent_file")
        .output()
        .expect("Failed to execute stringy");

    assert!(!output.status.success(), "Should fail for missing file");
}

#[test]
fn cli_min_length_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_stringy"))
        .args(["tests/fixtures/test_binary_elf", "-l", "20"])
        .output()
        .expect("Failed to execute stringy");

    assert!(output.status.success());
}
```

**Step 2: Run tests**

Run: `cargo nextest run --test integration_cli`
Expected: All pass

**Step 3: Commit**

```
git commit -s -m "test(cli): add integration tests for output formats and error handling"
```

---

### Task 15: Final verification

**Step 1: Run full CI check**

Run: `just ci-check`
Expected: All checks pass

**Step 2: Verify no file exceeds 500 lines (excluding test files)**

Run: `find src/ -name '*.rs' ! -name 'tests.rs' -exec wc -l {} + | sort -rn | head -10`

**Step 3: Verify coverage hasn't regressed**

Run: `just coverage`

---

## Verification Checklist

After all tasks complete:
- [ ] `just ci-check` passes (fmt, clippy, tests, coverage, dist)
- [ ] No source file exceeds 500 lines (test files may be slightly over)
- [ ] `cargo doc --no-deps` produces zero warnings
- [ ] All existing integration tests still pass
- [ ] New CLI integration tests pass for all output formats
- [ ] `stringy tests/fixtures/test_binary_elf` produces output
- [ ] `stringy tests/fixtures/test_binary_pe.exe --format json` produces JSONL
- [ ] Public API re-exports in lib.rs are unchanged
