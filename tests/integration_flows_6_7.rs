use std::time::Duration;

use assert_cmd::{Command, cargo_bin_cmd};
use predicates::prelude::*;
use stringy::format_table_with_mode;
use stringy::output::{OutputFormat, OutputMetadata};
use stringy::types::{BinaryFormat, Encoding, FoundString, StringSource, Tag};

fn stringy() -> Command {
    cargo_bin_cmd!("stringy")
}

// ---------------------------------------------------------------------------
// Flow 6 -- Non-TTY Plain Text
// ---------------------------------------------------------------------------
// assert_cmd output is piped (not a TTY), so every stringy() call is
// inherently a non-TTY test.

#[test]
fn flow6_piped_output_is_one_string_per_line_no_headers() {
    let assert = stringy()
        .arg("tests/fixtures/test_binary_elf")
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(!stdout.trim().is_empty(), "stdout must not be empty");

    // In TTY mode, the table uses column headers separated by borders.
    // Piped output must be plain one-string-per-line with no table chrome.
    // Assert each TTY header token is individually absent. We check "| Tags"
    // and "| Score" patterns to avoid false positives from payload strings
    // that happen to contain those words.
    assert!(
        !stdout.contains("| Tags"),
        "piped output must not contain TTY table header '| Tags'"
    );
    assert!(
        !stdout.contains("| Score"),
        "piped output must not contain TTY table header '| Score'"
    );
    assert!(
        !stdout.contains("| Section"),
        "piped output must not contain TTY table header '| Section'"
    );

    // No table-formatted lines (column separators use " | " with surrounding spaces)
    for line in stdout.lines().filter(|l| !l.is_empty()) {
        assert!(
            !line.contains(" | "),
            "piped output must not contain table column separator ' | ': {line}"
        );
    }
}

#[test]
fn flow6_piped_plain_text_compatible_with_grep() {
    let assert = stringy()
        .arg("tests/fixtures/test_binary_elf")
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(!lines.is_empty(), "expected at least one output line");

    // Plain one-string-per-line format: no blank interior lines
    let non_empty: Vec<&&str> = lines.iter().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines.len(),
        non_empty.len(),
        "piped output should have no blank interior lines"
    );
}

// ---------------------------------------------------------------------------
// Flow 7 -- Summary
// ---------------------------------------------------------------------------

#[test]
fn flow7_summary_conflicts_with_json_exit_2() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--summary", "--json"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn flow7_summary_conflicts_with_yara_exit_2() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--summary", "--yara"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn flow7_summary_non_tty_exit_2() {
    // assert_cmd output is piped, so --summary triggers the runtime TTY check
    // (ValidationError -> exit code 2).
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--summary"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("--summary"));
}

#[test]
fn flow7_tty_summary_block_contains_required_fields() {
    // TTY summary cannot be tested via assert_cmd (non-TTY). Instead, test
    // via the library-level format_table_with_mode(..., true) with
    // show_summary enabled.
    let fs = FoundString::new(
        "http://example.com".to_string(),
        Encoding::Ascii,
        0x1000,
        18,
        StringSource::SectionData,
    )
    .with_tags(vec![Tag::Url]);

    let top_tags = OutputMetadata::compute_top_tags(std::slice::from_ref(&fs), 5);
    let metadata = OutputMetadata::new("sample.elf".to_string(), OutputFormat::Table, 42, 10)
        .with_show_summary(true)
        .with_binary_format(BinaryFormat::Elf)
        .with_top_tags(top_tags)
        .with_analysis_duration(Duration::from_millis(123));

    let rendered =
        format_table_with_mode(&[fs], &metadata, true).expect("TTY summary rendering must succeed");

    // Binary identity (name + format)
    assert!(
        rendered.contains("sample.elf"),
        "summary must contain binary name 'sample.elf', got: {rendered}"
    );
    assert!(
        rendered.contains("ELF"),
        "summary must contain format label 'ELF', got: {rendered}"
    );
    assert!(
        rendered.contains("Binary:"),
        "summary must contain 'Binary:' label, got: {rendered}"
    );
    // Shown / extracted counts
    assert!(
        rendered.contains("10 shown"),
        "summary must contain filtered count '10 shown', got: {rendered}"
    );
    assert!(
        rendered.contains("42 extracted"),
        "summary must contain total count '42 extracted', got: {rendered}"
    );
    assert!(
        rendered.contains("Strings:"),
        "summary must contain 'Strings:' label, got: {rendered}"
    );
    // Top tag distribution
    assert!(
        rendered.contains("Top tags:"),
        "summary must contain 'Top tags:' label, got: {rendered}"
    );
    assert!(
        rendered.contains("url"),
        "summary must contain the canonical tag name 'url', got: {rendered}"
    );
    // Analysis timing
    assert!(
        rendered.contains("Analysis time:"),
        "summary must contain 'Analysis time:' label, got: {rendered}"
    );
    assert!(
        rendered.contains("123ms"),
        "summary must contain analysis duration '123ms', got: {rendered}"
    );
}
