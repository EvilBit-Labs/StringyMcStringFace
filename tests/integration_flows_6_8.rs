use assert_cmd::{Command, cargo_bin_cmd};
use predicates::prelude::*;
use serde_json::Value;
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
fn flow7_summary_non_tty_exit_1() {
    // assert_cmd output is piped, so --summary triggers the runtime TTY check.
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--summary"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("--summary"));
}

#[test]
fn flow7_tty_summary_block_contains_required_fields() {
    // TTY summary cannot be tested via assert_cmd (non-TTY). Instead, test
    // via the library-level format_table_with_mode(..., true) with
    // show_summary enabled.
    let mut fs = FoundString::new(
        "http://example.com".to_string(),
        Encoding::Ascii,
        0x1000,
        18,
        StringSource::SectionData,
    );
    fs.tags = vec![Tag::Url];

    let metadata = OutputMetadata::new("sample.elf".to_string(), OutputFormat::Table, 42, 10)
        .with_show_summary(true)
        .with_binary_format(BinaryFormat::Elf);

    let rendered =
        format_table_with_mode(&[fs], &metadata, true).expect("TTY summary rendering must succeed");

    // Binary format label
    assert!(
        rendered.contains("ELF"),
        "summary must contain format label 'ELF', got: {rendered}"
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
    // The summary line pattern: "Strings: N shown / M extracted  [FORMAT]"
    assert!(
        rendered.contains("Strings:"),
        "summary must contain 'Strings:' label, got: {rendered}"
    );
}

// ---------------------------------------------------------------------------
// Flow 8 -- All Error Paths
// ---------------------------------------------------------------------------

#[test]
fn flow8_invalid_tag_value_exit_2() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--only-tags", "bad_tag"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("invalid"));
}

#[test]
fn flow8_invalid_notag_value_exit_2() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--notags", "bad_tag"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("invalid"));
}

#[test]
fn flow8_comma_tag_syntax_rejected_exit_2() {
    // clap rejects "url,ipv4" as a single unknown tag value
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--only-tags", "url,ipv4"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("invalid"));
}

// --json + --yara conflict is covered in integration_cli.rs
// (cli_json_and_yara_conflict) with explicit exit code 2 assertion.

// NOTE: --summary + --json conflict is covered above in flow7_summary_conflicts_with_json_exit_2.

#[test]
fn flow8_raw_only_tags_conflict_exit_2() {
    stringy()
        .args([
            "tests/fixtures/test_binary_elf",
            "--raw",
            "--only-tags",
            "url",
        ])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn flow8_raw_notags_conflict_exit_2() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--raw", "--notags", "url"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn flow8_raw_top_conflict_exit_2() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--raw", "--top", "5"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn flow8_raw_debug_conflict_exit_2() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--raw", "--debug"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn flow8_raw_yara_conflict_exit_2() {
    // Also covered in integration_cli.rs (cli_raw_conflicts_with_yara),
    // but included here for completeness of the Flow 8 error matrix.
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--raw", "--yara"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
}

// NOTE: --summary non-TTY exit 1 is covered in flow7_summary_non_tty_exit_1 above.

#[test]
fn flow8_tag_overlap_exit_1() {
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
        .code(1)
        .stderr(predicate::str::contains("--only-tags and --notags"));
}

#[test]
fn flow8_unknown_binary_info_stderr_exit_0() {
    stringy()
        .arg("tests/fixtures/test_unknown.bin")
        .assert()
        .success()
        .stderr(predicate::str::contains("Info:"))
        .stderr(predicate::str::contains("unknown"));
}

#[test]
fn flow8_empty_binary_info_stderr_exit_0() {
    stringy()
        .arg("tests/fixtures/test_empty.bin")
        .assert()
        .success()
        .stderr(predicate::str::contains("Info:"));
}

#[test]
fn flow8_filters_match_nothing_info_stderr_exit_0() {
    // Use --only-tags guid as a deterministic no-match filter: the C test
    // fixture contains no GUIDs. If this assumption ever breaks, switch to
    // a different rare tag.
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--only-tags", "guid"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty().trim())
        .stderr(predicate::str::contains("Info:"));
}

// ---------------------------------------------------------------------------
// Score Determinism
// ---------------------------------------------------------------------------

#[test]
fn score_determinism_across_two_runs() {
    let run = || {
        let assert = stringy()
            .args(["tests/fixtures/test_binary_elf", "--json", "--debug"])
            .assert()
            .success();
        let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
        stdout
            .lines()
            .filter(|l| !l.is_empty())
            .map(|line| serde_json::from_str::<Value>(line).expect("valid JSON"))
            .collect::<Vec<Value>>()
    };

    let run1 = run();
    let run2 = run();

    assert_eq!(
        run1.len(),
        run2.len(),
        "both runs must produce the same number of results"
    );

    for (i, (v1, v2)) in run1.iter().zip(run2.iter()).enumerate() {
        assert_eq!(
            v1["text"], v2["text"],
            "row {i}: text must match across runs"
        );
        assert_eq!(
            v1["display_score"], v2["display_score"],
            "row {i}: display_score must match across runs"
        );
    }
}

// ---------------------------------------------------------------------------
// --debug Field Presence / Absence
// ---------------------------------------------------------------------------

#[test]
fn debug_flag_adds_score_breakdown_fields() {
    let assert = stringy()
        .args(["tests/fixtures/test_binary_elf", "--json", "--debug"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    // debug-only fields (section_weight, semantic_boost, noise_penalty)
    // are skip_serializing_if = "Option::is_none" and only populated in
    // debug mode. display_score is always present.
    let debug_only_fields = ["section_weight", "semantic_boost", "noise_penalty"];

    for line in stdout.lines().filter(|l| !l.is_empty()) {
        let v: Value = serde_json::from_str(line).expect("valid JSON");
        let obj = v.as_object().expect("each line must be a JSON object");
        for field in &debug_only_fields {
            assert!(
                obj.contains_key(*field),
                "debug mode must include '{field}' key"
            );
        }
        assert!(
            obj.contains_key("display_score"),
            "debug mode must include 'display_score' key"
        );
    }
}

#[test]
fn no_debug_flag_omits_score_breakdown_fields() {
    let assert = stringy()
        .args(["tests/fixtures/test_binary_elf", "--json"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    // All four debug-only fields must be absent without --debug:
    // section_weight, semantic_boost, noise_penalty, and display_score.
    let debug_only_fields = [
        "section_weight",
        "semantic_boost",
        "noise_penalty",
        "display_score",
    ];

    for line in stdout.lines().filter(|l| !l.is_empty()) {
        let v: Value = serde_json::from_str(line).expect("valid JSON");
        let obj = v.as_object().expect("each line must be a JSON object");
        for field in &debug_only_fields {
            assert!(
                !obj.contains_key(*field),
                "non-debug mode must NOT include '{field}' key"
            );
        }
    }
}
