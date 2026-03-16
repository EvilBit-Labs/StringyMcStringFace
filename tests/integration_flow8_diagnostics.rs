use assert_cmd::{Command, cargo_bin_cmd};
use predicates::prelude::*;
use serde_json::Value;

fn stringy() -> Command {
    cargo_bin_cmd!("stringy")
}

// ---------------------------------------------------------------------------
// Flow 8 -- End-to-End Warning Emission via CLI
// ---------------------------------------------------------------------------

#[test]
fn flow8_injected_demangle_failures_emit_warning_on_stderr() {
    // Uses debug-build env var injection to trigger partial-processing
    // warnings through the full CLI path (not just the helper function).
    stringy()
        .env("STRINGY_TEST_INJECT_DEMANGLE_FAILURES", "3")
        .arg("tests/fixtures/test_binary_elf")
        .assert()
        .success()
        .stderr(predicate::str::contains("Warning:"))
        .stderr(predicate::str::contains(
            "3 symbol(s) could not be demangled",
        ));
}

#[test]
fn flow8_injected_classify_failures_emit_warning_on_stderr() {
    stringy()
        .env("STRINGY_TEST_INJECT_CLASSIFY_FAILURES", "5")
        .arg("tests/fixtures/test_binary_elf")
        .assert()
        .success()
        .stderr(predicate::str::contains("Warning:"))
        .stderr(predicate::str::contains(
            "5 string(s) failed semantic classification",
        ));
}

#[test]
fn flow8_injected_both_failures_emit_combined_warning() {
    stringy()
        .env("STRINGY_TEST_INJECT_DEMANGLE_FAILURES", "2")
        .env("STRINGY_TEST_INJECT_CLASSIFY_FAILURES", "4")
        .arg("tests/fixtures/test_binary_elf")
        .assert()
        .success()
        .stderr(predicate::str::contains("Warning:"))
        .stderr(predicate::str::contains(
            "2 symbol(s) could not be demangled",
        ))
        .stderr(predicate::str::contains(
            "4 string(s) failed semantic classification",
        ));
}

#[test]
fn flow8_normal_processing_no_spurious_warnings() {
    // Normal processing of a valid binary must not emit Warning: on stderr
    stringy()
        .arg("tests/fixtures/test_binary_elf")
        .assert()
        .success()
        .stderr(predicate::str::contains("Warning:").not());
}

// ---------------------------------------------------------------------------
// Flow 8 -- Unknown/Empty Binary Fallback
// ---------------------------------------------------------------------------

#[test]
fn flow8_unknown_binary_info_stderr_exit_0() {
    stringy()
        .arg("tests/fixtures/test_unknown.bin")
        .assert()
        .success()
        .stderr(predicate::str::contains("Info:"))
        .stderr(predicate::str::contains(
            "proceeding with unstructured byte scan",
        ));
}

#[test]
fn flow8_unknown_binary_json_has_raw_bytes_section_and_tags() {
    let assert = stringy()
        .args(["tests/fixtures/test_unknown.bin", "--json"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Info:"));

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let records: Vec<Value> = stdout
        .lines()
        .filter(|l| !l.is_empty())
        .map(|line| serde_json::from_str(line).expect("each line must be valid JSON"))
        .collect();

    // Every record must have section == "raw-bytes" (the unknown-data fallback section)
    for (i, record) in records.iter().enumerate() {
        assert_eq!(
            record["section"].as_str(),
            Some("raw-bytes"),
            "record {i}: section must be 'raw-bytes', got: {}",
            record["section"]
        );
    }

    // At least one record should have non-empty semantic tags
    // (test_unknown.bin contains strings that the classifier can tag)
    let any_tagged = records
        .iter()
        .any(|r| r["tags"].as_array().is_some_and(|tags| !tags.is_empty()));
    assert!(
        any_tagged,
        "at least one record should have non-empty tags in unknown-binary fallback"
    );
}

#[test]
fn flow8_empty_binary_info_stderr_exit_0() {
    stringy()
        .arg("tests/fixtures/test_empty.bin")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().trim())
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
        .stderr(predicate::str::contains("Info:"))
        .stderr(predicate::str::contains("Try adjusting"));
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
    // Three debug-only fields must be absent without --debug:
    // section_weight, semantic_boost, and noise_penalty.
    // display_score is always present (score normalization runs for all non-raw).
    let debug_only_fields = ["section_weight", "semantic_boost", "noise_penalty"];

    for line in stdout.lines().filter(|l| !l.is_empty()) {
        let v: Value = serde_json::from_str(line).expect("valid JSON");
        let obj = v.as_object().expect("each line must be a JSON object");
        for field in &debug_only_fields {
            assert!(
                !obj.contains_key(*field),
                "non-debug mode must NOT include '{field}' key"
            );
        }
        // display_score is always present in non-raw mode
        assert!(
            obj.contains_key("display_score"),
            "display_score must be present in normal mode"
        );
    }
}
