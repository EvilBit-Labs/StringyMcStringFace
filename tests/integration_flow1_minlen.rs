use assert_cmd::cargo_bin_cmd;
use serde_json::Value;
use std::io::Write;

fn stringy() -> assert_cmd::Command {
    cargo_bin_cmd!("stringy")
}

// ---------------------------------------------------------------------------
// Default min-length behavior (no --min-len flag)
// ---------------------------------------------------------------------------

#[test]
fn flow1_default_no_min_length_filter() {
    // Create a temporary fixture containing short strings (< 4 chars) to prove
    // that the default extraction config does not impose a hidden minimum.
    let mut fixture = tempfile::NamedTempFile::new().expect("create temp file");

    // Write short null-terminated strings surrounded by padding.
    // "ab" (2 chars) and "XYZ" (3 chars) are both < 4 and should appear.
    let mut content = Vec::new();
    content.extend_from_slice(&[0u8; 16]);
    content.extend_from_slice(b"ab");
    content.push(0u8);
    content.extend_from_slice(b"XYZ");
    content.push(0u8);
    // Also include a longer string so we get non-empty output either way.
    content.extend_from_slice(b"LongerTestString");
    content.push(0u8);
    content.extend_from_slice(&[0u8; 16]);
    fixture.write_all(&content).expect("write fixture");
    fixture.flush().expect("flush fixture");

    let assert = stringy()
        .args([fixture.path().to_str().unwrap(), "--json"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let parsed: Vec<Value> = stdout
        .lines()
        .filter(|l| !l.is_empty())
        .map(|line| serde_json::from_str(line).expect("valid JSON"))
        .collect();

    assert!(!parsed.is_empty(), "expected at least one JSON result");

    let has_short = parsed
        .iter()
        .any(|v| v["length"].as_u64().unwrap_or(u64::MAX) < 4);

    assert!(
        has_short,
        "default mode (no --min-len) must include strings shorter than 4 chars"
    );
}

// ---------------------------------------------------------------------------
// Explicit --min-len 10 filters short strings
// ---------------------------------------------------------------------------

#[test]
fn flow2_explicit_min_len_10_filters_short_strings() {
    let assert = stringy()
        .args([
            "tests/fixtures/test_binary_elf",
            "--min-len",
            "10",
            "--json",
        ])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert!(
        !lines.is_empty(),
        "expected at least one result with len >= 10"
    );

    for line in &lines {
        let v: Value = serde_json::from_str(line).expect("valid JSON");
        let len = v["length"].as_u64().unwrap_or(0);
        assert!(len >= 10, "string length {len} is below --min-len 10");
    }
}
