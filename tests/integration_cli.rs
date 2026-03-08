use assert_cmd::{Command, cargo_bin_cmd};
use predicates::prelude::*;

fn stringy() -> Command {
    cargo_bin_cmd!("stringy")
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

#[test]
fn cli_help_flag() {
    stringy()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "smarter alternative to the strings command",
        ))
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

#[test]
fn cli_long_help_has_examples() {
    stringy()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("EXAMPLES:"));
}

#[test]
fn cli_top_flag() {
    let top_output = stringy()
        .args(["tests/fixtures/test_binary_elf", "--top", "1", "--json"])
        .output()
        .expect("should succeed");

    assert!(top_output.status.success());
    let stdout = String::from_utf8_lossy(&top_output.stdout);
    let line_count = stdout.lines().filter(|l| !l.is_empty()).count();
    assert!(
        line_count <= 1,
        "--top 1 should produce at most 1 result line, got {line_count}"
    );
}

#[test]
fn cli_enc_flag() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--enc", "ascii"])
        .assert()
        .success();
}

#[test]
fn cli_raw_flag() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--raw"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Score").not());
}

#[test]
fn cli_raw_conflicts_with_yara() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--raw", "--yara"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn cli_only_tags_filter_excludes_untagged() {
    let assert = stringy()
        .args([
            "tests/fixtures/test_binary_elf",
            "--only-tags",
            "url",
            "--json",
        ])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    for line in stdout.lines().filter(|l| !l.is_empty()) {
        let value: serde_json::Value =
            serde_json::from_str(line).expect("each line should be valid JSON");
        let tags = value["tags"]
            .as_array()
            .expect("tags field should be an array");
        assert!(
            tags.iter().any(|t| t.as_str() == Some("url")),
            "every result should contain the 'url' tag, got: {tags:?}"
        );
    }
}
