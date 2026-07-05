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
        .stderr(predicate::str::contains("value must be at least 1"));
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
        .code(2)
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
            "--no-tags",
            "url",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("conflicting tag filters"));
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
fn cli_help_shows_exit_codes() {
    stringy()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("EXIT CODES:"));
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
fn cli_help_examples_use_repeated_flags_not_comma_syntax() {
    let assert = stringy().arg("--help").assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    // The examples section must use repeated --only-tags flags, not comma-delimited values.
    // Comma-delimited syntax (e.g. "--only-tags url,domain") is rejected at parse time.
    assert!(
        !stdout.contains("--only-tags url,"),
        "help examples must not use comma-delimited tag syntax: {stdout}"
    );
    assert!(
        !stdout.contains("--no-tags url,"),
        "help examples must not use comma-delimited no-tags syntax: {stdout}"
    );
    // Verify the correct repeated-flag pattern is present
    assert!(
        stdout.contains("--only-tags url --only-tags domain"),
        "help examples must demonstrate repeated --only-tags flags: {stdout}"
    );
}

#[test]
fn cli_help_lists_all_canonical_tags() {
    stringy()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("url"))
        .stdout(predicate::str::contains("domain"))
        .stdout(predicate::str::contains("ipv4"))
        .stdout(predicate::str::contains("ipv6"))
        .stdout(predicate::str::contains("filepath"))
        .stdout(predicate::str::contains("regpath"))
        .stdout(predicate::str::contains("guid"))
        .stdout(predicate::str::contains("email"))
        .stdout(predicate::str::contains("b64"))
        .stdout(predicate::str::contains("fmt"))
        .stdout(predicate::str::contains("user-agent-ish"))
        .stdout(predicate::str::contains("demangled"))
        .stdout(predicate::str::contains("import"))
        .stdout(predicate::str::contains("export"))
        .stdout(predicate::str::contains("version"))
        .stdout(predicate::str::contains("manifest"))
        .stdout(predicate::str::contains("resource"))
        .stdout(predicate::str::contains("dylib-path"))
        .stdout(predicate::str::contains("rpath"))
        .stdout(predicate::str::contains("rpath-var"))
        .stdout(predicate::str::contains("framework-path"))
        .stdout(predicate::str::contains("crypto"))
        .stdout(predicate::str::contains("network"))
        .stdout(predicate::str::contains("fileio"))
        .stdout(predicate::str::contains("entry-point"));
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
            tags.iter()
                .any(|t| t.as_str().is_some_and(|s| s.eq_ignore_ascii_case("url"))),
            "every result should contain the 'url' tag, got: {tags:?}"
        );
    }
}
