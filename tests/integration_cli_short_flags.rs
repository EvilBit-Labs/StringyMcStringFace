use assert_cmd::{Command, cargo_bin_cmd};
use predicates::prelude::*;
use serde_json::Value;

fn stringy() -> Command {
    cargo_bin_cmd!("stringy")
}

#[test]
fn test_short_flag_json_equivalence() {
    let elf_path = "tests/fixtures/test_binary_elf";

    let long_output = stringy()
        .arg(elf_path)
        .arg("--json")
        .output()
        .expect("Failed to run with --json");

    let short_output = stringy()
        .arg(elf_path)
        .arg("-j")
        .output()
        .expect("Failed to run with -j");

    assert!(long_output.status.success());
    assert!(short_output.status.success());

    let long_lines = String::from_utf8_lossy(&long_output.stdout).lines().count();
    let short_lines = String::from_utf8_lossy(&short_output.stdout)
        .lines()
        .count();

    assert_eq!(
        long_lines, short_lines,
        "-j should produce same output as --json"
    );
}

#[test]
fn test_short_flag_min_len_equivalence() {
    let elf_path = "tests/fixtures/test_binary_elf";

    let long_output = stringy()
        .arg(elf_path)
        .arg("--min-len")
        .arg("10")
        .output()
        .expect("Failed to run with --min-len");

    let short_output = stringy()
        .arg(elf_path)
        .arg("-m")
        .arg("10")
        .output()
        .expect("Failed to run with -m");

    assert!(long_output.status.success());
    assert!(short_output.status.success());

    let long_lines = String::from_utf8_lossy(&long_output.stdout).lines().count();
    let short_lines = String::from_utf8_lossy(&short_output.stdout)
        .lines()
        .count();

    assert_eq!(
        long_lines, short_lines,
        "-m 10 should produce same output as --min-len 10"
    );
}

#[test]
fn test_short_flag_top_equivalence() {
    let elf_path = "tests/fixtures/test_binary_elf";

    let long_output = stringy()
        .arg(elf_path)
        .arg("--top")
        .arg("5")
        .output()
        .expect("Failed to run with --top");

    let short_output = stringy()
        .arg(elf_path)
        .arg("-t")
        .arg("5")
        .output()
        .expect("Failed to run with -t");

    assert!(long_output.status.success());
    assert!(short_output.status.success());

    let long_lines = String::from_utf8_lossy(&long_output.stdout).lines().count();
    let short_lines = String::from_utf8_lossy(&short_output.stdout)
        .lines()
        .count();

    assert_eq!(
        long_lines, short_lines,
        "-t 5 should produce same output as --top 5"
    );
}

#[test]
fn test_enc_long_flag_only() {
    let elf_path = "tests/fixtures/test_binary_elf";

    // --enc has no short form (infrequent flag)
    stringy()
        .arg(elf_path)
        .arg("--enc")
        .arg("ascii")
        .assert()
        .success();
}

#[test]
fn test_short_flag_combination() {
    let elf_path = "tests/fixtures/test_binary_elf";

    stringy()
        .arg(elf_path)
        .arg("-j")
        .arg("-m")
        .arg("10")
        .arg("-t")
        .arg("5")
        .arg("--enc")
        .arg("ascii")
        .assert()
        .success();
}

#[test]
fn test_no_color_env_var() {
    let elf_path = "tests/fixtures/test_binary_elf";

    stringy()
        .arg(elf_path)
        .env("NO_COLOR", "1")
        .assert()
        .success();
}

#[test]
fn test_multiple_only_tags_or_logic() {
    let elf_path = "tests/fixtures/test_binary_elf";

    let output = stringy()
        .arg(elf_path)
        .arg("--only-tags")
        .arg("url")
        .arg("--only-tags")
        .arg("domain")
        .arg("--json")
        .output()
        .expect("Failed to run with multiple --only-tags");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();

    assert!(!lines.is_empty(), "Expected at least one result");

    for line in lines {
        let parsed: Value = serde_json::from_str(line).expect("Each line should be valid JSON");

        let tags = parsed["tags"]
            .as_array()
            .expect("tags field should be an array");

        let has_url_or_domain = tags.iter().any(|tag| {
            let tag_str = tag.as_str().expect("tag should be a string");
            tag_str.eq_ignore_ascii_case("url") || tag_str.eq_ignore_ascii_case("domain")
        });

        assert!(
            has_url_or_domain,
            "Every record should have either Url or Domain tag, got: {:?}",
            tags
        );
    }
}

#[test]
fn test_top_larger_than_result_count() {
    let elf_path = "tests/fixtures/test_binary_elf";

    stringy()
        .arg(elf_path)
        .arg("--top")
        .arg("99999")
        .assert()
        .success();
}

#[test]
fn test_min_len_negative_fails() {
    let elf_path = "tests/fixtures/test_binary_elf";

    stringy()
        .arg(elf_path)
        .arg("--min-len")
        .arg("-1")
        .assert()
        .failure()
        .code(2);
}

#[test]
fn test_top_negative_fails() {
    let elf_path = "tests/fixtures/test_binary_elf";

    stringy()
        .arg(elf_path)
        .arg("--top")
        .arg("-5")
        .assert()
        .failure()
        .code(2);
}

#[test]
fn test_min_len_huge_value_config_error() {
    let elf_path = "tests/fixtures/test_binary_elf";

    // A min-len exceeding the internal max_length (4096) triggers a ConfigError
    stringy()
        .arg(elf_path)
        .arg("--min-len")
        .arg("999999")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("max_length"));
}

#[test]
fn test_stdin_empty_data() {
    stringy()
        .arg("-")
        .write_stdin("")
        .assert()
        .success()
        .code(0)
        .stderr(predicate::str::contains("Info"));
}

#[test]
fn test_raw_json_combination() {
    let elf_path = "tests/fixtures/test_binary_elf";

    let output = stringy()
        .arg(elf_path)
        .arg("--raw")
        .arg("--json")
        .output()
        .expect("Failed to run with --raw --json");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();

    assert!(
        !lines.is_empty(),
        "Expected at least one result in raw mode"
    );

    for line in lines {
        let parsed: Value = serde_json::from_str(line).expect("Each line should be valid JSON");

        // Raw mode forces display_score to 0 and clears tags
        assert_eq!(
            parsed["display_score"], 0,
            "Raw mode JSON display_score should be 0"
        );
        let tags = parsed["tags"].as_array().expect("tags should be an array");
        assert!(tags.is_empty(), "Raw mode JSON should have empty tags");
    }
}
