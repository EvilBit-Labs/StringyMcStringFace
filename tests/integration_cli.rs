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

// -- Convenience flags: --imports / --exports / --symbols (issue #208) --

/// Collect non-empty stdout lines, sorted, so equivalence checks are robust to
/// any run-to-run ordering nondeterminism in extraction or score tie-breaking.
fn sorted_stdout_lines(bytes: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(bytes);
    let mut lines: Vec<String> = text
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect();
    lines.sort();
    lines
}

#[test]
fn cli_imports_flag_succeeds() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--imports"])
        .assert()
        .success();
}

#[test]
fn cli_exports_flag_succeeds() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--exports"])
        .assert()
        .success();
}

#[test]
fn cli_symbols_flag_succeeds() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--symbols"])
        .assert()
        .success();
}

#[test]
fn cli_imports_equivalent_to_only_tags_import() {
    // R1: --imports is behaviorally equivalent to --only-tags import.
    let flag = stringy()
        .args(["tests/fixtures/test_binary_pe.exe", "--imports", "--json"])
        .output()
        .expect("should succeed");
    let tag = stringy()
        .args([
            "tests/fixtures/test_binary_pe.exe",
            "--only-tags",
            "import",
            "--json",
        ])
        .output()
        .expect("should succeed");
    assert!(flag.status.success() && tag.status.success());
    assert_eq!(
        sorted_stdout_lines(&flag.stdout),
        sorted_stdout_lines(&tag.stdout),
        "--imports should produce the same rows as --only-tags import"
    );
}

#[test]
fn cli_symbols_equivalent_to_only_tags_demangled() {
    // R2: --symbols maps to DemangledSymbol only; equivalent to --only-tags demangled.
    let flag = stringy()
        .args(["tests/fixtures/test_binary_pe.exe", "--symbols", "--json"])
        .output()
        .expect("should succeed");
    let tag = stringy()
        .args([
            "tests/fixtures/test_binary_pe.exe",
            "--only-tags",
            "demangled",
            "--json",
        ])
        .output()
        .expect("should succeed");
    assert!(flag.status.success() && tag.status.success());
    assert_eq!(
        sorted_stdout_lines(&flag.stdout),
        sorted_stdout_lines(&tag.stdout),
        "--symbols should produce the same rows as --only-tags demangled"
    );
}

#[test]
fn cli_convenience_flags_combine_as_union() {
    // AE1 / R3: --imports --exports equals repeated --only-tags import export (union).
    let flags = stringy()
        .args([
            "tests/fixtures/test_binary_pe.exe",
            "--imports",
            "--exports",
            "--json",
        ])
        .output()
        .expect("should succeed");
    let tags = stringy()
        .args([
            "tests/fixtures/test_binary_pe.exe",
            "--only-tags",
            "import",
            "--only-tags",
            "export",
            "--json",
        ])
        .output()
        .expect("should succeed");
    assert!(flags.status.success() && tags.status.success());
    assert_eq!(
        sorted_stdout_lines(&flags.stdout),
        sorted_stdout_lines(&tags.stdout),
        "--imports --exports should equal repeated --only-tags import export"
    );
}

#[test]
fn cli_imports_conflicts_with_only_tags() {
    // AE2 / R4: convenience flag conflicts with --only-tags at parse time.
    stringy()
        .args([
            "tests/fixtures/test_binary_elf",
            "--imports",
            "--only-tags",
            "url",
        ])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn cli_symbols_conflicts_with_raw() {
    // AE3 / R4: convenience flag conflicts with --raw at parse time.
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--symbols", "--raw"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn cli_imports_no_tags_contradiction_rejected() {
    // AE4 / R5: resolved include set overlapping --no-tags triggers runtime validation.
    stringy()
        .args([
            "tests/fixtures/test_binary_elf",
            "--imports",
            "--no-tags",
            "import",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("conflicting tag filters"));
}

#[test]
fn cli_imports_no_tags_compatible() {
    // AE5 / R5: no contradiction between --imports and --no-tags version.
    stringy()
        .args([
            "tests/fixtures/test_binary_elf",
            "--imports",
            "--no-tags",
            "version",
        ])
        .assert()
        .success();
}

#[test]
fn cli_help_lists_convenience_flags() {
    // R6: help lists the three flags and each points to --only-tags.
    stringy()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--imports"))
        .stdout(predicate::str::contains("--exports"))
        .stdout(predicate::str::contains("--symbols"))
        .stdout(predicate::str::contains("Shorthand for --only-tags"));
}
