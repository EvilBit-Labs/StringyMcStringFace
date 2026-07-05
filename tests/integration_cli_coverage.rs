use assert_cmd::{Command, cargo_bin_cmd};
use predicates::prelude::*;
use std::io::Write;

fn stringy() -> Command {
    cargo_bin_cmd!("stringy")
}

// Test 1: stdin pipe support
#[test]
fn stdin_pipe_elf_binary() {
    let fixture_data =
        std::fs::read("tests/fixtures/test_binary_elf").expect("fixture should exist");

    stringy()
        .arg("-")
        .write_stdin(fixture_data)
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

// Test 2: All encoding filter variants
#[test]
fn encoding_filter_utf8() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--enc", "utf8"])
        .assert()
        .success();
}

#[test]
fn encoding_filter_utf16() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--enc", "utf16"])
        .assert()
        .success();
}

#[test]
fn encoding_filter_utf16le() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--enc", "utf16le"])
        .assert()
        .success();
}

#[test]
fn encoding_filter_utf16be() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--enc", "utf16be"])
        .assert()
        .success();
}

#[test]
fn encoding_filter_ascii() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--enc", "ascii"])
        .assert()
        .success();
}

#[test]
fn encoding_filter_ascii_is_content_based() {
    // --enc ascii is a content filter (R16): every emitted row's text must be
    // pure-ASCII, regardless of stored encoding. Extraction labels ASCII
    // content as Utf8, so this asserts content, not the encoding field.
    let assert = stringy()
        .args(["tests/fixtures/test_binary_elf", "--enc", "ascii", "--json"])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let mut rows = 0;
    for line in stdout.lines().filter(|l| !l.is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line).expect("valid JSON line");
        let text = v["text"].as_str().expect("text field");
        assert!(
            text.is_ascii(),
            "--enc ascii must only emit pure-ASCII text, got: {text:?}"
        );
        rows += 1;
    }
    assert!(rows > 0, "ELF fixture should yield some ASCII rows");
}

#[test]
fn encoding_filter_invalid() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--enc", "invalid_enc"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("invalid value"));
}

// Test 3: Permission denied error (unix only)
#[test]
#[cfg(unix)]
fn permission_denied_exit_code_4() {
    use std::os::unix::fs::PermissionsExt;

    let temp_file = tempfile::NamedTempFile::new().expect("create temp file");
    temp_file
        .as_file()
        .write_all(b"test data")
        .expect("write data");
    let path = temp_file.path();

    // Set permissions to 0o000 (no read access)
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000))
        .expect("set permissions");

    // Verify exit code 4 for permission denied
    stringy().arg(path).assert().failure().code(4);

    // Restore permissions so temp file can be cleaned up
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
        .expect("restore permissions");
}

// Test 4: Combined filters
#[test]
fn combined_filters_with_json() {
    stringy()
        .args([
            "tests/fixtures/test_binary_elf",
            "--min-len",
            "10",
            "--enc",
            "ascii",
            "--top",
            "5",
            "--json",
        ])
        .assert()
        .success();
}

// Test 5: --no-tags standalone
#[test]
fn no_tags_url_excludes_url_tag() {
    let assert = stringy()
        .args([
            "tests/fixtures/test_unknown.bin",
            "--no-tags",
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

        // Verify no tag is "Url" (case-insensitive)
        assert!(
            !tags
                .iter()
                .any(|t| t.as_str().is_some_and(|s| s.eq_ignore_ascii_case("url"))),
            "should not contain url tag, got: {tags:?}"
        );
    }
}

// Test 6: Multiple --no-tags flags
#[test]
fn multiple_no_tags_flags() {
    stringy()
        .args([
            "tests/fixtures/test_binary_elf",
            "--no-tags",
            "url",
            "--no-tags",
            "ipv4",
            "--no-tags",
            "filepath",
        ])
        .assert()
        .success();
}

// Test 7: --top 0 rejected
#[test]
fn top_zero_rejected() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--top", "0"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("value must be at least 1"));
}

// Test 8: --min-len 0 rejected
#[test]
fn min_len_zero_rejected() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--min-len", "0"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("value must be at least 1"));
}

// Test 9: Exit code contract
#[test]
fn exit_code_0_success() {
    stringy()
        .arg("tests/fixtures/test_binary_elf")
        .assert()
        .success()
        .code(0);
}

#[test]
fn exit_code_2_validation_error() {
    // Overlapping --only-tags and --no-tags
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
        .code(2)
        .stderr(predicate::str::contains("conflicting tag filters"));
}

#[test]
fn exit_code_3_missing_file() {
    stringy()
        .arg("nonexistent_file_that_does_not_exist.bin")
        .assert()
        .failure()
        .code(3);
}

#[test]
fn exit_code_2_clap_conflict() {
    // --json and --yara conflict
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--json", "--yara"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
}

// Test 10: Special character paths (unix only)
#[test]
#[cfg(unix)]
fn special_character_paths_with_spaces() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let dest_path = temp_dir.path().join("test with spaces.bin");

    std::fs::copy("tests/fixtures/test_binary_elf", &dest_path)
        .expect("copy fixture to path with spaces");

    stringy()
        .arg(&dest_path)
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}
