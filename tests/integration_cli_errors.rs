use assert_cmd::{Command, cargo_bin_cmd};
use predicates::prelude::*;

fn stringy() -> Command {
    cargo_bin_cmd!("stringy")
}

#[test]
fn unknown_format_falls_back_to_raw_scan() {
    // Feed a non-binary file -- not ELF/PE/Mach-O.
    // The pipeline gracefully falls back to unstructured byte scanning.
    stringy()
        .arg("tests/fixtures/test_unknown.bin")
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "proceeding with unstructured byte scan",
        ));
}

#[test]
fn error_missing_file_shows_path() {
    stringy()
        .arg("this_file_does_not_exist.bin")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Error:"))
        .stderr(predicate::str::contains("this_file_does_not_exist.bin"));
}

#[test]
fn exit_code_2_for_clap_errors() {
    // Missing required argument
    stringy().assert().failure().code(2);
}

#[test]
fn exit_code_3_for_missing_file() {
    // Non-existent file triggers NotFound I/O error (exit code 3)
    stringy()
        .arg("this_file_also_does_not_exist.bin")
        .assert()
        .failure()
        .code(3);
}

#[test]
fn invalid_tag_exits_code_2() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--only-tags", "bad_tag"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::is_empty().not());
}

#[test]
fn comma_syntax_tag_exits_code_2() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--only-tags", "url,ipv4"])
        .assert()
        .failure()
        .code(2);
}

#[test]
fn repeatable_tag_flags_accepted() {
    stringy()
        .args([
            "tests/fixtures/test_binary_elf",
            "--only-tags",
            "url",
            "--only-tags",
            "ipv4",
        ])
        .assert()
        .success();
}
