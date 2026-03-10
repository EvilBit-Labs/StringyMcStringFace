use assert_cmd::{Command, cargo_bin_cmd};
use predicates::prelude::*;

fn stringy() -> Command {
    cargo_bin_cmd!("stringy")
}

#[test]
fn unknown_format_falls_back_to_raw_scan() {
    // Feed a plain text file -- not ELF/PE/Mach-O.
    // The pipeline gracefully falls back to unstructured byte scanning.
    stringy()
        .arg("Cargo.toml")
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
        .stderr(predicate::str::contains("this_file_does_not_exist.bin"));
}

#[test]
fn exit_code_2_for_clap_errors() {
    // Missing required argument
    stringy().assert().failure().code(2);
}

#[test]
fn exit_code_1_for_runtime_errors() {
    // Non-existent file triggers a runtime I/O error
    stringy()
        .arg("this_file_also_does_not_exist.bin")
        .assert()
        .failure()
        .code(1);
}
