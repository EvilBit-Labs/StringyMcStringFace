use assert_cmd::{Command, cargo_bin_cmd};
use predicates::prelude::*;

fn stringy() -> Command {
    cargo_bin_cmd!("stringy")
}

#[test]
fn error_unsupported_format_lists_supported() {
    // Feed a plain text file -- not ELF/PE/Mach-O
    stringy()
        .arg("Cargo.toml")
        .assert()
        .failure()
        .stderr(predicate::str::contains("ELF"))
        .stderr(predicate::str::contains("PE"))
        .stderr(predicate::str::contains("Mach-O"));
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
    // Cargo.toml is not a valid binary format
    stringy().arg("Cargo.toml").assert().failure().code(1);
}
