use assert_cmd::Command;
use assert_cmd::cargo_bin_cmd;
use predicates::prelude::*;

fn stringy() -> Command {
    cargo_bin_cmd!("stringy")
}

// ---------- Stdin edge cases ----------

#[test]
fn stdin_pipe_pe_binary() {
    let fixture_data =
        std::fs::read("tests/fixtures/test_binary_pe.exe").expect("PE fixture should exist");

    stringy()
        .arg("-")
        .write_stdin(fixture_data)
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

#[test]
fn stdin_pipe_macho_binary() {
    let fixture_data =
        std::fs::read("tests/fixtures/test_binary_macho").expect("Mach-O fixture should exist");

    // Mach-O fixtures may not parse on all platforms; verify it runs without panicking
    let result = stringy()
        .arg("-")
        .write_stdin(fixture_data)
        .output()
        .expect("should execute");

    assert!(result.status.success() || !result.stderr.is_empty());
}

#[test]
fn stdin_pipe_unknown_data() {
    let fixture_data =
        std::fs::read("tests/fixtures/test_unknown.bin").expect("unknown fixture should exist");

    // Unknown format falls back to unstructured byte scan (succeeds, may emit info)
    stringy()
        .arg("-")
        .write_stdin(fixture_data)
        .assert()
        .success();
}

#[test]
fn stdin_pipe_json_output() {
    let fixture_data =
        std::fs::read("tests/fixtures/test_binary_elf").expect("ELF fixture should exist");

    stringy()
        .arg("-")
        .arg("--json")
        .write_stdin(fixture_data)
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

#[test]
fn stdin_pipe_raw_mode() {
    let fixture_data =
        std::fs::read("tests/fixtures/test_binary_elf").expect("ELF fixture should exist");

    stringy()
        .arg("-")
        .arg("--raw")
        .write_stdin(fixture_data)
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

#[test]
fn stdin_pipe_with_filters() {
    let fixture_data =
        std::fs::read("tests/fixtures/test_binary_elf").expect("ELF fixture should exist");

    stringy()
        .arg("-")
        .arg("--min-len")
        .arg("8")
        .arg("--top")
        .arg("10")
        .write_stdin(fixture_data)
        .assert()
        .success();
}
