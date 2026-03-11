use assert_cmd::{Command, cargo_bin_cmd};
use predicates::prelude::*;

fn stringy() -> Command {
    cargo_bin_cmd!("stringy")
}

// ---------------------------------------------------------------------------
// Flow 8 -- Error Paths (argument conflicts, validation failures)
// ---------------------------------------------------------------------------

#[test]
fn flow8_invalid_tag_value_exit_2() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--only-tags", "bad_tag"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("invalid"));
}

#[test]
fn flow8_invalid_notag_value_exit_2() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--no-tags", "bad_tag"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("invalid"));
}

#[test]
fn flow8_comma_tag_syntax_rejected_exit_2() {
    // clap rejects "url,ipv4" as a single unknown tag value
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--only-tags", "url,ipv4"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("invalid"));
}

// --json + --yara conflict is covered in integration_cli.rs
// (cli_json_and_yara_conflict) with explicit exit code 2 assertion.

// NOTE: --summary + --json conflict is covered in integration_flows_6_7.rs
// (flow7_summary_conflicts_with_json_exit_2).

#[test]
fn flow8_raw_only_tags_conflict_exit_2() {
    stringy()
        .args([
            "tests/fixtures/test_binary_elf",
            "--raw",
            "--only-tags",
            "url",
        ])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn flow8_raw_notags_conflict_exit_2() {
    stringy()
        .args([
            "tests/fixtures/test_binary_elf",
            "--raw",
            "--no-tags",
            "url",
        ])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn flow8_raw_top_conflict_exit_2() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--raw", "--top", "5"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn flow8_raw_debug_conflict_exit_2() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--raw", "--debug"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn flow8_raw_yara_conflict_exit_2() {
    // Also covered in integration_cli.rs (cli_raw_conflicts_with_yara),
    // but included here for completeness of the Flow 8 error matrix.
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--raw", "--yara"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
}

// NOTE: --summary non-TTY exit 1 is covered in integration_flows_6_7.rs
// (flow7_summary_non_tty_exit_1).

#[test]
fn flow8_tag_overlap_exit_2() {
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
        .stderr(predicate::str::contains("--only-tags and --no-tags"));
}
