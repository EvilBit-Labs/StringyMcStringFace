//! Integration tests for the convenience flags --imports / --exports /
//! --symbols (issue #208). These are shorthands for the corresponding
//! `--only-tags` values and must stay behaviorally equivalent to them.
//!
//! Fixture note: `test_binary_elf` has import=81, export=9, demangled=0 rows.
//! The equivalence tests run against it because both import and export are
//! non-empty there, so an accidental tag mis-mapping (e.g. --symbols routing to
//! Import) is caught. No fixture currently yields demangled-tagged rows, so the
//! --symbols equivalence is additionally guarded by asserting it does not alias
//! --imports/--exports (which do have rows on this fixture).

use assert_cmd::{Command, cargo_bin_cmd};
use predicates::prelude::*;

const ELF: &str = "tests/fixtures/test_binary_elf";

fn stringy() -> Command {
    cargo_bin_cmd!("stringy")
}

/// Sorted, non-empty stdout lines so equivalence checks are robust to any
/// run-to-run ordering nondeterminism in extraction or score tie-breaking.
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

/// Run `stringy <ELF> --json <extra>` and return its sorted output rows.
fn elf_rows(extra: &[&str]) -> Vec<String> {
    let mut args = vec![ELF, "--json"];
    args.extend_from_slice(extra);
    let output = stringy().args(&args).output().expect("stringy should run");
    assert!(
        output.status.success(),
        "stringy should succeed for args {extra:?}"
    );
    sorted_stdout_lines(&output.stdout)
}

#[test]
fn cli_imports_equivalent_to_only_tags_import() {
    // R1: --imports behaves exactly like --only-tags import.
    let flag = elf_rows(&["--imports"]);
    let tag = elf_rows(&["--only-tags", "import"]);
    assert!(!flag.is_empty(), "ELF fixture should yield import rows");
    assert_eq!(flag, tag, "--imports must equal --only-tags import");
}

#[test]
fn cli_exports_equivalent_to_only_tags_export() {
    // R1: --exports behaves exactly like --only-tags export.
    let flag = elf_rows(&["--exports"]);
    let tag = elf_rows(&["--only-tags", "export"]);
    assert!(!flag.is_empty(), "ELF fixture should yield export rows");
    assert_eq!(flag, tag, "--exports must equal --only-tags export");
}

#[test]
fn cli_symbols_maps_to_demangled_only() {
    // R2: --symbols maps to DemangledSymbol only. No fixture has demangled rows,
    // so equivalence to --only-tags demangled is a (currently empty) match; the
    // load-bearing guard is that --symbols does not alias --imports/--exports,
    // both of which DO have rows on the ELF fixture.
    let symbols = elf_rows(&["--symbols"]);
    let demangled = elf_rows(&["--only-tags", "demangled"]);
    assert_eq!(
        symbols, demangled,
        "--symbols must equal --only-tags demangled"
    );
    assert_ne!(
        symbols,
        elf_rows(&["--imports"]),
        "--symbols must not alias --imports"
    );
    assert_ne!(
        symbols,
        elf_rows(&["--exports"]),
        "--symbols must not alias --exports"
    );
}

#[test]
fn cli_convenience_flags_combine_as_union() {
    // AE1 / R3: --imports --exports is the OR-union, matching repeated --only-tags.
    let flags = elf_rows(&["--imports", "--exports"]);
    let tags = elf_rows(&["--only-tags", "import", "--only-tags", "export"]);
    assert!(!flags.is_empty(), "union should yield import+export rows");
    assert_eq!(
        flags, tags,
        "--imports --exports must equal repeated --only-tags import export"
    );
}

#[test]
fn cli_convenience_flags_conflict_with_only_tags_and_raw() {
    // AE2 / AE3 / R4: every (flag x conflict-target) pair is rejected by clap.
    for flag in ["--imports", "--exports", "--symbols"] {
        for conflict in [["--only-tags", "url"].as_slice(), ["--raw"].as_slice()] {
            let mut args = vec![ELF, flag];
            args.extend_from_slice(conflict);
            stringy()
                .args(&args)
                .assert()
                .failure()
                .code(2)
                .stderr(predicate::str::contains("cannot be used with"));
        }
    }
}

#[test]
fn cli_convenience_flags_no_tags_contradiction_rejected() {
    // AE4 / R5: a resolved include tag also excluded via --no-tags fails validation.
    for (flag, tag) in [
        ("--imports", "import"),
        ("--exports", "export"),
        ("--symbols", "demangled"),
    ] {
        stringy()
            .args([ELF, flag, "--no-tags", tag])
            .assert()
            .failure()
            .stderr(predicate::str::contains("conflicting tag filters"));
    }
}

#[test]
fn cli_convenience_flags_no_tags_compatible() {
    // AE5 / R5: each convenience flag composes with a non-overlapping --no-tags.
    for flag in ["--imports", "--exports", "--symbols"] {
        stringy()
            .args([ELF, flag, "--no-tags", "version"])
            .assert()
            .success();
    }
}

#[test]
fn cli_help_lists_convenience_flags() {
    // R6: help lists the three flags and each one points to --only-tags.
    stringy()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--imports"))
        .stdout(predicate::str::contains("--exports"))
        .stdout(predicate::str::contains("--symbols"))
        .stdout(predicate::str::contains("Shorthand for --only-tags import"))
        .stdout(predicate::str::contains("Shorthand for --only-tags export"))
        .stdout(predicate::str::contains(
            "Shorthand for --only-tags demangled",
        ));
}
