use std::process::Command;

#[test]
fn cli_accepts_binary_file() {
    let output = Command::new(env!("CARGO_BIN_EXE_stringy"))
        .arg("tests/fixtures/test_binary_elf")
        .output()
        .expect("Failed to execute stringy");

    assert!(output.status.success(), "Exit code: {}", output.status);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("coming soon"),
        "CLI still shows stub message"
    );
    assert!(!stdout.is_empty(), "No output produced");
}

#[test]
fn cli_json_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_stringy"))
        .args(["tests/fixtures/test_binary_elf", "--json"])
        .output()
        .expect("Failed to execute stringy");

    assert!(output.status.success(), "Exit code: {}", output.status);
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines().filter(|l| !l.is_empty()) {
        serde_json::from_str::<serde_json::Value>(line).expect("Each line should be valid JSON");
    }
}

#[test]
fn cli_invalid_file() {
    let output = Command::new(env!("CARGO_BIN_EXE_stringy"))
        .arg("nonexistent_file")
        .output()
        .expect("Failed to execute stringy");

    assert!(!output.status.success(), "Should fail for missing file");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.trim().is_empty(),
        "Should produce an error message on stderr"
    );
}

#[test]
fn cli_min_length_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_stringy"))
        .args(["tests/fixtures/test_binary_elf", "--min-len", "20"])
        .output()
        .expect("Failed to execute stringy");

    assert!(output.status.success(), "Exit code: {}", output.status);
    // With min_length=20, output should differ from the default (min_length=4)
    let default_output = Command::new(env!("CARGO_BIN_EXE_stringy"))
        .arg("tests/fixtures/test_binary_elf")
        .output()
        .expect("Failed to execute stringy");
    assert!(
        default_output.status.success(),
        "Default run should succeed: {}",
        default_output.status
    );

    let filtered_stdout = String::from_utf8_lossy(&output.stdout);
    let default_stdout = String::from_utf8_lossy(&default_output.stdout);
    // Higher min_length should produce equal or fewer output lines
    assert!(
        filtered_stdout.lines().count() <= default_stdout.lines().count(),
        "min_length=20 should produce fewer or equal lines than default"
    );
}
