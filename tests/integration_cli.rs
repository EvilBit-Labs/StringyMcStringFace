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
        .args(["tests/fixtures/test_binary_elf", "--format", "json"])
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
}

#[test]
fn cli_min_length_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_stringy"))
        .args(["tests/fixtures/test_binary_elf", "-l", "20"])
        .output()
        .expect("Failed to execute stringy");

    assert!(output.status.success(), "Exit code: {}", output.status);
}
