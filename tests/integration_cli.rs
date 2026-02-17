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
