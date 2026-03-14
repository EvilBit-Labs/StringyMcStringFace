use assert_cmd::cargo_bin_cmd;

fn stringy() -> assert_cmd::Command {
    cargo_bin_cmd!("stringy")
}

#[test]
fn flow5_yara_long_string_deterministic_skip() {
    // Create a temporary fixture containing a string longer than 200 characters
    // to deterministically test the YARA long-string skip behavior.
    use std::io::Write;

    // Build a varied (non-homogeneous) string > 200 chars so the extractor
    // does not filter it as noise. Repeating a 10-char pattern 26 times = 260.
    let long_string: String = "ABCDEFGHIJ".repeat(26);
    assert!(long_string.len() > 200);

    let mut fixture = tempfile::NamedTempFile::new().expect("create temp file");

    // Write a minimal payload: the long string surrounded by null bytes
    // so the ASCII extractor can delimit it.
    let mut content = Vec::new();
    content.extend_from_slice(&[0u8; 16]);
    content.extend_from_slice(long_string.as_bytes());
    content.push(0u8);
    content.extend_from_slice(&[0u8; 16]);
    fixture.write_all(&content).expect("write fixture");
    fixture.flush().expect("flush fixture");

    let assert = stringy()
        .args([fixture.path().to_str().unwrap(), "--yara"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    // The output must contain the skipped comment for the long string
    assert!(
        stdout.contains("skipped (length > 200 chars)"),
        "YARA output must contain a skipped comment for strings > 200 chars"
    );

    // The full long literal must NOT appear in the YARA strings: block
    assert!(
        !stdout.contains(&long_string),
        "YARA output must not emit the full long string literal"
    );
}
