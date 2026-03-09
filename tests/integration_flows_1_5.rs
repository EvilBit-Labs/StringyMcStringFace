use assert_cmd::{Command, cargo_bin_cmd};
use predicates::prelude::*;
use serde_json::Value;
use stringy::output::{OutputFormat, OutputMetadata, format_table_with_mode};
use stringy::types::{Encoding, FoundString, StringSource, Tag};

fn stringy() -> Command {
    cargo_bin_cmd!("stringy")
}

// ---------------------------------------------------------------------------
// Flow 1 -- Quick Analysis
// ---------------------------------------------------------------------------

#[test]
fn flow1_debug_json_has_display_score_in_range() {
    let assert = stringy()
        .args(["tests/fixtures/test_binary_elf", "--json", "--debug"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert!(!lines.is_empty(), "expected at least one JSON line");

    for line in &lines {
        let v: Value = serde_json::from_str(line).expect("valid JSON");
        let score = v["display_score"]
            .as_i64()
            .expect("display_score should be present in debug mode");
        assert!(
            (0..=100).contains(&score),
            "display_score {score} out of [0, 100]"
        );
    }
}

/// Shared assertions for raw JSON mode: score==0, empty tags, no display_score,
/// and monotonically non-decreasing offsets (extraction order preserved).
fn assert_raw_json_contract(stdout: &str) {
    let parsed: Vec<Value> = stdout
        .lines()
        .filter(|l| !l.is_empty())
        .map(|line| serde_json::from_str(line).expect("valid JSON"))
        .collect();
    assert!(!parsed.is_empty(), "expected at least one JSON line");

    let mut prev_offset: Option<u64> = None;

    for v in &parsed {
        // Raw mode must not have display_score (no ranking/normalization)
        assert!(
            v["display_score"].is_null(),
            "raw mode should not have display_score"
        );
        assert!(v["text"].as_str().is_some(), "each result must have text");

        // Raw mode bypasses classify/rank/normalize -- score must be exactly 0
        assert_eq!(
            v["score"].as_i64(),
            Some(0i64),
            "raw score must be 0, got: {:?}",
            v["score"]
        );

        // Raw mode skips classification -- tags must be an empty array
        let tags = v["tags"]
            .as_array()
            .expect("tags must be an array in raw mode");
        assert!(tags.is_empty(), "raw tags must be empty, got: {tags:?}");

        // Offsets must be present and monotonically non-decreasing
        // (extraction scan order preserved)
        let offset = v["offset"].as_u64().expect("offset field must be present");
        if let Some(prev) = prev_offset {
            assert!(
                offset >= prev,
                "offsets must be non-decreasing: {offset} < {prev}"
            );
        }
        prev_offset = Some(offset);
    }

    assert!(
        parsed.len() > 1,
        "need multiple lines to verify raw contract"
    );
}

#[test]
fn flow1_raw_json_valid_and_offset_ordered() {
    let assert = stringy()
        .args(["tests/fixtures/test_binary_elf", "--raw", "--json"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert_raw_json_contract(&stdout);
}

#[test]
fn flow1_piped_output_no_score_header() {
    // In non-TTY (piped) mode the plain-text output should not contain a
    // "Score" table header.
    stringy()
        .arg("tests/fixtures/test_binary_elf")
        .assert()
        .success()
        .stdout(predicate::str::contains("Score").not());
}

#[test]
fn flow1_raw_piped_output_no_score_header() {
    // Raw mode plain-text output should also not contain a "Score" header.
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--raw"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Score").not());
}

#[test]
fn flow1_top3_json_snapshot() {
    let assert = stringy()
        .args(["tests/fixtures/test_binary_elf", "--top", "3", "--json"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    insta::assert_snapshot!("flow1_top3_json", stdout);
}

#[test]
fn flow1_tty_table_headers_snapshot() {
    // Verify TTY table output contains the required column headers:
    // String, Tags, Score, Section. Uses the public format_table_with_mode API
    // with is_tty=true to render the same table the CLI would show on a terminal.
    let strings = vec![
        FoundString::new(
            "https://github.com/EvilBit-Labs/Stringy".to_string(),
            Encoding::Ascii,
            0x2008,
            39,
            StringSource::SectionData,
        )
        .with_tags(vec![Tag::Url])
        .with_score(1050)
        .with_section(".rodata".to_string()),
        FoundString::new(
            "Project: %s".to_string(),
            Encoding::Ascii,
            0x204C,
            11,
            StringSource::SectionData,
        )
        .with_tags(vec![Tag::FormatString])
        .with_score(1002)
        .with_section(".rodata".to_string()),
        FoundString::new(
            "Helper called".to_string(),
            Encoding::Ascii,
            0x2030,
            13,
            StringSource::SectionData,
        )
        .with_score(993)
        .with_section(".rodata".to_string()),
    ];
    let metadata = OutputMetadata::new(
        "test_binary_elf".to_string(),
        OutputFormat::Table,
        strings.len(),
        strings.len(),
    );
    let result = format_table_with_mode(&strings, &metadata, true).unwrap();

    // Assert the required column headers are present
    assert!(
        result.contains("String"),
        "TTY table must have 'String' header"
    );
    assert!(result.contains("Tags"), "TTY table must have 'Tags' header");
    assert!(
        result.contains("Score"),
        "TTY table must have 'Score' header"
    );
    assert!(
        result.contains("Section"),
        "TTY table must have 'Section' header"
    );

    // Snapshot the full table layout to catch header/column regressions
    insta::assert_snapshot!("flow1_tty_table_headers", result);
}

// ---------------------------------------------------------------------------
// Flow 2 -- Filtered Analysis
// ---------------------------------------------------------------------------

#[test]
fn flow2_only_tags_url_ipv4_returns_only_those_tags() {
    let assert = stringy()
        .args([
            "tests/fixtures/test_binary_elf",
            "--only-tags",
            "url",
            "--only-tags",
            "ipv4",
            "--json",
        ])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();

    // The fixture has at least one URL
    assert!(
        !lines.is_empty(),
        "expected at least one result for url|ipv4"
    );

    let allowed: &[&str] = &["Url", "ipv4"];
    for line in &lines {
        let v: Value = serde_json::from_str(line).expect("valid JSON");
        let tags = v["tags"].as_array().expect("tags array present");
        let has_match = tags.iter().any(|t| {
            let s = t.as_str().unwrap_or("");
            allowed.iter().any(|a| a.eq_ignore_ascii_case(s))
        });
        assert!(
            has_match,
            "every result must have at least one of url/ipv4, got: {tags:?}"
        );
    }
}

#[test]
fn flow2_enc_utf16_filters_encoding() {
    let assert = stringy()
        .args(["tests/fixtures/test_binary_elf", "--enc", "utf16", "--json"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    // The ELF fixture has no UTF-16 strings, so output should be empty.
    // If it ever gains UTF-16 strings, verify encodings.
    if !stdout.trim().is_empty() {
        for line in stdout.lines().filter(|l| !l.is_empty()) {
            let v: Value = serde_json::from_str(line).expect("valid JSON");
            let enc = v["encoding"].as_str().unwrap_or("");
            assert!(
                enc.starts_with("Utf16"),
                "expected Utf16* encoding, got: {enc}"
            );
        }
    }
}

#[test]
fn flow2_min_len_excludes_short_strings() {
    let assert = stringy()
        .args([
            "tests/fixtures/test_binary_elf",
            "--min-len",
            "20",
            "--json",
        ])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert!(
        !lines.is_empty(),
        "expected at least one result with len>=20"
    );

    for line in &lines {
        let v: Value = serde_json::from_str(line).expect("valid JSON");
        let len = v["length"].as_u64().unwrap_or(0);
        assert!(len >= 20, "string length {len} is below --min-len 20");
    }
}

// ---------------------------------------------------------------------------
// Flow 3 -- Top N Results
// ---------------------------------------------------------------------------

#[test]
fn flow3_top_5_returns_exactly_5() {
    let assert = stringy()
        .args(["tests/fixtures/test_binary_elf", "--top", "5", "--json"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let count = stdout.lines().filter(|l| !l.is_empty()).count();
    assert_eq!(count, 5, "expected exactly 5 results from --top 5");
}

#[test]
fn flow3_top_5_with_only_tags_url() {
    // Baseline: get all URL-filtered results (no --top) to establish the
    // correct filtered ordering.
    let baseline_assert = stringy()
        .args([
            "tests/fixtures/test_binary_elf",
            "--only-tags",
            "url",
            "--json",
        ])
        .assert()
        .success();

    let baseline_stdout = String::from_utf8(baseline_assert.get_output().stdout.clone()).unwrap();
    let baseline_lines: Vec<&str> = baseline_stdout.lines().filter(|l| !l.is_empty()).collect();

    // Now run with --top 5 applied on top of the tag filter.
    let assert = stringy()
        .args([
            "tests/fixtures/test_binary_elf",
            "--only-tags",
            "url",
            "--top",
            "5",
            "--json",
        ])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();

    // Must return min(5, filtered_count) results
    let expected_count = baseline_lines.len().min(5);
    assert_eq!(
        lines.len(),
        expected_count,
        "--top 5 with --only-tags url should return min(5, filtered_count={}) results",
        baseline_lines.len()
    );

    // The top-N results must equal the first N entries from the filtered baseline
    for (i, (top_line, baseline_line)) in lines.iter().zip(baseline_lines.iter()).enumerate() {
        let top_v: Value = serde_json::from_str(top_line).expect("valid JSON");
        let base_v: Value = serde_json::from_str(baseline_line).expect("valid JSON");
        assert_eq!(
            top_v["text"], base_v["text"],
            "row {i}: --top result text must match baseline filtered order"
        );
        assert_eq!(
            top_v["score"], base_v["score"],
            "row {i}: --top result score must match baseline filtered order"
        );
    }

    // Every returned row must still have the Url tag
    for line in &lines {
        let v: Value = serde_json::from_str(line).expect("valid JSON");
        let tags = v["tags"].as_array().expect("tags array present");
        let has_url = tags
            .iter()
            .any(|t| t.as_str().unwrap_or("").eq_ignore_ascii_case("url"));
        assert!(
            has_url,
            "every result must have Url tag after --only-tags url"
        );
    }
}

// ---------------------------------------------------------------------------
// Flow 4 -- JSON Output
// ---------------------------------------------------------------------------

#[test]
fn flow4_every_line_is_valid_json_with_required_fields() {
    let assert = stringy()
        .args(["tests/fixtures/test_binary_elf", "--json"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let required_fields = [
        "text",
        "encoding",
        "offset",
        "section",
        "tags",
        "score",
        "source",
        "confidence",
        "length",
    ];

    for line in stdout.lines().filter(|l| !l.is_empty()) {
        let v: Value = serde_json::from_str(line).expect("each line must be valid JSON");
        for field in &required_fields {
            assert!(
                !v[field].is_null() || *field == "section",
                "missing required field '{field}' in: {line}"
            );
        }
        // section may be null for imports/exports, but the key must exist
        assert!(
            v.as_object().unwrap().contains_key("section"),
            "JSON object must contain 'section' key"
        );
    }
}

#[test]
fn flow4_raw_json_valid_with_extraction_order() {
    // Delegates to shared raw-JSON contract assertions (score==0, empty tags,
    // no display_score, monotonic offsets). See assert_raw_json_contract().
    let assert = stringy()
        .args(["tests/fixtures/test_binary_elf", "--raw", "--json"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert_raw_json_contract(&stdout);
}

// ---------------------------------------------------------------------------
// Flow 5 -- YARA Rule Generation
// ---------------------------------------------------------------------------

#[test]
fn flow5_yara_output_has_rule_and_strings_block() {
    stringy()
        .args(["tests/fixtures/test_binary_elf", "--yara"])
        .assert()
        .success()
        .stdout(predicate::str::contains("rule "))
        .stdout(predicate::str::contains("strings:"));
}

#[test]
fn flow5_yara_skipped_comment_format() {
    let assert = stringy()
        .args(["tests/fixtures/test_binary_elf", "--yara"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    // If any line contains "// skipped", it must follow the expected format.
    for line in stdout.lines() {
        if line.contains("// skipped") {
            assert!(
                line.contains("skipped (length > 200 chars)"),
                "skipped comment must say 'length > 200 chars', got: {line}"
            );
        }
    }
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
