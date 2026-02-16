//! Integration tests for JSON output formatter.
//!
//! Uses insta snapshots to verify output format consistency.

use insta::assert_snapshot;
use serde_json::Value;
use stringy::output::{OutputFormat, OutputMetadata, format_json};
use stringy::types::{Encoding, FoundString, StringSource, Tag};

fn make_string(text: &str) -> FoundString {
    FoundString::new(
        text.to_string(),
        Encoding::Ascii,
        0x1000,
        text.len() as u32,
        StringSource::SectionData,
    )
}

fn make_metadata(count: usize) -> OutputMetadata {
    OutputMetadata::new(
        "test_binary.exe".to_string(),
        OutputFormat::Json,
        count,
        count,
    )
}

fn parse_line(line: &str) -> Value {
    serde_json::from_str(line).expect("JSON should parse")
}

#[test]
fn test_json_empty_strings() {
    let output = format_json(&[], &make_metadata(0)).unwrap();
    assert_snapshot!(output);
}

#[test]
fn test_json_single_string() {
    let strings = vec![make_string("GetProcAddress")];
    let output = format_json(&strings, &make_metadata(1)).unwrap();
    assert_snapshot!(output);
}

#[test]
fn test_json_multiple_strings() {
    let strings = vec![make_string("one"), make_string("two"), make_string("three")];
    let output = format_json(&strings, &make_metadata(3)).unwrap();
    assert_snapshot!(output);
}

#[test]
fn test_json_all_fields_populated() {
    let strings = vec![
        make_string("fielded")
            .with_original_text("original".to_string())
            .with_section(".rdata".to_string())
            .with_rva(0x2000)
            .with_tags(vec![Tag::Url])
            .with_score(150)
            .with_section_weight(20)
            .with_semantic_boost(30)
            .with_noise_penalty(-10)
            .with_confidence(0.9),
    ];
    let output = format_json(&strings, &make_metadata(1)).unwrap();
    assert_snapshot!(output);
}

#[test]
fn test_json_optional_fields_none() {
    let strings = vec![make_string("no-optional")];
    let output = format_json(&strings, &make_metadata(1)).unwrap();
    assert_snapshot!(output);
}

#[test]
fn test_json_special_characters() {
    let strings = vec![make_string("quote\" backslash\\ line\n tab\t")];
    let output = format_json(&strings, &make_metadata(1)).unwrap();
    assert_snapshot!(output);
}

#[test]
fn test_json_all_encodings() {
    let strings = vec![
        FoundString::new(
            "ASCII".to_string(),
            Encoding::Ascii,
            0,
            5,
            StringSource::SectionData,
        ),
        FoundString::new(
            "UTF8".to_string(),
            Encoding::Utf8,
            1,
            4,
            StringSource::SectionData,
        ),
        FoundString::new(
            "UTF16LE".to_string(),
            Encoding::Utf16Le,
            2,
            14,
            StringSource::SectionData,
        ),
        FoundString::new(
            "UTF16BE".to_string(),
            Encoding::Utf16Be,
            3,
            14,
            StringSource::SectionData,
        ),
    ];
    let output = format_json(&strings, &make_metadata(4)).unwrap();
    assert_snapshot!(output);
}

#[test]
fn test_json_all_tags() {
    let tags = vec![
        Tag::Url,
        Tag::Domain,
        Tag::IPv4,
        Tag::IPv6,
        Tag::FilePath,
        Tag::RegistryPath,
        Tag::Guid,
        Tag::Email,
        Tag::Base64,
        Tag::FormatString,
        Tag::UserAgent,
        Tag::DemangledSymbol,
        Tag::Import,
        Tag::Export,
        Tag::Version,
        Tag::Manifest,
        Tag::Resource,
        Tag::DylibPath,
        Tag::Rpath,
        Tag::RpathVariable,
        Tag::FrameworkPath,
    ];
    let strings = vec![make_string("tagged").with_tags(tags)];
    let output = format_json(&strings, &make_metadata(1)).unwrap();
    assert_snapshot!(output);
}

#[test]
fn test_json_all_sources() {
    let strings = vec![
        FoundString::new(
            "sec".to_string(),
            Encoding::Ascii,
            0,
            3,
            StringSource::SectionData,
        ),
        FoundString::new(
            "imp".to_string(),
            Encoding::Ascii,
            1,
            3,
            StringSource::ImportName,
        ),
        FoundString::new(
            "exp".to_string(),
            Encoding::Ascii,
            2,
            3,
            StringSource::ExportName,
        ),
        FoundString::new(
            "res".to_string(),
            Encoding::Ascii,
            3,
            3,
            StringSource::ResourceString,
        ),
        FoundString::new(
            "lc".to_string(),
            Encoding::Ascii,
            4,
            2,
            StringSource::LoadCommand,
        ),
        FoundString::new(
            "dbg".to_string(),
            Encoding::Ascii,
            5,
            3,
            StringSource::DebugInfo,
        ),
    ];
    let output = format_json(&strings, &make_metadata(6)).unwrap();
    assert_snapshot!(output);
}

#[test]
fn test_json_debug_fields() {
    let strings = vec![
        make_string("debug")
            .with_section_weight(10)
            .with_semantic_boost(5)
            .with_noise_penalty(-3),
    ];
    let output = format_json(&strings, &make_metadata(1)).unwrap();
    assert_snapshot!(output);
}

#[test]
fn test_json_original_text() {
    let strings = vec![make_string("demangled").with_original_text("_ZN".to_string())];
    let output = format_json(&strings, &make_metadata(1)).unwrap();
    assert_snapshot!(output);
}

#[test]
fn test_json_long_strings() {
    let long_text = "a".repeat(300);
    let strings = vec![make_string(&long_text).with_score(5)];
    let output = format_json(&strings, &make_metadata(1)).unwrap();
    assert_snapshot!(output);
}

#[test]
fn test_json_unicode_content() {
    // Use UTF-8 encoding for non-ASCII content
    let unicode = "\u{4E2D}\u{6587}\u{5B57}\u{7B26}";
    let strings = vec![FoundString::new(
        unicode.to_string(),
        Encoding::Utf8,
        0x1000,
        unicode.len() as u32,
        StringSource::SectionData,
    )];
    let output = format_json(&strings, &make_metadata(1)).unwrap();
    assert_snapshot!(output);
}

#[test]
fn test_json_parse_roundtrip() {
    let strings = vec![
        make_string("roundtrip")
            .with_tags(vec![Tag::Url])
            .with_score(10),
        make_string("another")
            .with_tags(vec![Tag::Domain])
            .with_score(20),
    ];
    let output = format_json(&strings, &make_metadata(2)).unwrap();
    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(lines.len(), 2);

    let first: FoundString = serde_json::from_str(lines[0]).expect("should deserialize");
    let second: FoundString = serde_json::from_str(lines[1]).expect("should deserialize");

    assert_eq!(first.text, "roundtrip");
    assert_eq!(second.text, "another");
}

#[test]
fn test_json_optional_fields_excluded() {
    let strings = vec![make_string("no-optional")];
    let output = format_json(&strings, &make_metadata(1)).unwrap();
    let value = parse_line(&output);
    assert!(value.get("original_text").is_none());
    assert!(value.get("section_weight").is_none());
    assert!(value.get("semantic_boost").is_none());
    assert!(value.get("noise_penalty").is_none());
}
