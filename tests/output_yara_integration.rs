//! Integration tests for YARA output formatter.
//!
//! Uses insta snapshots to verify output format consistency.

use insta::assert_snapshot;
use stringy::output::{OutputFormat, OutputMetadata, format_yara};
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

fn make_metadata(binary_name: &str, count: usize) -> OutputMetadata {
    OutputMetadata::new(binary_name.to_string(), OutputFormat::Yara, count, count)
        .with_generated_at("0".to_string())
}

#[test]
fn test_yara_empty_strings() {
    let output = format_yara(&[], &make_metadata("empty.bin", 0)).unwrap();
    assert_snapshot!(output);
}

#[test]
fn test_yara_single_string() {
    let strings = vec![make_string("GetProcAddress").with_tags(vec![Tag::Import])];
    let output = format_yara(&strings, &make_metadata("single.exe", 1)).unwrap();
    assert_snapshot!(output);
}

#[test]
fn test_yara_multiple_strings_same_tag() {
    let strings = vec![
        make_string("alpha").with_tags(vec![Tag::Url]),
        make_string("beta").with_tags(vec![Tag::Url]),
    ];
    let output = format_yara(&strings, &make_metadata("same-tag.exe", 2)).unwrap();
    assert_snapshot!(output);
}

#[test]
fn test_yara_multiple_strings_different_tags() {
    let strings = vec![
        make_string("https://example.com").with_tags(vec![Tag::Url]),
        make_string("example.com").with_tags(vec![Tag::Domain]),
        make_string("192.168.1.1").with_tags(vec![Tag::IPv4]),
    ];
    let output = format_yara(&strings, &make_metadata("diff-tag.exe", 3)).unwrap();
    assert_snapshot!(output);
}

#[test]
fn test_yara_no_tags() {
    let strings = vec![make_string("no-tag"), make_string("still-no-tag")];
    let output = format_yara(&strings, &make_metadata("untagged.exe", 2)).unwrap();
    assert_snapshot!(output);
}

#[test]
fn test_yara_long_strings_skipped() {
    let long_text = "a".repeat(201);
    let strings = vec![make_string(&long_text).with_tags(vec![Tag::Url])];
    let output = format_yara(&strings, &make_metadata("long.exe", 1)).unwrap();
    assert_snapshot!(output);
}

#[test]
fn test_yara_special_characters() {
    let strings = vec![
        make_string("quote\" backslash\\ line\n tab\t")
            .with_tags(vec![Tag::FilePath])
            .with_score(10),
    ];
    let output = format_yara(&strings, &make_metadata("special.exe", 1)).unwrap();
    assert_snapshot!(output);
}

#[test]
fn test_yara_binary_name_sanitization() {
    let strings = vec![make_string("alpha")];
    let output = format_yara(&strings, &make_metadata("weird name.exe", 1)).unwrap();
    assert_snapshot!(output);
}

#[test]
fn test_yara_encoding_modifiers() {
    let ascii = make_string("ascii");
    let utf16 = FoundString::new(
        "wide".to_string(),
        Encoding::Utf16Le,
        0x2000,
        8,
        StringSource::SectionData,
    )
    .with_tags(vec![Tag::Resource]);

    let output = format_yara(&[ascii, utf16], &make_metadata("enc.exe", 2)).unwrap();
    assert_snapshot!(output);
}

#[test]
fn test_yara_mixed_encodings() {
    let strings = vec![
        FoundString::new(
            "ascii".to_string(),
            Encoding::Ascii,
            0x1000,
            5,
            StringSource::SectionData,
        )
        .with_tags(vec![Tag::Url]),
        FoundString::new(
            "utf8".to_string(),
            Encoding::Utf8,
            0x2000,
            4,
            StringSource::SectionData,
        )
        .with_tags(vec![Tag::Domain]),
        FoundString::new(
            "utf16".to_string(),
            Encoding::Utf16Be,
            0x3000,
            10,
            StringSource::SectionData,
        )
        .with_tags(vec![Tag::Resource]),
    ];
    let output = format_yara(&strings, &make_metadata("mixed.exe", 3)).unwrap();
    assert_snapshot!(output);
}

#[test]
fn test_yara_high_scores() {
    let strings = vec![
        make_string("critical")
            .with_tags(vec![Tag::Url])
            .with_score(9999),
        make_string("low")
            .with_tags(vec![Tag::Domain])
            .with_score(-10),
    ];
    let output = format_yara(&strings, &make_metadata("scores.exe", 2)).unwrap();
    assert_snapshot!(output);
}

#[test]
fn test_yara_all_tag_types() {
    let strings = vec![
        make_string("url").with_tags(vec![Tag::Url]),
        make_string("domain").with_tags(vec![Tag::Domain]),
        make_string("ipv4").with_tags(vec![Tag::IPv4]),
        make_string("ipv6").with_tags(vec![Tag::IPv6]),
        make_string("path").with_tags(vec![Tag::FilePath]),
        make_string("reg").with_tags(vec![Tag::RegistryPath]),
        make_string("guid").with_tags(vec![Tag::Guid]),
        make_string("email").with_tags(vec![Tag::Email]),
        make_string("b64").with_tags(vec![Tag::Base64]),
        make_string("fmt").with_tags(vec![Tag::FormatString]),
        make_string("agent").with_tags(vec![Tag::UserAgent]),
        make_string("demangled").with_tags(vec![Tag::DemangledSymbol]),
        make_string("import").with_tags(vec![Tag::Import]),
        make_string("export").with_tags(vec![Tag::Export]),
        make_string("version").with_tags(vec![Tag::Version]),
        make_string("manifest").with_tags(vec![Tag::Manifest]),
        make_string("resource").with_tags(vec![Tag::Resource]),
        make_string("dylib").with_tags(vec![Tag::DylibPath]),
        make_string("rpath").with_tags(vec![Tag::Rpath]),
        make_string("rpathvar").with_tags(vec![Tag::RpathVariable]),
        make_string("framework").with_tags(vec![Tag::FrameworkPath]),
    ];
    let output = format_yara(&strings, &make_metadata("tags.exe", strings.len())).unwrap();
    assert_snapshot!(output);
}

#[test]
fn test_yara_unicode_in_strings() {
    let unicode = "\u{4E2D}\u{6587}\u{5B57}\u{7B26}";
    let strings = vec![make_string(unicode).with_tags(vec![Tag::Domain])];
    let output = format_yara(&strings, &make_metadata("unicode.exe", 1)).unwrap();
    assert_snapshot!(output);
}

#[test]
fn test_yara_edge_case_names() {
    let strings = vec![make_string("alpha")];
    let output_numbers = format_yara(&strings, &make_metadata("12345", 1)).unwrap();
    let output_special = format_yara(&strings, &make_metadata("#$%", 1)).unwrap();
    assert_snapshot!(output_numbers);
    assert_snapshot!(output_special);
}
