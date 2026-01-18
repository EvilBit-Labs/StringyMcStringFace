//! Integration tests for table output formatter.
//!
//! Uses insta snapshots to verify output format consistency.

use insta::assert_snapshot;
use stringy::output::{OutputFormat, OutputMetadata, format_table_with_mode};
use stringy::types::{Encoding, FoundString, StringSource, Tag};

/// Create a test FoundString with common defaults.
fn make_string(text: &str) -> FoundString {
    FoundString::new(
        text.to_string(),
        Encoding::Ascii,
        0x1000,
        text.len() as u32,
        StringSource::SectionData,
    )
}

/// Create OutputMetadata for tests.
fn make_metadata(count: usize) -> OutputMetadata {
    OutputMetadata::new(
        "test_binary.exe".to_string(),
        OutputFormat::Table,
        count,
        count,
    )
}

// TTY mode tests

#[test]
fn test_tty_empty_strings() {
    let result = format_table_with_mode(&[], &make_metadata(0), true).unwrap();
    assert_snapshot!(result);
}

#[test]
fn test_tty_single_string() {
    let strings = vec![make_string("GetProcAddress")];
    let result = format_table_with_mode(&strings, &make_metadata(1), true).unwrap();
    assert_snapshot!(result);
}

#[test]
fn test_tty_multiple_strings() {
    let strings = vec![
        make_string("https://malware.example.com/beacon")
            .with_tags(vec![Tag::Url])
            .with_score(150)
            .with_section(".rdata".to_string()),
        make_string("C:\\Windows\\System32\\cmd.exe")
            .with_tags(vec![Tag::FilePath])
            .with_score(120)
            .with_section(".data".to_string()),
        make_string("GetProcAddress")
            .with_tags(vec![Tag::Import])
            .with_score(80),
        make_string("192.168.1.100")
            .with_tags(vec![Tag::IPv4])
            .with_score(100)
            .with_section(".rodata".to_string()),
    ];
    let result = format_table_with_mode(&strings, &make_metadata(4), true).unwrap();
    assert_snapshot!(result);
}

#[test]
fn test_tty_strings_with_multiple_tags() {
    let strings = vec![
        make_string("http://evil.com/download.exe")
            .with_tags(vec![Tag::Url, Tag::Domain, Tag::FilePath])
            .with_score(200)
            .with_section(".rdata".to_string()),
        make_string("user@example.com")
            .with_tags(vec![Tag::Email, Tag::Domain])
            .with_score(90)
            .with_section(".data".to_string()),
    ];
    let result = format_table_with_mode(&strings, &make_metadata(2), true).unwrap();
    assert_snapshot!(result);
}

#[test]
fn test_tty_long_strings_truncated() {
    let long_url = format!(
        "https://very-long-subdomain.malware-domain.example.com/path/to/beacon?id={}",
        "x".repeat(50)
    );
    let long_path = format!(
        "C:\\Users\\Administrator\\AppData\\Local\\Temp\\{}.exe",
        "a".repeat(60)
    );

    let strings = vec![
        make_string(&long_url)
            .with_tags(vec![Tag::Url])
            .with_score(150)
            .with_section(".rdata".to_string()),
        make_string(&long_path)
            .with_tags(vec![Tag::FilePath])
            .with_score(120)
            .with_section(".data".to_string()),
    ];
    let result = format_table_with_mode(&strings, &make_metadata(2), true).unwrap();
    assert_snapshot!(result);
}

#[test]
fn test_tty_missing_optional_fields() {
    let strings = vec![
        // No section
        make_string("kernel32.dll")
            .with_tags(vec![Tag::Import])
            .with_score(50),
        // No tags
        make_string("mysterious string")
            .with_score(10)
            .with_section(".text".to_string()),
        // No tags, no section, default score
        make_string("bare minimum"),
    ];
    let result = format_table_with_mode(&strings, &make_metadata(3), true).unwrap();
    assert_snapshot!(result);
}

#[test]
fn test_tty_special_characters() {
    let strings = vec![
        make_string("string with\ttab")
            .with_score(10)
            .with_section(".data".to_string()),
        make_string("pipe|character")
            .with_score(10)
            .with_section(".data".to_string()),
        make_string("backslash\\here")
            .with_tags(vec![Tag::FilePath])
            .with_score(20)
            .with_section(".rdata".to_string()),
    ];
    let result = format_table_with_mode(&strings, &make_metadata(3), true).unwrap();
    assert_snapshot!(result);
}

#[test]
fn test_tty_various_encodings() {
    let strings = vec![
        FoundString::new(
            "ASCII string".to_string(),
            Encoding::Ascii,
            0x1000,
            12,
            StringSource::SectionData,
        )
        .with_score(50)
        .with_section(".rodata".to_string()),
        FoundString::new(
            "UTF-8 string".to_string(),
            Encoding::Utf8,
            0x2000,
            12,
            StringSource::SectionData,
        )
        .with_score(50)
        .with_section(".rodata".to_string()),
        FoundString::new(
            "UTF-16LE string".to_string(),
            Encoding::Utf16Le,
            0x3000,
            30,
            StringSource::SectionData,
        )
        .with_score(50)
        .with_section(".data".to_string()),
    ];
    let result = format_table_with_mode(&strings, &make_metadata(3), true).unwrap();
    assert_snapshot!(result);
}

#[test]
fn test_tty_high_scores() {
    let strings = vec![
        make_string("critical IOC")
            .with_tags(vec![Tag::Url, Tag::IPv4])
            .with_score(9999)
            .with_section(".rdata".to_string()),
        make_string("negative score")
            .with_score(-50)
            .with_section(".text".to_string()),
    ];
    let result = format_table_with_mode(&strings, &make_metadata(2), true).unwrap();
    assert_snapshot!(result);
}

#[test]
fn test_tty_all_tag_types() {
    // Test a variety of tag types to ensure they all display correctly
    let strings = vec![
        make_string("https://example.com")
            .with_tags(vec![Tag::Url])
            .with_score(100),
        make_string("example.com")
            .with_tags(vec![Tag::Domain])
            .with_score(80),
        make_string("192.168.1.1")
            .with_tags(vec![Tag::IPv4])
            .with_score(90),
        make_string("::1").with_tags(vec![Tag::IPv6]).with_score(90),
        make_string("/etc/passwd")
            .with_tags(vec![Tag::FilePath])
            .with_score(85),
        make_string("HKLM\\Software")
            .with_tags(vec![Tag::RegistryPath])
            .with_score(85),
        make_string("{12345678-1234-1234-1234-123456789012}")
            .with_tags(vec![Tag::Guid])
            .with_score(70),
        make_string("user@domain.com")
            .with_tags(vec![Tag::Email])
            .with_score(75),
        make_string("SGVsbG8gV29ybGQ=")
            .with_tags(vec![Tag::Base64])
            .with_score(60),
        make_string("%s %d %x")
            .with_tags(vec![Tag::FormatString])
            .with_score(50),
    ];
    let result = format_table_with_mode(&strings, &make_metadata(10), true).unwrap();
    assert_snapshot!(result);
}

#[test]
fn test_tty_long_section_names() {
    let strings = vec![
        make_string("string one")
            .with_score(10)
            .with_section(".rodata.str1.1".to_string()),
        make_string("string two")
            .with_score(20)
            .with_section(".data.rel.ro".to_string()),
        make_string("string three")
            .with_score(30)
            .with_section(".text".to_string()),
    ];
    let result = format_table_with_mode(&strings, &make_metadata(3), true).unwrap();
    assert_snapshot!(result);
}

// Non-TTY (plain) mode tests

#[test]
fn test_plain_empty_strings() {
    let result = format_table_with_mode(&[], &make_metadata(0), false).unwrap();
    assert_snapshot!(result);
}

#[test]
fn test_plain_single_string() {
    let strings = vec![make_string("GetProcAddress")];
    let result = format_table_with_mode(&strings, &make_metadata(1), false).unwrap();
    assert_snapshot!(result);
}

#[test]
fn test_plain_multiple_strings() {
    let strings = vec![
        make_string("https://malware.example.com/beacon")
            .with_tags(vec![Tag::Url])
            .with_score(150),
        make_string("C:\\Windows\\System32\\cmd.exe")
            .with_tags(vec![Tag::FilePath])
            .with_score(120),
        make_string("GetProcAddress")
            .with_tags(vec![Tag::Import])
            .with_score(80),
    ];
    let result = format_table_with_mode(&strings, &make_metadata(4), false).unwrap();
    assert_snapshot!(result);
}

#[test]
fn test_plain_long_strings_not_truncated() {
    let long_string = "a".repeat(200);
    let strings = vec![make_string(&long_string)];
    let result = format_table_with_mode(&strings, &make_metadata(1), false).unwrap();
    assert_snapshot!(result);
}

#[test]
fn test_plain_preserves_special_characters() {
    let strings = vec![
        make_string("tab\there"),
        make_string("pipe|here"),
        make_string("quote\"here"),
        make_string("line1\nline2"),
    ];
    let result = format_table_with_mode(&strings, &make_metadata(3), false).unwrap();
    assert_snapshot!(result);
}

#[test]
fn test_plain_unicode_strings() {
    let strings = vec![
        make_string("\u{4E2D}\u{6587}\u{5B57}\u{7B26}\u{4E32}"), // Chinese characters
        make_string("\u{0420}\u{0443}\u{0441}\u{0441}\u{043A}\u{0438}\u{0439}"), // Russian
        make_string("\u{1F600}\u{1F601}\u{1F602}"),              // Emojis
    ];
    let result = format_table_with_mode(&strings, &make_metadata(3), false).unwrap();
    assert_snapshot!(result);
}

// Edge case tests

#[test]
fn test_edge_many_tags_truncated() {
    let strings = vec![
        make_string("multi-tagged")
            .with_tags(vec![
                Tag::Url,
                Tag::Domain,
                Tag::IPv4,
                Tag::FilePath,
                Tag::RegistryPath,
            ])
            .with_score(100)
            .with_section(".data".to_string()),
    ];
    let result = format_table_with_mode(&strings, &make_metadata(1), true).unwrap();
    // Should only show first 3 tags
    assert_snapshot!(result);
}

#[test]
fn test_edge_zero_score() {
    let strings = vec![
        make_string("zero score string")
            .with_score(0)
            .with_section(".data".to_string()),
    ];
    let result = format_table_with_mode(&strings, &make_metadata(1), true).unwrap();
    assert_snapshot!(result);
}

#[test]
fn test_edge_empty_section_name() {
    // Section explicitly set to empty string vs None
    let strings = vec![make_string("with empty section").with_section(String::new())];
    let result = format_table_with_mode(&strings, &make_metadata(1), true).unwrap();
    assert_snapshot!(result);
}

#[test]
fn test_edge_very_short_string() {
    let strings = vec![
        make_string("a").with_score(10),
        make_string("ab").with_score(20),
        make_string("abc").with_score(30),
    ];
    let result = format_table_with_mode(&strings, &make_metadata(3), true).unwrap();
    assert_snapshot!(result);
}

#[test]
fn test_edge_string_sources() {
    let strings = vec![
        FoundString::new(
            "import_func".to_string(),
            Encoding::Ascii,
            0x1000,
            11,
            StringSource::ImportName,
        )
        .with_tags(vec![Tag::Import])
        .with_score(80),
        FoundString::new(
            "export_func".to_string(),
            Encoding::Ascii,
            0x2000,
            11,
            StringSource::ExportName,
        )
        .with_tags(vec![Tag::Export])
        .with_score(80),
        FoundString::new(
            "resource string".to_string(),
            Encoding::Utf16Le,
            0x3000,
            30,
            StringSource::ResourceString,
        )
        .with_tags(vec![Tag::Resource])
        .with_score(60),
    ];
    let result = format_table_with_mode(&strings, &make_metadata(3), true).unwrap();
    assert_snapshot!(result);
}
