use crate::types::{FoundString, Result, StringyError};

use super::OutputMetadata;

/// Format strings as JSONL output, one object per line.
pub fn format_json(strings: &[FoundString], _metadata: &OutputMetadata) -> Result<String> {
    if strings.is_empty() {
        return Ok(String::new());
    }

    let mut lines = Vec::with_capacity(strings.len());
    for item in strings {
        if !item.confidence.is_finite() {
            return Err(StringyError::ConfigError(
                "JSON serialization failed: non-finite confidence".to_string(),
            ));
        }
        let line = serde_json::to_string(item).map_err(|err| {
            StringyError::ConfigError(format!("JSON serialization failed: {}", err))
        })?;
        lines.push(line);
    }

    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::{OutputFormat, OutputMetadata};
    use crate::types::{Encoding, FoundString, StringSource, Tag};
    use serde_json::Value;

    fn make_metadata(count: usize) -> OutputMetadata {
        OutputMetadata::new("test.bin".to_string(), OutputFormat::Json, count, count)
    }

    fn make_string(text: &str) -> FoundString {
        FoundString::new(
            text.to_string(),
            Encoding::Ascii,
            0x1000,
            text.len() as u32,
            StringSource::SectionData,
        )
    }

    fn parse_line(line: &str) -> Value {
        serde_json::from_str(line).expect("JSON should parse")
    }

    #[test]
    fn test_empty_strings_returns_empty_output() {
        let output = format_json(&[], &make_metadata(0)).expect("Formatting should succeed");
        assert!(output.is_empty());
    }

    #[test]
    fn test_single_string_serialization() {
        let strings = vec![make_string("alpha")];
        let output = format_json(&strings, &make_metadata(1)).expect("Formatting should succeed");
        let value = parse_line(&output);
        assert_eq!(value["text"], "alpha");
        assert_eq!(value["encoding"], "Ascii");
    }

    #[test]
    fn test_multiple_strings_jsonl_format() {
        let strings = vec![make_string("one"), make_string("two")];
        let output = format_json(&strings, &make_metadata(2)).expect("Formatting should succeed");
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(parse_line(lines[0])["text"], "one");
        assert_eq!(parse_line(lines[1])["text"], "two");
    }

    #[test]
    fn test_optional_fields_excluded_when_none() {
        let strings = vec![make_string("no-optional")];
        let output = format_json(&strings, &make_metadata(1)).expect("Formatting should succeed");
        assert!(!output.contains("original_text"));
        assert!(!output.contains("section_weight"));
        assert!(!output.contains("semantic_boost"));
        assert!(!output.contains("noise_penalty"));
    }

    #[test]
    fn test_optional_fields_included_when_some() {
        let strings = vec![
            make_string("with-optional")
                .with_original_text("orig".to_string())
                .with_section_weight(10)
                .with_semantic_boost(5)
                .with_noise_penalty(-2),
        ];
        let output = format_json(&strings, &make_metadata(1)).expect("Formatting should succeed");
        assert!(output.contains("original_text"));
        assert!(output.contains("section_weight"));
        assert!(output.contains("semantic_boost"));
        assert!(output.contains("noise_penalty"));
    }

    #[test]
    fn test_special_characters_are_escaped() {
        let strings = vec![make_string("quote\" backslash\\ line\n tab\t")];
        let output = format_json(&strings, &make_metadata(1)).expect("Formatting should succeed");
        assert!(output.contains("\\\""));
        assert!(output.contains("\\\\"));
        assert!(output.contains("\\n"));
        assert!(output.contains("\\t"));
    }

    #[test]
    fn test_all_encodings_serialize_correctly() {
        let strings = vec![
            FoundString::new(
                "a".to_string(),
                Encoding::Ascii,
                0,
                1,
                StringSource::SectionData,
            ),
            FoundString::new(
                "b".to_string(),
                Encoding::Utf8,
                1,
                1,
                StringSource::SectionData,
            ),
            FoundString::new(
                "c".to_string(),
                Encoding::Utf16Le,
                2,
                2,
                StringSource::SectionData,
            ),
            FoundString::new(
                "d".to_string(),
                Encoding::Utf16Be,
                3,
                2,
                StringSource::SectionData,
            ),
        ];
        let output = format_json(&strings, &make_metadata(4)).expect("Formatting should succeed");
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(parse_line(lines[0])["encoding"], "Ascii");
        assert_eq!(parse_line(lines[1])["encoding"], "Utf8");
        assert_eq!(parse_line(lines[2])["encoding"], "Utf16Le");
        assert_eq!(parse_line(lines[3])["encoding"], "Utf16Be");
    }

    #[test]
    fn test_all_tag_types_serialize_correct_names() {
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
        let output = format_json(&strings, &make_metadata(1)).expect("Formatting should succeed");
        let value = parse_line(&output);
        let tag_values: Vec<String> = value["tags"]
            .as_array()
            .expect("tags should be an array")
            .iter()
            .map(|item| item.as_str().expect("tag should be string").to_string())
            .collect();

        let expected = vec![
            "Url",
            "Domain",
            "ipv4",
            "ipv6",
            "filepath",
            "regpath",
            "guid",
            "Email",
            "b64",
            "fmt",
            "user-agent-ish",
            "demangled",
            "Import",
            "Export",
            "Version",
            "Manifest",
            "Resource",
            "dylib-path",
            "rpath",
            "rpath-var",
            "framework-path",
        ];

        for name in expected {
            assert!(tag_values.iter().any(|tag| tag == name));
        }
    }

    #[test]
    fn test_all_source_types_serialize_correctly() {
        let strings = vec![
            FoundString::new(
                "a".to_string(),
                Encoding::Ascii,
                0,
                1,
                StringSource::SectionData,
            ),
            FoundString::new(
                "b".to_string(),
                Encoding::Ascii,
                1,
                1,
                StringSource::ImportName,
            ),
            FoundString::new(
                "c".to_string(),
                Encoding::Ascii,
                2,
                1,
                StringSource::ExportName,
            ),
            FoundString::new(
                "d".to_string(),
                Encoding::Ascii,
                3,
                1,
                StringSource::ResourceString,
            ),
            FoundString::new(
                "e".to_string(),
                Encoding::Ascii,
                4,
                1,
                StringSource::LoadCommand,
            ),
            FoundString::new(
                "f".to_string(),
                Encoding::Ascii,
                5,
                1,
                StringSource::DebugInfo,
            ),
        ];
        let output = format_json(&strings, &make_metadata(6)).expect("Formatting should succeed");
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(parse_line(lines[0])["source"], "SectionData");
        assert_eq!(parse_line(lines[1])["source"], "ImportName");
        assert_eq!(parse_line(lines[2])["source"], "ExportName");
        assert_eq!(parse_line(lines[3])["source"], "ResourceString");
        assert_eq!(parse_line(lines[4])["source"], "LoadCommand");
        assert_eq!(parse_line(lines[5])["source"], "DebugInfo");
    }

    #[test]
    fn test_error_propagation_for_serialization_failures() {
        let strings = vec![make_string("nan").with_confidence(f32::NAN)];
        let result = format_json(&strings, &make_metadata(1));
        match result {
            Err(StringyError::ConfigError(_)) => {}
            _ => panic!("Expected ConfigError on invalid JSON serialization"),
        }
    }
}
