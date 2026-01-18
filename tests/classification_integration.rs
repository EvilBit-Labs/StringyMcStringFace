use insta::assert_debug_snapshot;
use std::time::{Duration, Instant};
use stringy::classification::SemanticClassifier;
use stringy::types::{Encoding, FoundString, StringSource, Tag};

fn make_found_string(text: &str) -> FoundString {
    FoundString {
        text: text.to_string(),
        original_text: None,
        encoding: Encoding::Ascii,
        offset: 0,
        rva: None,
        section: None,
        length: text.len() as u32,
        tags: Vec::new(),
        score: 0,
        section_weight: None,
        semantic_boost: None,
        noise_penalty: None,
        source: StringSource::SectionData,
        confidence: 1.0,
    }
}

fn classify_tags(classifier: &SemanticClassifier, text: &str) -> Vec<Tag> {
    classifier.classify(&make_found_string(text))
}

fn tags_as_strings(tags: &[Tag]) -> Vec<String> {
    let mut values: Vec<String> = tags.iter().map(|tag| format!("{:?}", tag)).collect();
    values.sort();
    values
}

#[test]
fn test_classify_mixed_indicators() {
    let classifier = SemanticClassifier::new();

    let samples = vec![
        ("https://example.com", vec![Tag::Url]),
        ("example.com", vec![Tag::Domain]),
        ("192.168.1.1", vec![Tag::IPv4]),
        ("::1", vec![Tag::IPv6]),
        ("/usr/bin/bash", vec![Tag::FilePath]),
        ("C:\\Windows\\System32\\cmd.exe", vec![Tag::FilePath]),
        (
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            vec![Tag::RegistryPath],
        ),
    ];

    for (text, expected) in samples {
        let tags = classify_tags(&classifier, text);
        for tag in expected {
            assert!(tags.contains(&tag));
        }
    }
}

#[test]
fn test_classify_all_path_types() {
    let classifier = SemanticClassifier::new();

    let posix_tags = classify_tags(&classifier, "/etc/passwd");
    assert!(posix_tags.contains(&Tag::FilePath));

    let windows_tags = classify_tags(&classifier, "C:\\Windows\\Temp\\evil.exe");
    assert!(windows_tags.contains(&Tag::FilePath));

    let unc_tags = classify_tags(&classifier, "\\\\server\\share\\file.txt");
    assert!(unc_tags.contains(&Tag::FilePath));

    let registry_tags = classify_tags(&classifier, "HKLM\\System\\CurrentControlSet\\Services");
    assert!(registry_tags.contains(&Tag::RegistryPath));
}

// Note: classify_tags with SemanticClassifier can be slow on CI.
#[test]
fn test_classification_performance() {
    let classifier = SemanticClassifier::new();

    let mut samples = Vec::new();
    for index in 0..350 {
        samples.push(format!("https://example.com/api/{}", index));
        samples.push(format!("C:\\Windows\\Temp\\file{}.tmp", index));
        samples.push(format!("/usr/local/bin/tool{}", index));
    }

    let start = Instant::now();
    for sample in &samples {
        let _ = classify_tags(&classifier, sample);
    }
    let elapsed = start.elapsed();

    // Timeout is set to 500ms to accommodate slower CI environments while still detecting
    // performance regressions. This processes 1050 samples (350 iterations x 3 samples each).
    // The timeout is higher than typical development performance (~50-100ms) to ensure
    // CI stability across different runner configurations and load conditions.
    assert!(elapsed < Duration::from_millis(500));
}

#[test]
fn test_regex_caching() {
    let classifier = SemanticClassifier::new();
    let first = classifier.regex_cache_addresses();

    let second_classifier = SemanticClassifier::new();
    let second = second_classifier.regex_cache_addresses();

    assert_eq!(first, second);
}

#[test]
fn test_no_false_positives_on_random_data() {
    let classifier = SemanticClassifier::new();
    let tags = classify_tags(&classifier, "x9qz1p0t8v7w6r5y4u3i2o1p");

    assert!(tags.is_empty());
}

#[test]
fn test_format_strings_not_paths() {
    let classifier = SemanticClassifier::new();
    let tags = classify_tags(&classifier, "C:\\%s");

    assert!(!tags.contains(&Tag::FilePath));
}

#[test]
fn test_version_numbers_not_paths() {
    let classifier = SemanticClassifier::new();
    let tags = classify_tags(&classifier, "1.2.3.4");

    assert!(tags.contains(&Tag::IPv4));
    assert!(!tags.contains(&Tag::FilePath));
}

#[test]
fn test_classification_snapshots() {
    let classifier = SemanticClassifier::new();

    let inputs = [
        "https://example.com",
        "192.168.1.1",
        "/usr/bin/bash",
        "C:\\Windows\\System32\\cmd.exe",
        "\\\\server\\share\\file.txt",
        "HKCU\\Software\\Microsoft",
    ];

    let snapshot: Vec<(String, Vec<String>)> = inputs
        .iter()
        .map(|text| {
            let tags = classify_tags(&classifier, text);
            (text.to_string(), tags_as_strings(&tags))
        })
        .collect();

    assert_debug_snapshot!(snapshot);
}
