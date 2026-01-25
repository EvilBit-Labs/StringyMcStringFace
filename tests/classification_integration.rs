use insta::assert_debug_snapshot;
use std::time::{Duration, Instant};
use stringy::classification::SemanticClassifier;
use stringy::types::{BinaryFormat, Encoding, SectionType, StringContext, StringSource, Tag};

fn make_context() -> StringContext {
    StringContext::new(
        SectionType::StringData,
        BinaryFormat::Elf,
        Encoding::Ascii,
        StringSource::SectionData,
    )
    .with_section_name(".rodata".to_string())
}

fn classify_tags(classifier: &SemanticClassifier, text: &str) -> Vec<Tag> {
    let context = make_context();
    classifier.classify(text, &context)
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
        ("{12345678-1234-1234-1234-123456789abc}", vec![Tag::Guid]),
        ("admin@malware.com", vec![Tag::Email]),
        ("U29tZSBsb25nZXIgYmFzZTY0IHN0cmluZw==", vec![Tag::Base64]),
        ("Error: %s at line %d", vec![Tag::FormatString]),
        (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            vec![Tag::UserAgent],
        ),
    ];

    for (text, expected) in samples {
        let tags = classify_tags(&classifier, text);
        for tag in expected {
            assert!(tags.contains(&tag));
        }
    }
}

// Note: classify_tags with SemanticClassifier can be slow on CI.
#[test]
fn test_classification_performance() {
    let classifier = SemanticClassifier::new();

    let mut samples = Vec::new();
    for index in 0..350 {
        samples.push(format!("{{12345678-1234-1234-1234-{:012x}}}", index));
        samples.push(format!("user{}@example.com", index));
        samples.push(format!("Error %s at line {}", index));
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
fn test_no_false_positives_on_random_data() {
    let classifier = SemanticClassifier::new();
    let tags = classify_tags(&classifier, "x9qz1p0t8v7w6r5y4u3i2o1p-");

    assert!(tags.is_empty());
}

#[test]
fn test_classification_snapshots() {
    let classifier = SemanticClassifier::new();

    let inputs = [
        "{12345678-1234-1234-1234-123456789abc}",
        "user.name+tag@example.co.uk",
        "U29tZSBsb25nZXIgYmFzZTY0IHN0cmluZw==",
        "Value: %x",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
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
