use stringy::classification::SemanticClassifier;
use stringy::types::{BinaryFormat, Encoding, SectionType, StringContext, StringSource, Tag};

fn make_context(section_type: SectionType, source: StringSource) -> StringContext {
    StringContext {
        section_type,
        section_name: Some(".rodata".to_string()),
        binary_format: BinaryFormat::Elf,
        encoding: Encoding::Ascii,
        source,
    }
}

#[test]
fn test_guid_detection() {
    let classifier = SemanticClassifier::new();
    let context = make_context(SectionType::StringData, StringSource::SectionData);

    let valid = "{12345678-1234-1234-1234-123456789abc}";
    let tags = classifier.classify(valid, &context);
    assert!(tags.contains(&Tag::Guid));

    let valid_upper = "{12345678-1234-1234-1234-123456789ABC}";
    let tags = classifier.classify(valid_upper, &context);
    assert!(tags.contains(&Tag::Guid));

    let invalid_missing_braces = "12345678-1234-1234-1234-123456789abc";
    let tags = classifier.classify(invalid_missing_braces, &context);
    assert!(!tags.contains(&Tag::Guid));

    let invalid_chars = "{12345678-1234-1234-1234-123456789abz}";
    let tags = classifier.classify(invalid_chars, &context);
    assert!(!tags.contains(&Tag::Guid));

    let invalid_short = "{12345678-1234-1234-1234-123456789ab}";
    let tags = classifier.classify(invalid_short, &context);
    assert!(!tags.contains(&Tag::Guid));
}

#[test]
fn test_email_detection() {
    let classifier = SemanticClassifier::new();
    let context = make_context(SectionType::StringData, StringSource::SectionData);

    let valid = "admin@malware.com";
    let tags = classifier.classify(valid, &context);
    assert!(tags.contains(&Tag::Email));

    let valid_plus = "user.name+tag@example.co.uk";
    let tags = classifier.classify(valid_plus, &context);
    assert!(tags.contains(&Tag::Email));

    let invalid_missing_at = "user.example.com";
    let tags = classifier.classify(invalid_missing_at, &context);
    assert!(!tags.contains(&Tag::Email));

    let invalid_tld = "user@example.c";
    let tags = classifier.classify(invalid_tld, &context);
    assert!(!tags.contains(&Tag::Email));

    let invalid_multi_at = "user@@example.com";
    let tags = classifier.classify(invalid_multi_at, &context);
    assert!(!tags.contains(&Tag::Email));
}

#[test]
fn test_base64_detection() {
    let classifier = SemanticClassifier::new();
    let context = make_context(SectionType::StringData, StringSource::SectionData);

    let valid_padded = "U29tZSBsb25nZXIgYmFzZTY0IHN0cmluZw==";
    let tags = classifier.classify(valid_padded, &context);
    assert!(tags.contains(&Tag::Base64));

    let valid_unpadded = "VGhpcyBpcyBhIHRlc3Qgc3RyaW5n";
    let tags = classifier.classify(valid_unpadded, &context);
    assert!(tags.contains(&Tag::Base64));

    let invalid_chars = "SGVsbG8gV29ybGQ$";
    let tags = classifier.classify(invalid_chars, &context);
    assert!(!tags.contains(&Tag::Base64));

    let invalid_padding = "U29tZSBsb25nZXIgYmFzZTY0====";
    let tags = classifier.classify(invalid_padding, &context);
    assert!(!tags.contains(&Tag::Base64));

    let too_short = "SGVsbG8gV29ybGQ=";
    let tags = classifier.classify(too_short, &context);
    assert!(!tags.contains(&Tag::Base64));

    let hex_like = "deadbeefcafebabedeadbeefcafebabe";
    let tags = classifier.classify(hex_like, &context);
    assert!(!tags.contains(&Tag::Base64));
}

#[test]
fn test_format_string_detection() {
    let classifier = SemanticClassifier::new();
    let context = make_context(SectionType::StringData, StringSource::SectionData);

    let printf_style = "Error: %s at line %d";
    let tags = classifier.classify(printf_style, &context);
    assert!(tags.contains(&Tag::FormatString));

    let python_style = "User {0} logged in";
    let tags = classifier.classify(python_style, &context);
    assert!(tags.contains(&Tag::FormatString));

    let mixed = "Value: %x {1}";
    let tags = classifier.classify(mixed, &context);
    assert!(tags.contains(&Tag::FormatString));

    let invalid = "Percent %q";
    let tags = classifier.classify(invalid, &context);
    assert!(!tags.contains(&Tag::FormatString));
}

#[test]
fn test_user_agent_detection() {
    let classifier = SemanticClassifier::new();
    let context = make_context(SectionType::StringData, StringSource::SectionData);

    let mozilla = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
    let tags = classifier.classify(mozilla, &context);
    assert!(tags.contains(&Tag::UserAgent));

    let chrome = "Chrome/117.0.5938.92";
    let tags = classifier.classify(chrome, &context);
    assert!(tags.contains(&Tag::UserAgent));

    let safari = "Safari/605.1.15";
    let tags = classifier.classify(safari, &context);
    assert!(tags.contains(&Tag::UserAgent));

    let bot = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
    let tags = classifier.classify(bot, &context);
    assert!(tags.contains(&Tag::UserAgent));
}

#[test]
fn test_false_positive_reduction() {
    let classifier = SemanticClassifier::new();
    let context = make_context(SectionType::StringData, StringSource::SectionData);

    let random = "x9qz1p0t8v7w6r5y4u3i2o1p-";
    let tags = classifier.classify(random, &context);
    assert!(tags.is_empty());

    let short = "%s";
    let tags = classifier.classify(short, &context);
    assert!(!tags.contains(&Tag::FormatString));
}

#[test]
fn test_multi_tag_scenarios() {
    let classifier = SemanticClassifier::new();
    let context = make_context(SectionType::StringData, StringSource::SectionData);

    let text = "Mozilla/5.0 %s";
    let tags = classifier.classify(text, &context);
    assert!(tags.contains(&Tag::UserAgent));
    assert!(tags.contains(&Tag::FormatString));
    assert_eq!(tags.len(), 2);
}

#[test]
fn test_context_aware_classification() {
    let classifier = SemanticClassifier::new();
    let text = "ID: %d";

    let boosted = make_context(SectionType::StringData, StringSource::SectionData);
    let tags = classifier.classify(text, &boosted);
    assert!(tags.contains(&Tag::FormatString));

    let unboosted = make_context(SectionType::Code, StringSource::SectionData);
    let tags = classifier.classify(text, &unboosted);
    assert!(!tags.contains(&Tag::FormatString));
}
