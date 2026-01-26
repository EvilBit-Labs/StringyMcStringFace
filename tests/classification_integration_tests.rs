use std::fs;

use stringy::classification::SemanticClassifier;
use stringy::container::{ContainerParser, ElfParser, MachoParser, PeParser};
use stringy::types::{BinaryFormat, Encoding, SectionType, StringContext, StringSource, Tag};

fn get_fixture_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn create_test_context(
    binary_format: BinaryFormat,
    section_type: SectionType,
    source: StringSource,
) -> StringContext {
    StringContext::new(section_type, binary_format, Encoding::Ascii, source)
        .with_section_name(".rodata".to_string())
}

#[test]
fn test_elf_string_classification() {
    let fixture_path = get_fixture_path("test_binary_elf");
    let elf_data = fs::read(&fixture_path)
        .expect("Failed to read ELF fixture. Run the build script to generate fixtures.");

    assert!(ElfParser::detect(&elf_data), "ELF detection should succeed");
    let parser = ElfParser::new();
    let container_info = parser.parse(&elf_data).expect("Failed to parse ELF");

    assert_eq!(container_info.format, BinaryFormat::Elf);

    let classifier = SemanticClassifier::new();
    let context = create_test_context(
        BinaryFormat::Elf,
        SectionType::StringData,
        StringSource::SectionData,
    );

    let guid = "{12345678-1234-1234-1234-123456789abc}";
    let tags = classifier.classify(guid, &context);
    assert!(tags.contains(&Tag::Guid));

    let email = "admin@malware.com";
    let tags = classifier.classify(email, &context);
    assert!(tags.contains(&Tag::Email));

    let format_string = "Error: %s at line %d";
    let tags = classifier.classify(format_string, &context);
    assert!(tags.contains(&Tag::FormatString));
}

#[test]
fn test_pe_string_classification() {
    let fixture_path = get_fixture_path("test_binary_pe.exe");
    let pe_data = fs::read(&fixture_path)
        .expect("Failed to read PE fixture. Run the build script to generate fixtures.");

    assert!(PeParser::detect(&pe_data), "PE detection should succeed");
    let parser = PeParser::new();
    let container_info = parser.parse(&pe_data).expect("Failed to parse PE");

    assert_eq!(container_info.format, BinaryFormat::Pe);

    let classifier = SemanticClassifier::new();
    let context = create_test_context(
        BinaryFormat::Pe,
        SectionType::Resources,
        StringSource::ResourceString,
    );

    let base64 = "U29tZSBsb25nZXIgYmFzZTY0IHN0cmluZw==";
    let tags = classifier.classify(base64, &context);
    assert!(tags.contains(&Tag::Base64));

    let user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
    let tags = classifier.classify(user_agent, &context);
    assert!(tags.contains(&Tag::UserAgent));
}

#[test]
fn test_macho_string_classification() {
    let fixture_path = get_fixture_path("test_binary_macho");
    let macho_data = fs::read(&fixture_path)
        .expect("Failed to read Mach-O fixture. Run the build script to generate fixtures.");

    assert!(
        MachoParser::detect(&macho_data),
        "Mach-O detection should succeed"
    );
    let parser = MachoParser::new();
    let container_info = parser.parse(&macho_data).expect("Failed to parse Mach-O");

    assert_eq!(container_info.format, BinaryFormat::MachO);

    let classifier = SemanticClassifier::new();
    let context = create_test_context(
        BinaryFormat::MachO,
        SectionType::StringData,
        StringSource::SectionData,
    );

    let guid = "{87654321-4321-4321-4321-abcdefabcdef}";
    let tags = classifier.classify(guid, &context);
    assert!(tags.contains(&Tag::Guid));

    let format_string = "Value: %x";
    let tags = classifier.classify(format_string, &context);
    assert!(tags.contains(&Tag::FormatString));
}

#[test]
fn test_real_world_patterns() {
    let classifier = SemanticClassifier::new();
    let context = create_test_context(
        BinaryFormat::Elf,
        SectionType::StringData,
        StringSource::SectionData,
    );

    let c2_url = "https://evil.com/payload";
    let tags = classifier.classify(c2_url, &context);
    assert!(tags.contains(&Tag::Url), "C2 URL should be detected");

    let registry = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    let tags = classifier.classify(registry, &context);
    assert!(
        tags.contains(&Tag::RegistryPath),
        "Registry path should be detected"
    );

    let guid = "{01234567-89ab-cdef-0123-456789abcdef}";
    let tags = classifier.classify(guid, &context);
    assert!(tags.contains(&Tag::Guid));

    let user_agent = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
    let tags = classifier.classify(user_agent, &context);
    assert!(tags.contains(&Tag::UserAgent));

    let format_string = "Failed to open %s";
    let tags = classifier.classify(format_string, &context);
    assert!(tags.contains(&Tag::FormatString));
}

#[test]
fn test_classification_batch_processing() {
    let classifier = SemanticClassifier::new();
    let context = create_test_context(
        BinaryFormat::Elf,
        SectionType::StringData,
        StringSource::SectionData,
    );

    // Generate a batch of samples to verify classification handles volume correctly
    let mut samples = Vec::new();
    for index in 0..1200 {
        samples.push(format!("{{12345678-1234-1234-1234-{:012x}}}", index));
        samples.push(format!("user{}@example.com", index));
        samples.push(format!("Error %s at line {}", index));
    }

    // Verify all samples are classified without panics
    // Performance is tested via criterion benchmarks, not wall-clock assertions
    for sample in &samples {
        let _ = classifier.classify(sample, &context);
    }
}
