use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use stringy::classification::SemanticClassifier;
use stringy::types::{BinaryFormat, Encoding, SectionType, StringContext, StringSource};

fn make_context() -> StringContext {
    StringContext::new(
        SectionType::StringData,
        BinaryFormat::Elf,
        Encoding::Ascii,
        StringSource::SectionData,
    )
    .with_section_name(".rodata".to_string())
}

fn bench_classifier_construction(c: &mut Criterion) {
    c.bench_function("classification_classifier_construction", |b| {
        b.iter(|| {
            let _ = SemanticClassifier::new();
        });
    });
}

fn bench_guid_classification(c: &mut Criterion) {
    let classifier = SemanticClassifier::new();
    let context = make_context();
    let guid = "{12345678-1234-1234-1234-123456789abc}";

    c.bench_function("classification_guid", |b| {
        b.iter(|| {
            let _ = classifier.classify(black_box(guid), &context);
        });
    });
}

fn bench_email_classification(c: &mut Criterion) {
    let classifier = SemanticClassifier::new();
    let context = make_context();
    let email = "user.name+tag@example.co.uk";

    c.bench_function("classification_email", |b| {
        b.iter(|| {
            let _ = classifier.classify(black_box(email), &context);
        });
    });
}

fn bench_base64_classification(c: &mut Criterion) {
    let classifier = SemanticClassifier::new();
    let context = make_context();
    let base64 = "U29tZSBsb25nZXIgYmFzZTY0IHN0cmluZw==";

    c.bench_function("classification_base64", |b| {
        b.iter(|| {
            let _ = classifier.classify(black_box(base64), &context);
        });
    });
}

fn bench_format_string_classification(c: &mut Criterion) {
    let classifier = SemanticClassifier::new();
    let context = make_context();
    let format_string = "Error: %s at line %d";

    c.bench_function("classification_format_string", |b| {
        b.iter(|| {
            let _ = classifier.classify(black_box(format_string), &context);
        });
    });
}

fn bench_user_agent_classification(c: &mut Criterion) {
    let classifier = SemanticClassifier::new();
    let context = make_context();
    let user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";

    c.bench_function("classification_user_agent", |b| {
        b.iter(|| {
            let _ = classifier.classify(black_box(user_agent), &context);
        });
    });
}

fn bench_batch_classification(c: &mut Criterion) {
    let classifier = SemanticClassifier::new();
    let context = make_context();

    let mut samples = Vec::new();
    for index in 0..1000 {
        samples.push(format!("{{12345678-1234-1234-1234-{:012x}}}", index));
        samples.push(format!("user{}@example.com", index));
        samples.push(format!("Error %s at line {}", index));
    }

    c.bench_function("classification_batch", |b| {
        b.iter(|| {
            for sample in &samples {
                let _ = classifier.classify(black_box(sample.as_str()), &context);
            }
        });
    });
}

fn bench_worst_case(c: &mut Criterion) {
    let classifier = SemanticClassifier::new();
    let context = make_context();
    let worst_case = "x9qz1p0t8v7w6r5y4u3i2o1p-";

    c.bench_function("classification_worst_case", |b| {
        b.iter(|| {
            let _ = classifier.classify(black_box(worst_case), &context);
        });
    });
}

fn bench_context_creation(c: &mut Criterion) {
    c.bench_function("classification_context_creation", |b| {
        b.iter(|| {
            let _ = make_context();
        });
    });
}

criterion_group!(
    classification_benches,
    bench_classifier_construction,
    bench_guid_classification,
    bench_email_classification,
    bench_base64_classification,
    bench_format_string_classification,
    bench_user_agent_classification,
    bench_batch_classification,
    bench_worst_case,
    bench_context_creation
);
criterion_main!(classification_benches);
