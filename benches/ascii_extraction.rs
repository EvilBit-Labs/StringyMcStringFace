use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use stringy::extraction::ascii::{AsciiExtractionConfig, extract_ascii_strings};
use stringy::extraction::config::NoiseFilterConfig;
use stringy::extraction::filters::{CompositeNoiseFilter, FilterContext};

fn bench_basic_extraction(c: &mut Criterion) {
    // Create test data with various string patterns
    let test_data =
        b"Hello World\0Test String\0Another String\0Binary\x00\x01\x02Data\0More Strings\0"
            .repeat(100);
    let config = AsciiExtractionConfig::default();

    c.bench_function("ascii_extraction_basic", |b| {
        b.iter(|| {
            let _ = extract_ascii_strings(black_box(&test_data), black_box(&config));
        });
    });
}

fn bench_filtered_extraction(c: &mut Criterion) {
    let test_data =
        b"Hello World\0Test String\0Another String\0Binary\x00\x01\x02Data\0More Strings\0"
            .repeat(100);
    let config = AsciiExtractionConfig::default();
    let filter_config = NoiseFilterConfig::default();
    let filter = CompositeNoiseFilter::new(&filter_config);
    let context = FilterContext::default();

    c.bench_function("ascii_extraction_with_filtering", |b| {
        b.iter(|| {
            let strings = extract_ascii_strings(black_box(&test_data), black_box(&config));
            for string in &strings {
                let _ = filter.calculate_confidence(black_box(&string.text), black_box(&context));
            }
        });
    });
}

fn bench_individual_filters(c: &mut Criterion) {
    use stringy::extraction::filters::{
        CharDistributionFilter, ContextFilter, EntropyFilter, LengthFilter, LinguisticFilter,
        NoiseFilter, RepetitionFilter,
    };

    let test_strings = vec![
        "Hello, World!",
        "AAAA",
        "Error: file not found",
        "!!!@@@###",
        "C:\\Windows\\System32",
    ];

    let char_filter = CharDistributionFilter;
    let entropy_filter = EntropyFilter::new(1.5, 7.5);
    let linguistic_filter = LinguisticFilter::new(0.1, 0.9);
    let length_filter = LengthFilter::new(200);
    let repetition_filter = RepetitionFilter::new(0.7);
    let context_filter = ContextFilter;
    let context = FilterContext::default();

    c.bench_function("filter_char_distribution", |b| {
        b.iter(|| {
            for text in &test_strings {
                let _ = char_filter.calculate_confidence(black_box(text), black_box(&context));
            }
        });
    });

    c.bench_function("filter_entropy", |b| {
        b.iter(|| {
            for text in &test_strings {
                let _ = entropy_filter.calculate_confidence(black_box(text), black_box(&context));
            }
        });
    });

    c.bench_function("filter_linguistic", |b| {
        b.iter(|| {
            for text in &test_strings {
                let _ =
                    linguistic_filter.calculate_confidence(black_box(text), black_box(&context));
            }
        });
    });

    c.bench_function("filter_length", |b| {
        b.iter(|| {
            for text in &test_strings {
                let _ = length_filter.calculate_confidence(black_box(text), black_box(&context));
            }
        });
    });

    c.bench_function("filter_repetition", |b| {
        b.iter(|| {
            for text in &test_strings {
                let _ =
                    repetition_filter.calculate_confidence(black_box(text), black_box(&context));
            }
        });
    });

    c.bench_function("filter_context", |b| {
        b.iter(|| {
            for text in &test_strings {
                let _ = context_filter.calculate_confidence(black_box(text), black_box(&context));
            }
        });
    });
}

fn bench_composite_filter(c: &mut Criterion) {
    let test_strings = vec![
        "Hello, World!",
        "AAAA",
        "Error: file not found",
        "!!!@@@###",
        "C:\\Windows\\System32",
        "https://example.com",
    ];

    let filter_config = NoiseFilterConfig::default();
    let filter = CompositeNoiseFilter::new(&filter_config);
    let context = FilterContext::default();

    c.bench_function("composite_filter_all_enabled", |b| {
        b.iter(|| {
            for text in &test_strings {
                let _ = filter.calculate_confidence(black_box(text), black_box(&context));
            }
        });
    });

    // Test with some filters disabled
    // Note: CompositeNoiseFilter doesn't expose a builder pattern, so we create a new one
    // with modified enable flags. For this benchmark, we'll just use the default filter.
    let filter_partial = CompositeNoiseFilter::new(&filter_config);

    c.bench_function("composite_filter_partial", |b| {
        b.iter(|| {
            for text in &test_strings {
                let _ = filter_partial.calculate_confidence(black_box(text), black_box(&context));
            }
        });
    });
}

fn bench_entropy_calculation(c: &mut Criterion) {
    use entropy::shannon_entropy;

    let test_strings = vec![
        "Hello, World!",
        "AAAA",
        "Error: file not found",
        "!!!@@@###",
    ];

    c.bench_function("entropy_shannon_calculation", |b| {
        b.iter(|| {
            for text in &test_strings {
                let _ = shannon_entropy(black_box(text.as_bytes()));
            }
        });
    });
}

fn bench_large_binary(c: &mut Criterion) {
    // Create a large binary-like data with embedded strings
    let mut large_data = Vec::new();
    for i in 0..10000 {
        if i % 100 == 0 {
            large_data.extend_from_slice(b"Hello World\0");
        } else {
            large_data.push((i % 256) as u8);
        }
    }

    let config = AsciiExtractionConfig::default();
    let filter_config = NoiseFilterConfig::default();
    let filter = CompositeNoiseFilter::new(&filter_config);
    let context = FilterContext::default();

    c.bench_function("large_binary_extraction", |b| {
        b.iter(|| {
            let strings = extract_ascii_strings(black_box(&large_data), black_box(&config));
            for string in &strings {
                let _ = filter.calculate_confidence(black_box(&string.text), black_box(&context));
            }
        });
    });
}

criterion_group!(
    ascii_extraction_benches,
    bench_basic_extraction,
    bench_filtered_extraction,
    bench_individual_filters,
    bench_composite_filter,
    bench_entropy_calculation,
    bench_large_binary
);
criterion_main!(ascii_extraction_benches);
