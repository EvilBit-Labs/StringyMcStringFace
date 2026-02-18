use super::*;
use crate::extraction::config::NoiseFilterConfig;
use crate::types::SectionType;

#[test]
fn test_char_distribution_filter() {
    let filter = CharDistributionFilter;
    let context = FilterContext::default();

    // Normal text
    assert!(filter.calculate_confidence("Hello, World!", &context) > 0.7);

    // Excessive punctuation
    assert!(filter.calculate_confidence("!!!@@@###$$$", &context) < 0.5);

    // Repeated character
    assert!(filter.calculate_confidence("AAAA", &context) < 0.5);
}

#[test]
fn test_entropy_filter() {
    let filter = EntropyFilter::new(1.5, 7.5);
    let context = FilterContext::default();

    // Normal text
    assert!(filter.calculate_confidence("Hello, World!", &context) > 0.5);

    // Low entropy (repetition)
    assert!(filter.calculate_confidence("AAAA", &context) < 0.5);

    // High entropy (random-like string with many different characters)
    // Note: This string may not always have entropy > 7.5 due to repetition of patterns
    // The test verifies that very high entropy strings get lower confidence
    let random = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let random_confidence = filter.calculate_confidence(random, &context);
    // High entropy strings should have lower confidence than normal text
    let normal_confidence = filter.calculate_confidence("Hello, World!", &context);
    assert!(
        random_confidence < normal_confidence,
        "High entropy string should have lower confidence than normal text (random: {}, normal: {})",
        random_confidence,
        normal_confidence
    );
}

#[test]
fn test_linguistic_filter() {
    let filter = LinguisticFilter::new(0.1, 0.9);
    let context = FilterContext::default();

    // Normal English text
    assert!(filter.calculate_confidence("Hello world", &context) > 0.7);

    // Consonant-heavy
    assert!(filter.calculate_confidence("bcdfghjklmnpqrstvwxyz", &context) < 0.7);

    // Vowel-heavy
    assert!(filter.calculate_confidence("aeiouaeiou", &context) < 0.7);
}

#[test]
fn test_length_filter() {
    let filter = LengthFilter::new(200);
    let context = FilterContext::default();

    // Normal length
    assert!(filter.calculate_confidence("Hello", &context) > 0.7);

    // Very long
    let long_string = "A".repeat(300);
    assert!(filter.calculate_confidence(&long_string, &context) < 0.5);

    // Very short in low-weight section
    let low_weight_context = FilterContext {
        section_weight: 0.3,
        ..Default::default()
    };
    assert!(filter.calculate_confidence("Hi", &low_weight_context) < 0.7);
}

#[test]
fn test_repetition_filter() {
    let filter = RepetitionFilter::new(0.7);
    let context = FilterContext::default();

    // Normal text
    assert!(filter.calculate_confidence("Hello", &context) > 0.7);

    // Repeated characters
    assert!(filter.calculate_confidence("AAAA", &context) < 0.5);

    // Repeated pattern
    assert!(filter.calculate_confidence("abcabcabc", &context) < 0.5);
}

#[test]
fn test_context_filter() {
    let filter = ContextFilter;

    // String data section
    let context = FilterContext {
        section_type: SectionType::StringData,
        is_executable: false,
        is_writable: false,
        ..Default::default()
    };
    assert!(filter.calculate_confidence("test", &context) > 0.8);

    // Code section
    let context = FilterContext {
        section_type: SectionType::Code,
        section_weight: 0.1,
        ..Default::default()
    };
    assert!(filter.calculate_confidence("test", &context) < 0.5);
}

#[test]
fn test_composite_filter() {
    let config = NoiseFilterConfig::default();
    let filter = CompositeNoiseFilter::new(&config);
    let context = FilterContext::default();

    // Normal text should have high confidence
    let score = filter.calculate_confidence("Hello, World!", &context);
    assert!(score > 0.5);

    // Noise should have low confidence
    let noise_score = filter.calculate_confidence("AAAA", &context);
    assert!(noise_score < score);
}
