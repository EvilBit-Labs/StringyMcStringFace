//! Unit tests for noise filtering heuristics

use stringy::extraction::config::{FilterWeights, NoiseFilterConfig};
use stringy::extraction::filters::{
    CharDistributionFilter, CompositeNoiseFilter, ContextFilter, EntropyFilter, FilterContext,
    LengthFilter, LinguisticFilter, NoiseFilter, RepetitionFilter,
};
use stringy::types::SectionType;

#[test]
fn test_char_distribution_filter_all_punctuation() {
    let filter = CharDistributionFilter;
    let context = FilterContext::default();

    let score = filter.calculate_confidence("!!!@@@###$$$", &context);
    assert!(score < 0.5, "All punctuation should have low confidence");
}

#[test]
fn test_char_distribution_filter_repeated_character() {
    let filter = CharDistributionFilter;
    let context = FilterContext::default();

    let score = filter.calculate_confidence("AAAA", &context);
    assert!(score < 0.5, "Repeated character should have low confidence");
}

#[test]
fn test_char_distribution_filter_normal_text() {
    let filter = CharDistributionFilter;
    let context = FilterContext::default();

    let score = filter.calculate_confidence("Hello, World!", &context);
    assert!(score > 0.7, "Normal text should have high confidence");
}

#[test]
fn test_char_distribution_filter_mixed_alphanumeric() {
    let filter = CharDistributionFilter;
    let context = FilterContext::default();

    let score = filter.calculate_confidence("Test123", &context);
    assert!(
        score > 0.5,
        "Mixed alphanumeric should have reasonable confidence"
    );
}

#[test]
fn test_entropy_filter_low_entropy() {
    let filter = EntropyFilter::new(1.5, 7.5);
    let context = FilterContext::default();

    // Low entropy (repetition)
    let score = filter.calculate_confidence("AAAA", &context);
    assert!(score < 0.5, "Low entropy should have low confidence");
}

#[test]
fn test_entropy_filter_high_entropy() {
    let filter = EntropyFilter::new(1.5, 7.5);
    let context = FilterContext::default();

    // High entropy (random-like)
    // Note: This string may not always have entropy > 7.5 due to repetition of patterns
    // The test verifies that very high entropy strings get lower confidence than normal text
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
fn test_entropy_filter_normal_text() {
    let filter = EntropyFilter::new(1.5, 7.5);
    let context = FilterContext::default();

    let score = filter.calculate_confidence("Hello, World!", &context);
    assert!(score > 0.5, "Normal text should have reasonable confidence");
}

#[test]
fn test_entropy_filter_edge_cases() {
    let filter = EntropyFilter::new(1.5, 7.5);
    let context = FilterContext::default();

    // Test at threshold boundaries
    let score1 = filter.calculate_confidence("\x00\x00\x00\x00", &context);
    assert!(score1 < 0.5);

    let score2 = filter.calculate_confidence("Error: file not found", &context);
    assert!(score2 > 0.5);
}

#[test]
fn test_linguistic_filter_english_like() {
    let filter = LinguisticFilter::new(0.1, 0.9);
    let context = FilterContext::default();

    let score = filter.calculate_confidence("Hello world", &context);
    assert!(score > 0.7, "English-like text should have high confidence");
}

#[test]
fn test_linguistic_filter_consonant_heavy() {
    let filter = LinguisticFilter::new(0.1, 0.9);
    let context = FilterContext::default();

    let score = filter.calculate_confidence("bcdfghjklmnpqrstvwxyz", &context);
    assert!(score < 0.7, "Consonant-heavy should have lower confidence");
}

#[test]
fn test_linguistic_filter_vowel_heavy() {
    let filter = LinguisticFilter::new(0.1, 0.9);
    let context = FilterContext::default();

    let score = filter.calculate_confidence("aeiouaeiou", &context);
    assert!(score < 0.7, "Vowel-heavy should have lower confidence");
}

#[test]
fn test_linguistic_filter_with_numbers() {
    let filter = LinguisticFilter::new(0.1, 0.9);
    let context = FilterContext::default();

    let score = filter.calculate_confidence("Error 404", &context);
    assert!(
        score > 0.5,
        "Text with numbers should have reasonable confidence"
    );
}

#[test]
fn test_length_filter_very_short() {
    let filter = LengthFilter::new(200);
    let context = FilterContext {
        section_weight: 0.3,
        ..Default::default()
    };

    let score = filter.calculate_confidence("Hi", &context);
    assert!(
        score < 0.7,
        "Very short in low-weight section should have lower confidence"
    );
}

#[test]
fn test_length_filter_normal_length() {
    let filter = LengthFilter::new(200);
    let context = FilterContext::default();

    let score = filter.calculate_confidence("Hello", &context);
    assert!(score > 0.7, "Normal length should have high confidence");
}

#[test]
fn test_length_filter_very_long() {
    let filter = LengthFilter::new(200);
    let context = FilterContext::default();

    let long_string = "A".repeat(300);
    let score = filter.calculate_confidence(&long_string, &context);
    assert!(score < 0.5, "Very long string should have low confidence");
}

#[test]
fn test_repetition_filter_repeated_characters() {
    let filter = RepetitionFilter::new(0.7);
    let context = FilterContext::default();

    let score = filter.calculate_confidence("AAAA", &context);
    assert!(
        score < 0.5,
        "Repeated characters should have low confidence"
    );
}

#[test]
fn test_repetition_filter_repeated_pattern() {
    let filter = RepetitionFilter::new(0.7);
    let context = FilterContext::default();

    let score = filter.calculate_confidence("abcabcabc", &context);
    assert!(score < 0.5, "Repeated pattern should have low confidence");
}

#[test]
fn test_repetition_filter_normal_string() {
    let filter = RepetitionFilter::new(0.7);
    let context = FilterContext::default();

    let score = filter.calculate_confidence("Hello", &context);
    assert!(score > 0.7, "Normal string should have high confidence");
}

#[test]
fn test_repetition_filter_some_repetition() {
    let filter = RepetitionFilter::new(0.7);
    let context = FilterContext::default();

    // "Mississippi" has some repetition but is legitimate
    let score = filter.calculate_confidence("Mississippi", &context);
    assert!(
        score > 0.5,
        "Some repetition in legitimate text should be acceptable"
    );
}

#[test]
fn test_context_filter_string_data_section() {
    let filter = ContextFilter;
    let context = FilterContext {
        section_type: SectionType::StringData,
        is_executable: false,
        is_writable: false,
        ..Default::default()
    };

    let score = filter.calculate_confidence("test", &context);
    assert!(
        score > 0.8,
        "String data section should have high confidence"
    );
}

#[test]
fn test_context_filter_code_section() {
    let filter = ContextFilter;
    let context = FilterContext {
        section_type: SectionType::Code,
        section_weight: 0.1,
        ..Default::default()
    };

    let score = filter.calculate_confidence("test", &context);
    assert!(score < 0.5, "Code section should have lower confidence");
}

#[test]
fn test_context_filter_resources_section() {
    let filter = ContextFilter;
    let context = FilterContext {
        section_type: SectionType::Resources,
        ..Default::default()
    };

    let score = filter.calculate_confidence("test", &context);
    assert_eq!(
        score, 1.0,
        "Resources section should have maximum confidence"
    );
}

#[test]
fn test_composite_filter_legitimate_string() {
    let config = NoiseFilterConfig::default();
    let filter = CompositeNoiseFilter::new(&config);
    let context = FilterContext::default();

    let score = filter.calculate_confidence("Hello, World!", &context);
    assert!(
        score > 0.5,
        "Legitimate string should have reasonable confidence"
    );
}

#[test]
fn test_composite_filter_noise() {
    let config = NoiseFilterConfig::default();
    let filter = CompositeNoiseFilter::new(&config);
    let context = FilterContext::default();

    let score = filter.calculate_confidence("AAAA", &context);
    assert!(score < 0.5, "Noise should have low confidence");
}

#[test]
fn test_composite_filter_custom_weights() {
    let config = NoiseFilterConfig {
        filter_weights: FilterWeights {
            entropy_weight: 0.5,
            char_distribution_weight: 0.3,
            linguistic_weight: 0.1,
            length_weight: 0.05,
            repetition_weight: 0.03,
            context_weight: 0.02,
        },
        ..Default::default()
    };

    let filter = CompositeNoiseFilter::new(&config);
    let context = FilterContext::default();

    let score = filter.calculate_confidence("Hello, World!", &context);
    assert!(score > 0.0, "Should produce a valid score");
}

#[test]
fn test_composite_filter_enable_disable() {
    let config = NoiseFilterConfig::default();
    let mut filter = CompositeNoiseFilter::new(&config);
    filter.enable_entropy = false;
    filter.enable_linguistic = false;

    let context = FilterContext::default();
    let score = filter.calculate_confidence("Hello", &context);
    assert!(score > 0.0, "Should work with some filters disabled");
}

#[test]
fn test_real_world_scenarios() {
    let config = NoiseFilterConfig::default();
    let filter = CompositeNoiseFilter::new(&config);
    let context = FilterContext::default();

    // Legitimate strings
    let legitimate = [
        "Error: file not found",
        "Hello, World!",
        "C:\\Windows\\System32",
        "https://example.com",
    ];

    for text in &legitimate {
        let score = filter.calculate_confidence(text, &context);
        assert!(
            score > 0.5,
            "Legitimate string '{}' should have reasonable confidence",
            text
        );
    }

    // Obvious noise
    let noise = ["\x00\x00\x00\x00", "AAAA", "!!!@@@###", "00000000"];

    for text in &noise {
        let score = filter.calculate_confidence(text, &context);
        assert!(score < 0.5, "Noise '{}' should have low confidence", text);
    }
}
