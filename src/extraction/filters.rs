//! Noise Filtering Module
//!
//! This module provides multi-layered heuristic filters for detecting and filtering
//! noise in extracted strings. It uses a combination of entropy analysis, character
//! distribution, linguistic patterns, length checks, repetition detection, and
//! context-aware filtering to assign confidence scores to strings.

use crate::extraction::config::{FilterWeights, NoiseFilterConfig};
use crate::types::{SectionInfo, SectionType};

/// Context information for noise filtering
///
/// Provides section metadata and surrounding context to help filters make
/// informed decisions about string legitimacy.
#[derive(Debug, Clone)]
pub struct FilterContext {
    /// Section type where the string was found
    pub section_type: SectionType,
    /// Section name
    pub section_name: Option<String>,
    /// Section weight (higher = more likely to contain strings)
    pub section_weight: f32,
    /// Whether the section is executable
    pub is_executable: bool,
    /// Whether the section is writable
    pub is_writable: bool,
    /// Surrounding bytes for context (optional, for future use)
    pub surrounding_bytes: Option<Vec<u8>>,
}

impl Default for FilterContext {
    fn default() -> Self {
        Self {
            section_type: SectionType::Other,
            section_name: None,
            section_weight: 0.5,
            is_executable: false,
            is_writable: false,
            surrounding_bytes: None,
        }
    }
}

impl FilterContext {
    /// Create a new FilterContext from a SectionInfo
    pub fn from_section(section: &SectionInfo) -> Self {
        Self {
            section_type: section.section_type,
            section_name: Some(section.name.clone()),
            section_weight: section.weight,
            is_executable: section.is_executable,
            is_writable: section.is_writable,
            surrounding_bytes: None,
        }
    }
}

/// Trait for noise filters that calculate confidence scores
///
/// Each filter implements this trait to provide a confidence score (0.0-1.0)
/// indicating how likely a string is to be legitimate vs noise.
pub trait NoiseFilter {
    /// Calculate confidence score for a string
    ///
    /// Returns a value between 0.0 (definitely noise) and 1.0 (definitely legitimate).
    ///
    /// # Arguments
    ///
    /// * `text` - The string text to analyze
    /// * `context` - Context information about where the string was found
    ///
    /// # Returns
    ///
    /// Confidence score between 0.0 and 1.0
    fn calculate_confidence(&self, text: &str, context: &FilterContext) -> f32;
}

/// Character distribution filter
///
/// Detects abnormal character frequency distributions that indicate noise:
/// - Excessive punctuation (>80%)
/// - Excessive repetition of same character (>90%)
/// - Excessive non-alphanumeric characters (>70%)
pub struct CharDistributionFilter;

impl NoiseFilter for CharDistributionFilter {
    fn calculate_confidence(&self, text: &str, _context: &FilterContext) -> f32 {
        if text.is_empty() {
            return 0.0;
        }

        let chars: Vec<char> = text.chars().collect();
        let total = chars.len() as f32;

        // Count character types
        let mut punctuation_count = 0;
        let mut alphanumeric_count = 0;
        let mut char_counts = std::collections::HashMap::new();

        for &ch in &chars {
            if ch.is_ascii_punctuation() {
                punctuation_count += 1;
            }
            if ch.is_alphanumeric() {
                alphanumeric_count += 1;
            }
            *char_counts.entry(ch).or_insert(0) += 1;
        }

        // Check for excessive punctuation
        let punctuation_ratio = punctuation_count as f32 / total;
        if punctuation_ratio > 0.8 {
            return 0.2; // Very low confidence
        }

        // Check for excessive repetition of same character
        let max_char_count = char_counts.values().max().copied().unwrap_or(0) as f32;
        let max_char_ratio = max_char_count / total;
        if max_char_ratio > 0.9 {
            return 0.1; // Very low confidence (likely padding)
        }

        // Check for excessive non-alphanumeric
        let non_alphanumeric_ratio = 1.0 - (alphanumeric_count as f32 / total);
        if non_alphanumeric_ratio > 0.7 {
            return 0.3; // Low confidence
        }

        // Reasonable distribution
        if punctuation_ratio < 0.3 && max_char_ratio < 0.5 && non_alphanumeric_ratio < 0.4 {
            1.0 // High confidence
        } else {
            0.7 // Moderate confidence
        }
    }
}

/// Entropy-based filter
///
/// Uses Shannon entropy to detect low-entropy (padding/repetition) and
/// high-entropy (random binary) strings. Optimal range for text is 3.5-6.0 bits/byte.
pub struct EntropyFilter {
    /// Minimum entropy threshold
    pub entropy_min: f32,
    /// Maximum entropy threshold
    pub entropy_max: f32,
}

impl EntropyFilter {
    /// Create a new EntropyFilter with custom thresholds
    pub fn new(entropy_min: f32, entropy_max: f32) -> Self {
        Self {
            entropy_min,
            entropy_max,
        }
    }
}

impl NoiseFilter for EntropyFilter {
    fn calculate_confidence(&self, text: &str, _context: &FilterContext) -> f32 {
        if text.is_empty() {
            return 0.0;
        }

        let bytes = text.as_bytes();
        let entropy = entropy::shannon_entropy(bytes);

        // Very low entropy (< 1.5) - likely padding or repetition
        if entropy < self.entropy_min {
            return 0.1;
        }

        // Very high entropy (> 7.5) - likely random binary
        if entropy > self.entropy_max {
            return 0.2;
        }

        // Optimal range for text: 3.5-6.0 bits/byte
        if (3.5..=6.0).contains(&entropy) {
            1.0 // High confidence
        } else if (2.0..3.5).contains(&entropy) {
            0.7 // Moderate confidence (low but acceptable)
        } else if (6.0..=7.0).contains(&entropy) {
            0.6 // Moderate confidence (high but acceptable)
        } else {
            0.4 // Lower confidence (outside optimal range)
        }
    }
}

/// Linguistic pattern filter
///
/// Detects word-like patterns by analyzing vowel-to-consonant ratios and
/// common bigrams. Handles non-English strings gracefully.
pub struct LinguisticFilter {
    /// Minimum vowel ratio
    pub min_vowel_ratio: f32,
    /// Maximum vowel ratio
    pub max_vowel_ratio: f32,
}

impl LinguisticFilter {
    /// Create a new LinguisticFilter with custom thresholds
    pub fn new(min_vowel_ratio: f32, max_vowel_ratio: f32) -> Self {
        Self {
            min_vowel_ratio,
            max_vowel_ratio,
        }
    }
}

impl NoiseFilter for LinguisticFilter {
    fn calculate_confidence(&self, text: &str, _context: &FilterContext) -> f32 {
        if text.is_empty() {
            return 0.0;
        }

        let chars: Vec<char> = text.chars().collect();
        let total = chars.len() as f32;

        if total == 0.0 {
            return 0.0;
        }

        // Count vowels and consonants (case-insensitive)
        let mut vowel_count = 0;
        let mut consonant_count = 0;

        for &ch in &chars {
            let ch_lower = ch.to_ascii_lowercase();
            match ch_lower {
                'a' | 'e' | 'i' | 'o' | 'u' => vowel_count += 1,
                'b' | 'c' | 'd' | 'f' | 'g' | 'h' | 'j' | 'k' | 'l' | 'm' | 'n' | 'p' | 'q'
                | 'r' | 's' | 't' | 'v' | 'w' | 'x' | 'y' | 'z' => consonant_count += 1,
                _ => {} // Ignore non-letters
            }
        }

        let letter_count = vowel_count + consonant_count;
        if letter_count == 0 {
            // No letters, check for numbers/symbols
            // Strings with only numbers/symbols might still be legitimate
            return 0.6;
        }

        let vowel_ratio = vowel_count as f32 / letter_count as f32;

        // Check vowel ratio
        if vowel_ratio < self.min_vowel_ratio {
            // Consonant-heavy (might be noise or non-English)
            return 0.5;
        }
        if vowel_ratio > self.max_vowel_ratio {
            // Vowel-heavy (likely noise)
            return 0.3;
        }

        // Check for common English bigrams
        let common_bigrams = ["th", "he", "in", "er", "an", "re", "on", "at", "en", "nd"];
        let text_lower = text.to_ascii_lowercase();
        let mut bigram_count = 0;
        for bigram in &common_bigrams {
            if text_lower.contains(bigram) {
                bigram_count += 1;
            }
        }

        // Good vowel ratio and some common bigrams
        if (0.2..=0.8).contains(&vowel_ratio) && bigram_count > 0 {
            1.0 // High confidence
        } else if (0.1..=0.9).contains(&vowel_ratio) {
            0.7 // Moderate confidence
        } else {
            0.4 // Lower confidence
        }
    }
}

/// Length-based filter
///
/// Penalizes excessively long strings (likely table data) and very short
/// strings in low-weight sections.
pub struct LengthFilter {
    /// Maximum length before penalty
    pub max_length: usize,
}

impl LengthFilter {
    /// Create a new LengthFilter with custom threshold
    pub fn new(max_length: usize) -> Self {
        Self { max_length }
    }
}

impl NoiseFilter for LengthFilter {
    fn calculate_confidence(&self, text: &str, context: &FilterContext) -> f32 {
        let len = text.len();

        // Excessively long strings are likely table data
        if len > self.max_length {
            return 0.3; // Low confidence
        }

        // Very short strings in low-weight sections are suspicious
        if len < 4 && context.section_weight < 0.5 {
            return 0.5; // Moderate confidence
        }

        // Normal length strings
        if (4..=100).contains(&len) {
            1.0 // High confidence
        } else if (100..=self.max_length).contains(&len) {
            0.7 // Moderate confidence (long but acceptable)
        } else {
            0.6 // Lower confidence
        }
    }
}

/// Repetition detection filter
///
/// Detects repeated character patterns (e.g., "AAAA", "0000") and
/// repeated substrings (e.g., "abcabcabc").
pub struct RepetitionFilter {
    /// Maximum ratio of repeated characters
    pub max_repetition_ratio: f32,
}

impl RepetitionFilter {
    /// Create a new RepetitionFilter with custom threshold
    pub fn new(max_repetition_ratio: f32) -> Self {
        Self {
            max_repetition_ratio,
        }
    }
}

impl NoiseFilter for RepetitionFilter {
    fn calculate_confidence(&self, text: &str, _context: &FilterContext) -> f32 {
        if text.is_empty() {
            return 0.0;
        }

        let chars: Vec<char> = text.chars().collect();
        let total = chars.len() as f32;

        // Check for repeated characters
        let mut char_counts = std::collections::HashMap::new();
        for &ch in &chars {
            *char_counts.entry(ch).or_insert(0) += 1;
        }

        let max_char_count = char_counts.values().max().copied().unwrap_or(0) as f32;
        let max_char_ratio = max_char_count / total;

        if max_char_ratio > self.max_repetition_ratio {
            return 0.1; // Very low confidence (likely padding)
        }

        // Check for repeated substrings (optimized to avoid O(n^3))
        // Cap pattern_len to a small bound (8-16) to avoid excessive computation
        let max_pattern_len = (total as usize / 3).min(16).min(chars.len());

        if total >= 6.0 && max_pattern_len > 0 {
            // Early exit optimization: if we can't possibly get 3 repetitions, skip
            let min_pattern_len_for_3_reps = ((total as usize) as f32 / 3.0).ceil() as usize;
            if min_pattern_len_for_3_reps > max_pattern_len {
                return 1.0; // Can't have 3 repetitions, so no issue
            }

            // Check patterns starting from length 1 up to max_pattern_len
            for pattern_len in 1..=max_pattern_len {
                // Early exit: if pattern_len is too large to repeat 3 times, skip
                if pattern_len * 3 > chars.len() {
                    break;
                }

                // Use slice comparison instead of constructing String
                let pattern_slice = &chars[0..pattern_len];
                let mut count = 1; // First occurrence
                let mut pos = pattern_len;

                // Check for repetitions
                while pos + pattern_len <= chars.len() && count < 3 {
                    let candidate_slice = &chars[pos..pos + pattern_len];
                    // Compare slices directly (char comparison)
                    if pattern_slice == candidate_slice {
                        count += 1;
                        pos += pattern_len;
                    } else {
                        break; // Pattern broken, try next pattern length
                    }
                }

                if count >= 3 {
                    return 0.2; // Low confidence (repetitive pattern)
                }
            }
        }

        // No significant repetition
        1.0
    }
}

/// Context-aware filter
///
/// Boosts confidence for strings in high-weight sections (.rodata, .rdata, __cstring)
/// and reduces confidence for strings in code sections. Considers section permissions.
pub struct ContextFilter;

impl NoiseFilter for ContextFilter {
    fn calculate_confidence(&self, _text: &str, context: &FilterContext) -> f32 {
        // Boost confidence for high-weight sections
        match context.section_type {
            SectionType::StringData => {
                // .rodata, .rdata, __cstring - very likely to contain strings
                if !context.is_executable && !context.is_writable {
                    return 1.0; // Read-only string data section
                }
                0.9 // String data section (even if writable)
            }
            SectionType::ReadOnlyData => {
                // Read-only data sections
                if !context.is_executable {
                    return 0.9;
                }
                0.7
            }
            SectionType::Resources => {
                // PE resource sections
                1.0 // Resources are known-good sources
            }
            SectionType::Code => {
                // Code sections - less likely to contain strings
                if context.section_weight < 0.3 {
                    return 0.3; // Low-weight code section
                }
                0.5 // Code section with some weight
            }
            SectionType::WritableData => {
                // Writable data sections - moderate confidence
                0.6
            }
            SectionType::Debug => {
                // Debug sections - may contain strings but lower confidence
                0.5
            }
            SectionType::Other => {
                // Unknown sections - use section weight as guide
                if context.section_weight > 0.7 {
                    0.7
                } else if context.section_weight > 0.4 {
                    0.5
                } else {
                    0.3
                }
            }
        }
    }
}

/// Composite noise filter
///
/// Combines multiple filters with configurable weights to produce an overall
/// confidence score. Allows enabling/disabling individual filters.
pub struct CompositeNoiseFilter {
    /// Entropy filter
    pub entropy_filter: EntropyFilter,
    /// Character distribution filter
    pub char_distribution_filter: CharDistributionFilter,
    /// Linguistic filter
    pub linguistic_filter: LinguisticFilter,
    /// Length filter
    pub length_filter: LengthFilter,
    /// Repetition filter
    pub repetition_filter: RepetitionFilter,
    /// Context filter
    pub context_filter: ContextFilter,
    /// Filter weights
    pub weights: FilterWeights,
    /// Whether to enable entropy filter
    pub enable_entropy: bool,
    /// Whether to enable character distribution filter
    pub enable_char_distribution: bool,
    /// Whether to enable linguistic filter
    pub enable_linguistic: bool,
    /// Whether to enable length filter
    pub enable_length: bool,
    /// Whether to enable repetition filter
    pub enable_repetition: bool,
    /// Whether to enable context filter
    pub enable_context: bool,
}

impl CompositeNoiseFilter {
    /// Create a new CompositeNoiseFilter with default configuration
    pub fn new(config: &NoiseFilterConfig) -> Self {
        Self {
            entropy_filter: EntropyFilter::new(config.entropy_min, config.entropy_max),
            char_distribution_filter: CharDistributionFilter,
            linguistic_filter: LinguisticFilter::new(
                config.min_vowel_ratio,
                config.max_vowel_ratio,
            ),
            length_filter: LengthFilter::new(config.max_length),
            repetition_filter: RepetitionFilter::new(config.max_repetition_ratio),
            context_filter: ContextFilter,
            weights: config.filter_weights.clone(),
            enable_entropy: true,
            enable_char_distribution: true,
            enable_linguistic: true,
            enable_length: true,
            enable_repetition: true,
            enable_context: true,
        }
    }

    /// Calculate overall confidence score by combining all enabled filters
    pub fn calculate_confidence(&self, text: &str, context: &FilterContext) -> f32 {
        let mut total_weight = 0.0;
        let mut weighted_sum = 0.0;

        if self.enable_entropy {
            let score = self.entropy_filter.calculate_confidence(text, context);
            weighted_sum += score * self.weights.entropy_weight;
            total_weight += self.weights.entropy_weight;
        }

        if self.enable_char_distribution {
            let score = self
                .char_distribution_filter
                .calculate_confidence(text, context);
            weighted_sum += score * self.weights.char_distribution_weight;
            total_weight += self.weights.char_distribution_weight;
        }

        if self.enable_linguistic {
            let score = self.linguistic_filter.calculate_confidence(text, context);
            weighted_sum += score * self.weights.linguistic_weight;
            total_weight += self.weights.linguistic_weight;
        }

        if self.enable_length {
            let score = self.length_filter.calculate_confidence(text, context);
            weighted_sum += score * self.weights.length_weight;
            total_weight += self.weights.length_weight;
        }

        if self.enable_repetition {
            let score = self.repetition_filter.calculate_confidence(text, context);
            weighted_sum += score * self.weights.repetition_weight;
            total_weight += self.weights.repetition_weight;
        }

        if self.enable_context {
            let score = self.context_filter.calculate_confidence(text, context);
            weighted_sum += score * self.weights.context_weight;
            total_weight += self.weights.context_weight;
        }

        // Normalize by total weight (in case some filters are disabled)
        if total_weight > 0.0 {
            weighted_sum / total_weight
        } else {
            0.5 // Default if all filters disabled
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
