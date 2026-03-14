//! Noise filter implementations
//!
//! Contains all individual filter structs and their `NoiseFilter` trait implementations:
//! `CharDistributionFilter`, `EntropyFilter`, `LinguisticFilter`, `LengthFilter`,
//! `RepetitionFilter`, and `ContextFilter`.

use crate::types::SectionType;

use super::{CharStats, FilterContext, NoiseFilter};

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
        self.confidence_with_stats(text, &CharStats::new(text))
    }
}

impl CharDistributionFilter {
    /// Calculate confidence using pre-computed char stats (avoids redundant allocation).
    pub(crate) fn confidence_with_stats(&self, _text: &str, stats: &CharStats) -> f32 {
        if stats.chars.is_empty() {
            return 0.0;
        }

        let total = stats.chars.len() as f32;

        // Check for excessive punctuation
        let punctuation_ratio = stats.punctuation_count as f32 / total;
        if punctuation_ratio > 0.8 {
            return 0.2; // Very low confidence
        }

        // Check for excessive repetition of same character
        let max_char_count = stats.char_counts.values().max().copied().unwrap_or(0) as f32;
        let max_char_ratio = max_char_count / total;
        if max_char_ratio > 0.9 {
            return 0.1; // Very low confidence (likely padding)
        }

        // Check for excessive non-alphanumeric
        let non_alphanumeric_ratio = 1.0 - (stats.alphanumeric_count as f32 / total);
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
        self.confidence_with_stats(text, &CharStats::new(text))
    }
}

impl LinguisticFilter {
    /// Calculate confidence using pre-computed char stats (avoids redundant allocation).
    pub(crate) fn confidence_with_stats(&self, text: &str, stats: &CharStats) -> f32 {
        if stats.chars.is_empty() {
            return 0.0;
        }

        let letter_count = stats.vowel_count + stats.consonant_count;
        if letter_count == 0 {
            // No letters -- strings with only numbers/symbols might still be legitimate
            return 0.6;
        }

        let vowel_ratio = stats.vowel_count as f32 / letter_count as f32;

        // Consonant-heavy (might be noise or non-English)
        if vowel_ratio < self.min_vowel_ratio {
            return 0.5;
        }
        // Vowel-heavy (likely noise)
        if vowel_ratio > self.max_vowel_ratio {
            return 0.3;
        }

        // Check for common English bigrams
        let common_bigrams = ["th", "he", "in", "er", "an", "re", "on", "at", "en", "nd"];
        let text_lower = text.to_ascii_lowercase();
        let bigram_count = common_bigrams
            .iter()
            .filter(|bigram| text_lower.contains(*bigram))
            .count();

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
        self.confidence_with_stats(text, &CharStats::new(text))
    }
}

impl RepetitionFilter {
    /// Calculate confidence using pre-computed char stats (avoids redundant allocation).
    pub(crate) fn confidence_with_stats(&self, _text: &str, stats: &CharStats) -> f32 {
        if stats.chars.is_empty() {
            return 0.0;
        }

        let total = stats.chars.len() as f32;

        // Check for repeated characters using pre-computed counts
        let max_char_count = stats.char_counts.values().max().copied().unwrap_or(0) as f32;
        let max_char_ratio = max_char_count / total;

        if max_char_ratio > self.max_repetition_ratio {
            return 0.1; // Very low confidence (likely padding)
        }

        // Check for repeated substrings (optimized to avoid O(n^3))
        // Cap pattern_len to a small bound (8-16) to avoid excessive computation
        let max_pattern_len = (total as usize / 3).min(16).min(stats.chars.len());

        if total >= 6.0 && max_pattern_len > 0 {
            // Early exit: if we cannot possibly get 3 repetitions, skip
            let min_pattern_len_for_3_reps = ((total as usize) as f32 / 3.0).ceil() as usize;
            if min_pattern_len_for_3_reps > max_pattern_len {
                return 1.0;
            }

            for pattern_len in 1..=max_pattern_len {
                // Early exit: if pattern_len is too large to repeat 3 times, skip
                if pattern_len * 3 > stats.chars.len() {
                    break;
                }

                // Use slice comparison instead of constructing String
                let pattern_slice = &stats.chars[0..pattern_len];
                let mut count = 1; // First occurrence
                let mut pos = pattern_len;

                while pos + pattern_len <= stats.chars.len() && count < 3 {
                    let candidate_slice = &stats.chars[pos..pos + pattern_len];
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
