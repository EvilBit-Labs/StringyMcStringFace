//! Noise Filtering Module
//!
//! This module provides multi-layered heuristic filters for detecting and filtering
//! noise in extracted strings. It uses a combination of entropy analysis, character
//! distribution, linguistic patterns, length checks, repetition detection, and
//! context-aware filtering to assign confidence scores to strings.

mod implementations;
#[cfg(test)]
mod tests;

use crate::extraction::config::{FilterWeights, NoiseFilterConfig};
use crate::types::{SectionInfo, SectionType};

pub use implementations::{
    CharDistributionFilter, ContextFilter, EntropyFilter, LengthFilter, LinguisticFilter,
    RepetitionFilter,
};

/// Pre-computed character statistics shared across filters.
///
/// Avoids repeated `chars().collect()` when multiple filters analyze the same string.
pub(crate) struct CharStats {
    pub chars: Vec<char>,
    pub char_counts: std::collections::HashMap<char, usize>,
    pub punctuation_count: usize,
    pub alphanumeric_count: usize,
    pub vowel_count: usize,
    pub consonant_count: usize,
}

impl CharStats {
    pub fn new(text: &str) -> Self {
        let chars: Vec<char> = text.chars().collect();
        let mut char_counts = std::collections::HashMap::new();
        let mut punctuation_count = 0;
        let mut alphanumeric_count = 0;
        let mut vowel_count = 0;
        let mut consonant_count = 0;

        for &ch in &chars {
            *char_counts.entry(ch).or_insert(0) += 1;
            if ch.is_ascii_punctuation() {
                punctuation_count += 1;
            }
            if ch.is_alphanumeric() {
                alphanumeric_count += 1;
            }
            let ch_lower = ch.to_ascii_lowercase();
            match ch_lower {
                'a' | 'e' | 'i' | 'o' | 'u' => vowel_count += 1,
                'b'..='d' | 'f'..='h' | 'j'..='n' | 'p'..='t' | 'v'..='z' => {
                    consonant_count += 1;
                }
                _ => {}
            }
        }

        Self {
            chars,
            char_counts,
            punctuation_count,
            alphanumeric_count,
            vowel_count,
            consonant_count,
        }
    }
}

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
    ///
    /// Pre-computes shared `CharStats` once when char-dependent filters are enabled,
    /// avoiding 3 separate `chars().collect()` allocations.
    pub fn calculate_confidence(&self, text: &str, context: &FilterContext) -> f32 {
        let mut total_weight = 0.0;
        let mut weighted_sum = 0.0;

        // Pre-compute char stats once for filters that need them (only if
        // the filter is both enabled AND has a non-zero weight).
        let needs_char_stats = (self.enable_char_distribution
            && self.weights.char_distribution_weight > 0.0)
            || (self.enable_linguistic && self.weights.linguistic_weight > 0.0)
            || (self.enable_repetition && self.weights.repetition_weight > 0.0);
        let stats = if needs_char_stats && !text.is_empty() {
            Some(CharStats::new(text))
        } else {
            None
        };

        if self.enable_entropy {
            let score = self.entropy_filter.calculate_confidence(text, context);
            weighted_sum += score * self.weights.entropy_weight;
            total_weight += self.weights.entropy_weight;
        }

        if self.enable_char_distribution {
            let score = match &stats {
                Some(s) => self.char_distribution_filter.confidence_with_stats(text, s),
                None => self
                    .char_distribution_filter
                    .calculate_confidence(text, context),
            };
            weighted_sum += score * self.weights.char_distribution_weight;
            total_weight += self.weights.char_distribution_weight;
        }

        if self.enable_linguistic {
            let score = match &stats {
                Some(s) => self.linguistic_filter.confidence_with_stats(text, s),
                None => self.linguistic_filter.calculate_confidence(text, context),
            };
            weighted_sum += score * self.weights.linguistic_weight;
            total_weight += self.weights.linguistic_weight;
        }

        if self.enable_length {
            let score = self.length_filter.calculate_confidence(text, context);
            weighted_sum += score * self.weights.length_weight;
            total_weight += self.weights.length_weight;
        }

        if self.enable_repetition {
            let score = match &stats {
                Some(s) => self.repetition_filter.confidence_with_stats(text, s),
                None => self.repetition_filter.calculate_confidence(text, context),
            };
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
