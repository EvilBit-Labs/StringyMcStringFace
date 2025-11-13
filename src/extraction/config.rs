//! Extraction Configuration Module
//!
//! This module provides configuration structures for controlling string extraction
//! and noise filtering behavior. It allows fine-tuning of thresholds, filter weights,
//! and extraction parameters.

/// Configuration for noise filtering heuristics
///
/// Controls thresholds and parameters for the various noise detection filters.
/// All thresholds are configurable to allow fine-tuning for different use cases.
///
/// # Example
///
/// ```rust
/// use stringy::extraction::config::NoiseFilterConfig;
///
/// // Use default configuration
/// let config = NoiseFilterConfig::default();
///
/// // Customize thresholds
/// let mut config = NoiseFilterConfig::default();
/// config.entropy_min = 2.0;
/// config.entropy_max = 7.0;
/// ```
#[derive(Debug, Clone)]
pub struct NoiseFilterConfig {
    /// Minimum entropy threshold in bits per byte (default: 1.5)
    ///
    /// Strings with entropy below this are likely padding or repetition.
    pub entropy_min: f32,
    /// Maximum entropy threshold in bits per byte (default: 7.5)
    ///
    /// Strings with entropy above this are likely random binary data.
    pub entropy_max: f32,
    /// Maximum string length before applying penalty (default: 200)
    ///
    /// Very long strings are often table data or other structured content.
    pub max_length: usize,
    /// Maximum ratio of repeated characters (default: 0.7)
    ///
    /// Strings with higher repetition ratios are likely padding or noise.
    pub max_repetition_ratio: f32,
    /// Minimum vowel ratio for linguistic filter (default: 0.1)
    ///
    /// Used to detect consonant-heavy strings that may be noise.
    pub min_vowel_ratio: f32,
    /// Maximum vowel ratio for linguistic filter (default: 0.9)
    ///
    /// Used to detect vowel-heavy strings that may be noise.
    pub max_vowel_ratio: f32,
    /// Weights for combining filter scores (default: balanced weights)
    pub filter_weights: FilterWeights,
}

impl Default for NoiseFilterConfig {
    fn default() -> Self {
        Self {
            entropy_min: 1.5,
            entropy_max: 7.5,
            max_length: 200,
            max_repetition_ratio: 0.7,
            min_vowel_ratio: 0.1,
            max_vowel_ratio: 0.9,
            filter_weights: FilterWeights::default(),
        }
    }
}

impl NoiseFilterConfig {
    /// Validate the configuration
    ///
    /// Returns an error if any thresholds are invalid.
    pub fn validate(&self) -> Result<(), String> {
        if self.entropy_min < 0.0 || self.entropy_min > 8.0 {
            return Err("entropy_min must be between 0.0 and 8.0".to_string());
        }
        if self.entropy_max < 0.0 || self.entropy_max > 8.0 {
            return Err("entropy_max must be between 0.0 and 8.0".to_string());
        }
        if self.entropy_min >= self.entropy_max {
            return Err("entropy_min must be less than entropy_max".to_string());
        }
        if self.max_length == 0 {
            return Err("max_length must be greater than 0".to_string());
        }
        if !(0.0..=1.0).contains(&self.max_repetition_ratio) {
            return Err("max_repetition_ratio must be between 0.0 and 1.0".to_string());
        }
        if !(0.0..=1.0).contains(&self.min_vowel_ratio) {
            return Err("min_vowel_ratio must be between 0.0 and 1.0".to_string());
        }
        if !(0.0..=1.0).contains(&self.max_vowel_ratio) {
            return Err("max_vowel_ratio must be between 0.0 and 1.0".to_string());
        }
        if self.min_vowel_ratio >= self.max_vowel_ratio {
            return Err("min_vowel_ratio must be less than max_vowel_ratio".to_string());
        }
        self.filter_weights.validate()?;
        Ok(())
    }
}

/// Weights for combining multiple filter confidence scores
///
/// These weights control how individual filter scores are combined into
/// an overall confidence assessment. All weights must sum to 1.0.
///
/// # Example
///
/// ```rust
/// use stringy::extraction::config::FilterWeights;
///
/// // Use default weights
/// let weights = FilterWeights::default();
///
/// // Customize weights (must sum to 1.0)
/// let weights = FilterWeights {
///     entropy_weight: 0.3,
///     char_distribution_weight: 0.25,
///     linguistic_weight: 0.2,
///     length_weight: 0.15,
///     repetition_weight: 0.05,
///     context_weight: 0.05,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct FilterWeights {
    /// Weight for entropy filter (default: 0.25)
    pub entropy_weight: f32,
    /// Weight for character distribution filter (default: 0.20)
    pub char_distribution_weight: f32,
    /// Weight for linguistic pattern filter (default: 0.20)
    pub linguistic_weight: f32,
    /// Weight for length filter (default: 0.15)
    pub length_weight: f32,
    /// Weight for repetition filter (default: 0.10)
    pub repetition_weight: f32,
    /// Weight for context-aware filter (default: 0.10)
    pub context_weight: f32,
}

impl Default for FilterWeights {
    fn default() -> Self {
        Self {
            entropy_weight: 0.25,
            char_distribution_weight: 0.20,
            linguistic_weight: 0.20,
            length_weight: 0.15,
            repetition_weight: 0.10,
            context_weight: 0.10,
        }
    }
}

impl FilterWeights {
    /// Validate that weights sum to 1.0
    ///
    /// Returns an error if the sum is not approximately 1.0 (within 0.01 tolerance).
    pub fn validate(&self) -> Result<(), String> {
        let sum = self.entropy_weight
            + self.char_distribution_weight
            + self.linguistic_weight
            + self.length_weight
            + self.repetition_weight
            + self.context_weight;
        if (sum - 1.0).abs() > 0.01 {
            return Err(format!("Filter weights must sum to 1.0, got {}", sum));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noise_filter_config_default() {
        let config = NoiseFilterConfig::default();
        assert_eq!(config.entropy_min, 1.5);
        assert_eq!(config.entropy_max, 7.5);
        assert_eq!(config.max_length, 200);
        assert_eq!(config.max_repetition_ratio, 0.7);
    }

    #[test]
    fn test_noise_filter_config_validate() {
        let mut config = NoiseFilterConfig::default();
        assert!(config.validate().is_ok());

        config.entropy_min = 8.0;
        assert!(config.validate().is_err());

        config.entropy_min = 1.5;
        config.entropy_max = 1.0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_filter_weights_default() {
        let weights = FilterWeights::default();
        assert_eq!(weights.entropy_weight, 0.25);
        assert_eq!(weights.char_distribution_weight, 0.20);
        assert_eq!(weights.linguistic_weight, 0.20);
        assert_eq!(weights.length_weight, 0.15);
        assert_eq!(weights.repetition_weight, 0.10);
        assert_eq!(weights.context_weight, 0.10);
    }

    #[test]
    fn test_filter_weights_validate() {
        let weights = FilterWeights::default();
        assert!(weights.validate().is_ok());

        let bad_weights = FilterWeights {
            entropy_weight: 0.5,
            ..Default::default()
        };
        assert!(bad_weights.validate().is_err());
    }
}
