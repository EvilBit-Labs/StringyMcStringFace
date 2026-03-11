//! Ranking and scoring system for extracted strings
//!
//! This module provides a configurable scoring algorithm that prioritizes and ranks
//! strings extracted from binaries based on multiple factors:
//!
//! - **Section weights**: Strings from high-value sections (e.g., `.rodata`, resources)
//!   receive higher base scores than strings from low-value sections (e.g., code, debug)
//! - **Semantic tag boosts**: Strings with meaningful semantic tags (e.g., URLs, IPs,
//!   imports/exports) receive additional score boosts
//! - **Noise penalties**: Strings with low confidence scores are penalized to reduce
//!   false positives and noisy output
//!
//! The final score for each string is computed as:
//! ```text
//! score = section_weight + semantic_boost - noise_penalty
//! ```
//!
//! ## Usage Example
//!
//! ```rust
//! use stringy::classification::{RankingEngine, RankingConfig};
//! use stringy::types::{FoundString, SectionInfo, Encoding, StringSource};
//!
//! // Use default configuration
//! let engine = RankingEngine::new(false);
//!
//! // Or customize configuration
//! let mut config = RankingConfig::default();
//! config.noise_penalty_multiplier = 150; // Increase noise penalties
//! let engine = RankingEngine::with_config(config, true); // Enable debug mode
//!
//! // Score a string
//! let mut found_string = FoundString::new(
//!     "https://example.com".to_string(),
//!     Encoding::Ascii,
//!     0x1000,
//!     19,
//!     StringSource::SectionData,
//! );
//! engine.calculate_score(&mut found_string, None);
//!
//! // Rank a collection of strings
//! let mut strings = vec![/* ... */];
//! engine.rank_strings(&mut strings); // Sorted by score descending
//! ```
//!
//! ## Relationship Between RankingConfig and RankingEngine
//!
//! `RankingConfig` holds the scoring parameters (section weights, tag boosts, noise
//! penalty multiplier), while `RankingEngine` applies those parameters to compute
//! scores for individual strings. The engine is constructed with a config and then
//! used to score and rank collections of strings.

use std::collections::HashMap;

use crate::types::{FoundString, SectionInfo, SectionType, Tag};

/// Configuration for the `RankingEngine` scoring algorithm.
///
/// This struct controls how different container sections and semantic tags
/// contribute to the final score of a `FoundString`, and how aggressively
/// noisy or low-value strings are penalized.
///
/// All integer values in this configuration are treated as relative weights
/// or penalties in the scoring formula: higher values increase the influence
/// of a given factor, while lower or negative values reduce it. Typical
/// values are in the range `0..=200`, but any `i32` is accepted so callers
/// can tune ranking behavior for their use case.
///
/// The default configuration used by `RankingEngine` can be obtained via
/// [`RankingConfig::new`] or [`RankingConfig::default`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RankingConfig {
    /// Per-section weighting applied when scoring a `FoundString` based on
    /// the `SectionType` it was extracted from.
    ///
    /// Higher values cause strings from the corresponding section to rank
    /// higher relative to other sections. Typical values are in the range
    /// `0..=200`. Negative values are allowed to strongly de-prioritize
    /// specific section types if desired.
    pub section_weights: HashMap<SectionType, i32>,

    /// Per-tag scoring boosts applied when a `FoundString` has a particular
    /// semantic `Tag`.
    ///
    /// The value is added as a relative bonus to the base score of the
    /// string. Higher values make strings with that tag more prominent in
    /// ranked output. Typical values are in the range `0..=200`. Negative
    /// values can be used to penalize certain tags.
    pub tag_boosts: HashMap<Tag, i32>,

    /// Global multiplier applied to noise-related penalties in the scoring
    /// algorithm.
    ///
    /// Larger values increase the impact of noise detection (noisy strings
    /// lose more score), while smaller values reduce it. A value of `0`
    /// effectively disables noise penalties. Typical values are in the range
    /// `0..=200`.
    pub noise_penalty_multiplier: i32,
}

impl RankingConfig {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for RankingConfig {
    fn default() -> Self {
        let mut section_weights = HashMap::new();
        section_weights.insert(SectionType::StringData, 100);
        section_weights.insert(SectionType::ReadOnlyData, 70);
        section_weights.insert(SectionType::Resources, 100);
        section_weights.insert(SectionType::WritableData, 50);
        section_weights.insert(SectionType::Code, 10);
        section_weights.insert(SectionType::Debug, 30);
        section_weights.insert(SectionType::Other, 20);

        let mut tag_boosts = HashMap::new();
        tag_boosts.insert(Tag::Url, 50);
        tag_boosts.insert(Tag::Domain, 40);
        tag_boosts.insert(Tag::IPv4, 45);
        tag_boosts.insert(Tag::IPv6, 45);
        tag_boosts.insert(Tag::FilePath, 35);
        tag_boosts.insert(Tag::RegistryPath, 40);
        tag_boosts.insert(Tag::Guid, 30);
        tag_boosts.insert(Tag::Email, 35);
        tag_boosts.insert(Tag::DemangledSymbol, 25);
        tag_boosts.insert(Tag::Import, 60);
        tag_boosts.insert(Tag::Export, 60);
        tag_boosts.insert(Tag::Version, 40);
        tag_boosts.insert(Tag::Manifest, 40);
        tag_boosts.insert(Tag::Resource, 40);
        tag_boosts.insert(Tag::DylibPath, 35);
        tag_boosts.insert(Tag::Rpath, 35);
        tag_boosts.insert(Tag::RpathVariable, 35);
        tag_boosts.insert(Tag::FrameworkPath, 35);
        tag_boosts.insert(Tag::Base64, 10);
        tag_boosts.insert(Tag::FormatString, 15);
        tag_boosts.insert(Tag::UserAgent, 20);

        Self {
            section_weights,
            tag_boosts,
            noise_penalty_multiplier: 100,
        }
    }
}

/// Engine for scoring and ranking `FoundString` values.
///
/// `RankingEngine` applies a configurable scoring model to each `FoundString`
/// and then orders strings by their final score. The scoring model combines:
///
/// - Section weights from `RankingConfig`, based on the `SectionType` and
///   per-section `SectionInfo::weight`.
/// - Semantic tag boosts from `RankingConfig::tag_boosts`.
/// - A noise penalty derived from `FoundString::confidence` and
///   `RankingConfig::noise_penalty_multiplier`.
///
/// The `debug_mode` flag controls whether per-component scoring details are
/// written back to `FoundString` after `calculate_score` is called. When
/// `debug_mode` is `true`, the engine populates fields such as
/// `section_weight`, `semantic_boost`, and `noise_penalty` to make the
/// scoring breakdown visible to callers. When `false`, only the aggregate
/// `score` field is updated.
///
/// ## Typical Usage
///
/// 1. Optionally construct a `RankingConfig` with custom weights and boosts.
/// 2. Construct a `RankingEngine` with `new` or `with_config`, choosing
///    whether `debug_mode` should be enabled.
/// 3. For each `FoundString`, call `calculate_score`, passing the string and
///    an optional `SectionInfo` describing its origin.
/// 4. Once all scores are computed, call `rank_strings` on a collection of
///    `FoundString` values to sort them by score in descending order.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RankingEngine {
    config: RankingConfig,
    debug_mode: bool,
}

impl RankingEngine {
    /// Creates a new `RankingEngine` using the default `RankingConfig`.
    ///
    /// The `debug_mode` flag controls whether `calculate_score` populates
    /// detailed scoring components (`section_weight`, `semantic_boost`,
    /// `noise_penalty`) on each `FoundString`. When `debug_mode` is `false`,
    /// only the aggregate `score` field is updated.
    #[must_use]
    pub fn new(debug_mode: bool) -> Self {
        Self::with_config(RankingConfig::default(), debug_mode)
    }

    /// Creates a new `RankingEngine` with an explicit `RankingConfig`.
    ///
    /// - `config` provides section weights, tag boosts, and the noise penalty
    ///   multiplier that control how scores are computed.
    /// - `debug_mode` controls whether per-component scoring details are written
    ///   back to each `FoundString` when `calculate_score` is called.
    #[must_use]
    pub fn with_config(config: RankingConfig, debug_mode: bool) -> Self {
        Self { config, debug_mode }
    }

    /// Computes the score for a single `FoundString`.
    ///
    /// This method uses the current `RankingConfig` and optional `SectionInfo`
    /// to derive a final integer score using the formula:
    ///
    /// ```text
    /// score = section_weight + semantic_boost - noise_penalty
    /// ```
    ///
    /// The computation proceeds as follows:
    ///
    /// - Starts from a base section weight derived from `section_info` and the
    ///   configured `section_weights`, or a default of 20 when no match is found.
    /// - Applies the dynamic `SectionInfo::weight` factor if provided.
    /// - Adds semantic tag boosts for each tag present on the string.
    /// - Subtracts a noise penalty based on `FoundString::confidence`.
    ///
    /// The resulting value is written to `found_string.score`. If the engine
    /// was constructed with `debug_mode == true`, the method also populates
    /// `found_string.section_weight`, `found_string.semantic_boost`, and
    /// `found_string.noise_penalty` with the intermediate values used to
    /// produce the final score.
    ///
    /// # Parameters
    ///
    /// - `found_string` - The string record to score; it is modified in place
    ///   with the computed score (and optionally debug fields).
    /// - `section_info` - Optional metadata about the section from which the
    ///   string was extracted. When `None`, a default base section weight of 20
    ///   is used.
    pub fn calculate_score(
        &self,
        found_string: &mut FoundString,
        section_info: Option<&SectionInfo>,
    ) {
        let base_section_weight = section_info
            .and_then(|info| self.config.section_weights.get(&info.section_type).copied())
            .unwrap_or(20);

        let section_weight_score = section_info
            .map(|info| (base_section_weight as f32 * info.weight).round() as i32)
            .unwrap_or(base_section_weight);

        let semantic_boost_score = found_string
            .tags
            .iter()
            .map(|tag| self.config.tag_boosts.get(tag).copied().unwrap_or(0))
            .sum();

        let confidence = found_string.confidence.clamp(0.0, 1.0);
        let penalty_f32 = (1.0 - confidence) * self.config.noise_penalty_multiplier as f32;
        let noise_penalty_score = penalty_f32 as i32;

        let final_score = section_weight_score + semantic_boost_score - noise_penalty_score;
        found_string.score = final_score;

        if self.debug_mode {
            found_string.section_weight = Some(section_weight_score);
            found_string.semantic_boost = Some(semantic_boost_score);
            found_string.noise_penalty = Some(noise_penalty_score);
        }
    }

    /// Sorts strings by their precomputed score in descending order.
    ///
    /// Call `calculate_score` for each `FoundString` before invoking this method,
    /// otherwise ordering will reflect uninitialized or stale scores. This uses
    /// a stable sort, so the relative order of equal scores is preserved.
    pub fn rank_strings(&self, strings: &mut [FoundString]) {
        strings.sort_by(|a, b| b.score.cmp(&a.score));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Encoding, StringSource};

    fn make_section_info(section_type: SectionType) -> SectionInfo {
        SectionInfo::new("test".to_string(), 0, 0, section_type, 1.0)
    }

    fn make_found_string(tags: Vec<Tag>, confidence: f32) -> FoundString {
        FoundString::new(
            "test".to_string(),
            Encoding::Ascii,
            0,
            4,
            StringSource::SectionData,
        )
        .with_tags(tags)
        .with_confidence(confidence)
    }

    #[test]
    fn test_default_config_values() {
        let config = RankingConfig::default();

        assert_eq!(
            config.section_weights.get(&SectionType::StringData),
            Some(&100)
        );
        assert_eq!(
            config.section_weights.get(&SectionType::ReadOnlyData),
            Some(&70)
        );
        assert_eq!(
            config.section_weights.get(&SectionType::Resources),
            Some(&100)
        );
        assert_eq!(
            config.section_weights.get(&SectionType::WritableData),
            Some(&50)
        );
        assert_eq!(config.section_weights.get(&SectionType::Code), Some(&10));
        assert_eq!(config.section_weights.get(&SectionType::Debug), Some(&30));
        assert_eq!(config.section_weights.get(&SectionType::Other), Some(&20));

        assert_eq!(config.tag_boosts.get(&Tag::Url), Some(&50));
        assert_eq!(config.tag_boosts.get(&Tag::Domain), Some(&40));
        assert_eq!(config.tag_boosts.get(&Tag::IPv4), Some(&45));
        assert_eq!(config.tag_boosts.get(&Tag::IPv6), Some(&45));
        assert_eq!(config.tag_boosts.get(&Tag::FilePath), Some(&35));
        assert_eq!(config.tag_boosts.get(&Tag::RegistryPath), Some(&40));
        assert_eq!(config.tag_boosts.get(&Tag::Guid), Some(&30));
        assert_eq!(config.tag_boosts.get(&Tag::Email), Some(&35));
        assert_eq!(config.tag_boosts.get(&Tag::DemangledSymbol), Some(&25));
        assert_eq!(config.tag_boosts.get(&Tag::Import), Some(&60));
        assert_eq!(config.tag_boosts.get(&Tag::Export), Some(&60));
        assert_eq!(config.tag_boosts.get(&Tag::Version), Some(&40));
        assert_eq!(config.tag_boosts.get(&Tag::Manifest), Some(&40));
        assert_eq!(config.tag_boosts.get(&Tag::Resource), Some(&40));
        assert_eq!(config.tag_boosts.get(&Tag::DylibPath), Some(&35));
        assert_eq!(config.tag_boosts.get(&Tag::Rpath), Some(&35));
        assert_eq!(config.tag_boosts.get(&Tag::RpathVariable), Some(&35));
        assert_eq!(config.tag_boosts.get(&Tag::FrameworkPath), Some(&35));
        assert_eq!(config.tag_boosts.get(&Tag::Base64), Some(&10));
        assert_eq!(config.tag_boosts.get(&Tag::FormatString), Some(&15));
        assert_eq!(config.tag_boosts.get(&Tag::UserAgent), Some(&20));

        assert_eq!(config.noise_penalty_multiplier, 100);
    }

    #[test]
    fn test_score_calculation_high_value_url() {
        let engine = RankingEngine::new(true);
        let mut found_string = make_found_string(vec![Tag::Url], 0.9);
        let section_info = make_section_info(SectionType::StringData);

        engine.calculate_score(&mut found_string, Some(&section_info));

        assert_eq!(found_string.score, 140);
        assert_eq!(found_string.section_weight, Some(100));
        assert_eq!(found_string.semantic_boost, Some(50));
        assert_eq!(found_string.noise_penalty, Some(10));
    }

    #[test]
    fn test_score_calculation_file_path_code_section() {
        let engine = RankingEngine::new(true);
        let mut found_string = make_found_string(vec![Tag::FilePath], 0.6);
        let section_info = make_section_info(SectionType::Code);

        engine.calculate_score(&mut found_string, Some(&section_info));

        // Note: (1.0 - 0.6) as f32 is ~0.39999998, so penalty is 39, not 40
        assert_eq!(found_string.score, 6);
        assert_eq!(found_string.section_weight, Some(10));
        assert_eq!(found_string.semantic_boost, Some(35));
        assert_eq!(found_string.noise_penalty, Some(39));
    }

    #[test]
    fn test_score_calculation_low_confidence_noise() {
        let engine = RankingEngine::new(true);
        let mut found_string = make_found_string(Vec::new(), 0.2);
        let section_info = make_section_info(SectionType::Other);

        engine.calculate_score(&mut found_string, Some(&section_info));

        assert_eq!(found_string.score, -60);
        assert_eq!(found_string.section_weight, Some(20));
        assert_eq!(found_string.semantic_boost, Some(0));
        assert_eq!(found_string.noise_penalty, Some(80));
    }

    #[test]
    fn test_multiple_tags_accumulate() {
        let engine = RankingEngine::new(true);
        let mut found_string = make_found_string(vec![Tag::Url, Tag::Domain], 1.0);
        let section_info = make_section_info(SectionType::StringData);

        engine.calculate_score(&mut found_string, Some(&section_info));

        assert_eq!(found_string.semantic_boost, Some(90));
        assert_eq!(found_string.score, 190);
    }

    #[test]
    fn test_debug_mode_population() {
        let section_info = make_section_info(SectionType::StringData);

        let mut debug_string = make_found_string(vec![Tag::Url], 0.9);
        let debug_engine = RankingEngine::new(true);
        debug_engine.calculate_score(&mut debug_string, Some(&section_info));

        assert!(debug_string.section_weight.is_some());
        assert!(debug_string.semantic_boost.is_some());
        assert!(debug_string.noise_penalty.is_some());

        let mut release_string = make_found_string(vec![Tag::Url], 0.9);
        let release_engine = RankingEngine::new(false);
        release_engine.calculate_score(&mut release_string, Some(&section_info));

        assert!(release_string.section_weight.is_none());
        assert!(release_string.semantic_boost.is_none());
        assert!(release_string.noise_penalty.is_none());
    }

    #[test]
    fn test_ranking_sorting() {
        let engine = RankingEngine::new(false);
        let mut strings = vec![
            make_found_string(Vec::new(), 1.0).with_score(10),
            make_found_string(Vec::new(), 1.0).with_score(50),
            make_found_string(Vec::new(), 1.0).with_score(30),
            make_found_string(Vec::new(), 1.0).with_score(5),
            make_found_string(Vec::new(), 1.0).with_score(40),
        ];

        engine.rank_strings(&mut strings);

        let scores: Vec<i32> = strings.iter().map(|item| item.score).collect();
        assert_eq!(scores, vec![50, 40, 30, 10, 5]);
    }

    #[test]
    fn test_edge_cases() {
        let engine = RankingEngine::new(true);

        let mut no_section_info = make_found_string(vec![Tag::Url], 1.0);
        engine.calculate_score(&mut no_section_info, None);
        assert_eq!(no_section_info.section_weight, Some(20));

        let mut rpath_variable_string = make_found_string(vec![Tag::RpathVariable], 1.0);
        engine.calculate_score(&mut rpath_variable_string, None);
        assert_eq!(rpath_variable_string.semantic_boost, Some(35));

        let mut zero_confidence = make_found_string(Vec::new(), 0.0);
        engine.calculate_score(&mut zero_confidence, None);
        assert_eq!(zero_confidence.noise_penalty, Some(100));

        let mut full_confidence = make_found_string(Vec::new(), 1.0);
        engine.calculate_score(&mut full_confidence, None);
        assert_eq!(full_confidence.noise_penalty, Some(0));
    }
}
