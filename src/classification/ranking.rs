use std::collections::HashMap;

use crate::types::{FoundString, SectionInfo, SectionType, Tag};

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RankingConfig {
    pub section_weights: HashMap<SectionType, i32>,
    pub tag_boosts: HashMap<Tag, i32>,
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

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RankingEngine {
    config: RankingConfig,
    debug_mode: bool,
}

impl RankingEngine {
    #[must_use]
    pub fn new(debug_mode: bool) -> Self {
        Self::with_config(RankingConfig::default(), debug_mode)
    }

    #[must_use]
    pub fn with_config(config: RankingConfig, debug_mode: bool) -> Self {
        Self { config, debug_mode }
    }

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
    /// otherwise ordering will reflect uninitialized or stale scores. This is an
    /// unstable sort, so the relative order of equal scores is not preserved.
    pub fn rank_strings(&self, strings: &mut [FoundString]) {
        strings.sort_by(|a, b| b.score.cmp(&a.score));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Encoding, StringSource};

    fn make_section_info(section_type: SectionType) -> SectionInfo {
        SectionInfo {
            name: "test".to_string(),
            offset: 0,
            size: 0,
            rva: None,
            section_type,
            is_executable: false,
            is_writable: false,
            weight: 1.0,
        }
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
