//! Score calculation for deduplicated strings
//!
//! Combines individual occurrence scores with bonuses for multiple
//! occurrences, cross-section presence, multi-source presence, and confidence.

use super::StringOccurrence;
use std::collections::HashSet;

/// Calculate combined score for a group of occurrences
///
/// Combines individual scores with bonuses for multiple occurrences,
/// cross-section presence, multi-source presence, and confidence.
///
/// # Arguments
///
/// * `occurrences` - Slice of string occurrences
///
/// # Returns
///
/// Combined score as i32
pub(super) fn calculate_combined_score(occurrences: &[StringOccurrence]) -> i32 {
    if occurrences.is_empty() {
        return 0;
    }

    // Base score: maximum original_score across all occurrences
    let base_score = occurrences
        .iter()
        .map(|occ| occ.original_score)
        .max()
        .unwrap_or(0);

    // Occurrence bonus: 5 points per additional occurrence
    let occurrence_bonus = if occurrences.len() > 1 {
        5 * (occurrences.len() - 1) as i32
    } else {
        0
    };

    // Cross-section bonus: 10 points if string appears in different sections
    let unique_sections: HashSet<_> = occurrences.iter().map(|occ| &occ.section).collect();
    let cross_section_bonus = if unique_sections.len() > 1 { 10 } else { 0 };

    // Multi-source bonus: 15 points if string appears from different sources
    let unique_sources: HashSet<_> = occurrences.iter().map(|occ| occ.source).collect();
    let multi_source_bonus = if unique_sources.len() > 1 { 15 } else { 0 };

    // Confidence boost: max_confidence * 10
    let max_confidence = occurrences
        .iter()
        .map(|occ| occ.confidence)
        .fold(0.0f32, f32::max);
    let confidence_boost = (max_confidence * 10.0) as i32;

    base_score + occurrence_bonus + cross_section_bonus + multi_source_bonus + confidence_boost
}
