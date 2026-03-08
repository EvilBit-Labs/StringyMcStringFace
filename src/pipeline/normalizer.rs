//! Score normalization for display purposes.
//!
//! Maps internal ranking scores to a user-facing 0-100 display range using
//! a fixed band-interpolation table.

use crate::types::FoundString;

/// Normalizes internal scores to a 0-100 display range.
#[derive(Debug, Default)]
pub struct ScoreNormalizer;

impl ScoreNormalizer {
    /// Create a new `ScoreNormalizer`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Populate `display_score` on every string by normalizing its internal score.
    pub fn normalize(&self, strings: &mut [FoundString]) {
        for s in strings.iter_mut() {
            s.display_score = Some(normalize_score(s.score));
        }
    }
}

/// Map an internal score to a 0-100 display score via band interpolation.
///
/// | Internal score | Display range | Rule               |
/// |----------------|---------------|--------------------|
/// | <= 0           | 0             | Clamp              |
/// | 1..=79         | 1..=49        | Linear interpolation |
/// | 80..=119       | 50..=69       | Linear interpolation |
/// | 120..=159      | 70..=89       | Linear interpolation |
/// | 160..=220      | 90..=100      | Linear interpolation |
/// | > 220          | 100           | Clamp              |
fn normalize_score(raw: i32) -> i32 {
    if raw <= 0 {
        return 0;
    }
    if raw > 220 {
        return 100;
    }

    // (raw_lo, raw_hi, display_lo, display_hi)
    let bands: [(i32, i32, i32, i32); 4] = [
        (1, 79, 1, 49),
        (80, 119, 50, 69),
        (120, 159, 70, 89),
        (160, 220, 90, 100),
    ];

    for (raw_lo, raw_hi, band_lo, band_hi) in bands {
        if raw <= raw_hi {
            let range = raw_hi - raw_lo;
            if range == 0 {
                return band_lo;
            }
            return band_lo + (raw - raw_lo) * (band_hi - band_lo) / range;
        }
    }

    // Should be unreachable due to the > 220 clamp above
    100
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clamp_negative() {
        assert_eq!(normalize_score(-10), 0);
    }

    #[test]
    fn test_clamp_zero() {
        assert_eq!(normalize_score(0), 0);
    }

    #[test]
    fn test_clamp_high() {
        assert_eq!(normalize_score(250), 100);
        assert_eq!(normalize_score(221), 100);
    }

    #[test]
    fn test_band_boundaries() {
        assert_eq!(normalize_score(1), 1);
        assert_eq!(normalize_score(79), 49);
        assert_eq!(normalize_score(80), 50);
        assert_eq!(normalize_score(119), 69);
        assert_eq!(normalize_score(120), 70);
        assert_eq!(normalize_score(159), 89);
        assert_eq!(normalize_score(160), 90);
        assert_eq!(normalize_score(220), 100);
    }

    #[test]
    fn test_mid_band_interpolation() {
        // Mid-point of band 1: raw=40 -> display = 1 + (40-1)*(49-1)/(79-1) = 1 + 39*48/78 = 1 + 24 = 25
        assert_eq!(normalize_score(40), 25);
    }

    #[test]
    fn test_normalizer_populates_display_score() {
        use crate::types::{Encoding, StringSource};

        let mut strings = vec![
            FoundString::new(
                "low".into(),
                Encoding::Ascii,
                0,
                3,
                StringSource::SectionData,
            )
            .with_score(-5),
            FoundString::new(
                "mid".into(),
                Encoding::Ascii,
                10,
                3,
                StringSource::SectionData,
            )
            .with_score(100),
            FoundString::new(
                "high".into(),
                Encoding::Ascii,
                20,
                4,
                StringSource::SectionData,
            )
            .with_score(300),
        ];

        let normalizer = ScoreNormalizer::new();
        normalizer.normalize(&mut strings);

        assert_eq!(strings[0].display_score, Some(0));
        // raw 100 is in band 80..=119 -> 50 + (100-80)*(69-50)/(119-80) = 50 + 20*19/39 = 50 + 9 = 59
        assert_eq!(strings[1].display_score, Some(59));
        assert_eq!(strings[2].display_score, Some(100));
    }
}
