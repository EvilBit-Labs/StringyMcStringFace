//! Post-extraction string filtering.
//!
//! Applies deterministic filters (length, encoding, tags, sorting, top-N)
//! to the extracted string collection in a fixed order.

use std::collections::HashSet;

use crate::pipeline::config::{EncodingFilter, FilterConfig};
use crate::types::{Encoding, FoundString};

/// Applies post-extraction filters to a collection of strings.
#[derive(Debug, Default)]
pub struct FilterEngine;

impl FilterEngine {
    /// Create a new `FilterEngine`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Apply all filters in deterministic order and return the filtered collection.
    ///
    /// Filter order:
    /// 1. min-len: retain strings by UTF-8 byte length (`text.len() >= min_length`)
    /// 2. encoding: restrict by encoding variant
    /// 3. include-tags: retain only strings with at least one included tag
    /// 4. exclude-tags: drop strings with any excluded tag
    /// 5. stable sort: score desc, offset asc, text asc
    /// 6. top-N: truncate to N entries
    #[must_use]
    pub fn apply(&self, strings: Vec<FoundString>, config: &FilterConfig) -> Vec<FoundString> {
        // Pre-build HashSets for O(1) tag containment checks
        let include_set: HashSet<_> = config.include_tags.iter().collect();
        let exclude_set: HashSet<_> = config.exclude_tags.iter().collect();

        let mut result: Vec<FoundString> = strings
            .into_iter()
            // 1. min-len (only applied when set)
            .filter(|s| config.min_length.is_none_or(|min| s.text.len() >= min))
            // 2. encoding
            .filter(|s| match &config.encoding {
                None => true,
                Some(EncodingFilter::Exact(enc)) => s.encoding == *enc,
                Some(EncodingFilter::Utf16Any) => {
                    s.encoding == Encoding::Utf16Le || s.encoding == Encoding::Utf16Be
                }
                Some(EncodingFilter::AsciiContent) => {
                    // Cheap O(1) encoding guards short-circuit before the O(n)
                    // is_ascii() scan, so UTF-16 rows skip the content check.
                    s.encoding != Encoding::Utf16Le
                        && s.encoding != Encoding::Utf16Be
                        && s.text.is_ascii()
                }
            })
            // 3. include-tags
            .filter(|s| include_set.is_empty() || s.tags.iter().any(|t| include_set.contains(t)))
            // 4. exclude-tags
            .filter(|s| exclude_set.is_empty() || !s.tags.iter().any(|t| exclude_set.contains(t)))
            .collect();

        // 5. stable sort: score desc -> offset asc -> text asc
        result.sort_by(|a, b| {
            b.score
                .cmp(&a.score)
                .then(a.offset.cmp(&b.offset))
                .then(a.text.cmp(&b.text))
        });

        // 6. top-N
        if let Some(n) = config.top_n {
            result.truncate(n);
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Encoding, StringSource, Tag};

    fn make_string(text: &str, score: i32, offset: u64) -> FoundString {
        FoundString::new(
            text.to_string(),
            Encoding::Ascii,
            offset,
            text.len() as u32,
            StringSource::SectionData,
        )
        .with_score(score)
    }

    fn make_tagged_string(text: &str, score: i32, tags: Vec<Tag>) -> FoundString {
        FoundString::new(
            text.to_string(),
            Encoding::Ascii,
            0,
            text.len() as u32,
            StringSource::SectionData,
        )
        .with_score(score)
        .with_tags(tags)
    }

    #[test]
    fn test_min_length_filter() {
        let strings = vec![make_string("ab", 10, 0), make_string("abcdef", 5, 10)];
        let config = FilterConfig::new().with_min_length(4);
        let result = FilterEngine::new().apply(strings, &config);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].text, "abcdef");
    }

    #[test]
    fn test_encoding_exact_filter() {
        let mut s_utf16 = make_string("wide", 10, 0);
        s_utf16.encoding = Encoding::Utf16Le;
        let s_ascii = make_string("narrow", 10, 10);

        let config = FilterConfig::new()
            .with_min_length(1)
            .with_encoding(EncodingFilter::Exact(Encoding::Utf16Le));
        let result = FilterEngine::new().apply(vec![s_utf16, s_ascii], &config);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].text, "wide");
    }

    #[test]
    fn test_ascii_content_filter_matches_narrow_ascii_text() {
        // Narrow ASCII content (now labeled Utf8 per KTD7) passes.
        let mut narrow = make_string("CreateFileW", 10, 0);
        narrow.encoding = Encoding::Utf8;
        // UTF-8 content with non-ASCII characters is excluded.
        let mut wide_utf8 = make_string("caf\u{e9}", 10, 10);
        wide_utf8.encoding = Encoding::Utf8;
        // A UTF-16 row that happens to decode to ASCII is still excluded,
        // preserving the flag's pre-existing "narrow strings only" meaning.
        let mut utf16_ascii = make_string("hello", 10, 20);
        utf16_ascii.encoding = Encoding::Utf16Le;

        let config = FilterConfig::new()
            .with_min_length(1)
            .with_encoding(EncodingFilter::AsciiContent);
        let result = FilterEngine::new().apply(vec![narrow, wide_utf8, utf16_ascii], &config);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].text, "CreateFileW");
    }

    #[test]
    fn test_encoding_utf16any_filter() {
        let mut s_le = make_string("le", 10, 0);
        s_le.encoding = Encoding::Utf16Le;
        let mut s_be = make_string("be", 10, 10);
        s_be.encoding = Encoding::Utf16Be;
        let s_ascii = make_string("ascii", 10, 20);

        let config = FilterConfig::new()
            .with_min_length(1)
            .with_encoding(EncodingFilter::Utf16Any);
        let result = FilterEngine::new().apply(vec![s_le, s_be, s_ascii], &config);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_include_tags_filter() {
        let s1 = make_tagged_string("http://example.com", 10, vec![Tag::Url]);
        let s2 = make_tagged_string("plain text here", 10, vec![]);

        let config = FilterConfig::new()
            .with_min_length(1)
            .with_include_tags(vec![Tag::Url]);
        let result = FilterEngine::new().apply(vec![s1, s2], &config);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].text, "http://example.com");
    }

    #[test]
    fn test_exclude_tags_filter() {
        let s1 = make_tagged_string("debug info", 10, vec![Tag::FormatString]);
        let s2 = make_tagged_string("keep me!!", 10, vec![Tag::Url]);

        let config = FilterConfig::new()
            .with_min_length(1)
            .with_exclude_tags(vec![Tag::FormatString]);
        let result = FilterEngine::new().apply(vec![s1, s2], &config);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].text, "keep me!!");
    }

    #[test]
    fn test_sort_order() {
        let s1 = make_string("beta", 10, 20);
        let s2 = make_string("alpha", 10, 10);
        let s3 = make_string("gamma", 20, 5);

        let config = FilterConfig::new().with_min_length(1);
        let result = FilterEngine::new().apply(vec![s1, s2, s3], &config);

        // gamma (score 20) first, then alpha (score 10, offset 10), then beta (score 10, offset 20)
        assert_eq!(result[0].text, "gamma");
        assert_eq!(result[1].text, "alpha");
        assert_eq!(result[2].text, "beta");
    }

    #[test]
    fn test_top_n() {
        let strings = vec![
            make_string("third", 5, 0),
            make_string("first!", 20, 10),
            make_string("second", 10, 20),
        ];

        let config = FilterConfig::new().with_min_length(1).with_top_n(2);
        let result = FilterEngine::new().apply(strings, &config);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].text, "first!");
        assert_eq!(result[1].text, "second");
    }

    #[test]
    fn test_empty_input() {
        let config = FilterConfig::new();
        let result = FilterEngine::new().apply(vec![], &config);
        assert!(result.is_empty());
    }

    #[test]
    fn test_permissive_defaults_pass_everything() {
        let strings = vec![
            make_string("hello world", 10, 0),
            make_string("test", 5, 20),
            make_string("ab", 3, 30), // short string passes with no min_length
        ];
        let config = FilterConfig::new();
        assert!(
            config.min_length.is_none(),
            "default min_length must be None"
        );
        let result = FilterEngine::new().apply(strings, &config);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_none_min_length_passes_all_lengths() {
        let strings = vec![
            make_string("a", 10, 0),
            make_string("ab", 10, 10),
            make_string("abcdef", 10, 20),
        ];
        let config = FilterConfig::new(); // min_length is None
        let result = FilterEngine::new().apply(strings, &config);
        assert_eq!(result.len(), 3, "None min_length must pass all strings");
    }

    #[test]
    fn test_some_min_length_filters_short_strings() {
        let strings = vec![
            make_string("a", 10, 0),
            make_string("ab", 10, 10),
            make_string("abcdef", 10, 20),
        ];
        let config = FilterConfig::new().with_min_length(3);
        let result = FilterEngine::new().apply(strings, &config);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].text, "abcdef");
    }
}
