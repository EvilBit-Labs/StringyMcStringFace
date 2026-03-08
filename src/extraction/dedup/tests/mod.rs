//! Tests for string deduplication
//!
//! Split into submodules:
//! - `basic`: Core deduplication, encoding separation, metadata, tag merging
//! - `scoring`: Score calculation, bonuses, thresholds, length preservation

mod basic;
mod scoring;

use super::*;
use crate::types::{Encoding, StringSource, Tag};

// Test helper needs many parameters to construct FoundString with full metadata
#[allow(clippy::too_many_arguments)]
fn create_test_string(
    text: &str,
    encoding: Encoding,
    offset: u64,
    section: Option<String>,
    source: StringSource,
    tags: Vec<Tag>,
    score: i32,
    confidence: f32,
) -> FoundString {
    // Calculate byte length based on encoding
    let length = match encoding {
        Encoding::Utf16Le | Encoding::Utf16Be => {
            // UTF-16: 2 bytes per character
            text.chars().count() * 2
        }
        _ => {
            // ASCII/UTF-8: 1 byte per character (approximation for tests)
            text.len()
        }
    } as u32;

    FoundString {
        text: text.to_string(),
        original_text: None,
        encoding,
        offset,
        rva: Some(offset + 0x1000),
        section,
        length,
        tags,
        score,
        section_weight: None,
        semantic_boost: None,
        noise_penalty: None,
        display_score: None,
        source,
        confidence,
    }
}
