//! `FoundString` and `StringContext` constructors and builder methods

use super::{BinaryFormat, Encoding, FoundString, SectionType, StringContext, StringSource, Tag};

impl FoundString {
    /// Creates a new FoundString with required fields and sensible defaults
    ///
    /// # Arguments
    ///
    /// * `text` - The extracted string text
    /// * `encoding` - The encoding used for this string
    /// * `offset` - File offset where the string was found
    /// * `length` - Length of the string in bytes
    /// * `source` - Source of the string (section data, import, etc.)
    ///
    /// # Returns
    ///
    /// A new FoundString with optional fields set to None/empty and confidence
    /// set to 1.0
    #[must_use]
    pub fn new(
        text: String,
        encoding: Encoding,
        offset: u64,
        length: u32,
        source: StringSource,
    ) -> Self {
        Self {
            text,
            original_text: None,
            encoding,
            offset,
            rva: None,
            section: None,
            length,
            tags: Vec::new(),
            score: 0,
            section_weight: None,
            semantic_boost: None,
            noise_penalty: None,
            display_score: None,
            source,
            confidence: 1.0,
        }
    }

    /// Sets the RVA (Relative Virtual Address)
    #[must_use]
    pub fn with_rva(mut self, rva: u64) -> Self {
        self.rva = Some(rva);
        self
    }

    /// Sets the section name
    #[must_use]
    pub fn with_section(mut self, section: String) -> Self {
        self.section = Some(section);
        self
    }

    /// Sets the tags
    #[must_use]
    pub fn with_tags(mut self, tags: Vec<Tag>) -> Self {
        self.tags = tags;
        self
    }

    /// Sets the score
    #[must_use]
    pub fn with_score(mut self, score: i32) -> Self {
        self.score = score;
        self
    }

    /// Sets the confidence
    #[must_use]
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence;
        self
    }

    /// Sets the original text (for demangled symbols)
    #[must_use]
    pub fn with_original_text(mut self, original_text: String) -> Self {
        self.original_text = Some(original_text);
        self
    }

    /// Sets the section weight (debug mode)
    #[must_use]
    pub fn with_section_weight(mut self, weight: i32) -> Self {
        self.section_weight = Some(weight);
        self
    }

    /// Sets the semantic boost (debug mode)
    #[must_use]
    pub fn with_semantic_boost(mut self, boost: i32) -> Self {
        self.semantic_boost = Some(boost);
        self
    }

    /// Sets the noise penalty (debug mode)
    #[must_use]
    pub fn with_noise_penalty(mut self, penalty: i32) -> Self {
        self.noise_penalty = Some(penalty);
        self
    }

    /// Sets the display score (debug mode)
    #[must_use]
    pub fn with_display_score(mut self, score: i32) -> Self {
        self.display_score = Some(score);
        self
    }

    /// Returns true if confidence is high (>= 0.7)
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.7
    }

    /// Returns true if confidence is low (< 0.5)
    pub fn is_low_confidence(&self) -> bool {
        self.confidence < 0.5
    }
}

impl StringContext {
    /// Creates a new `StringContext` with required fields
    ///
    /// Use the builder methods (`with_section_name`) to set optional fields.
    #[must_use]
    pub fn new(
        section_type: SectionType,
        binary_format: BinaryFormat,
        encoding: Encoding,
        source: StringSource,
    ) -> Self {
        Self {
            section_type,
            section_name: None,
            binary_format,
            encoding,
            source,
        }
    }

    /// Sets the section name
    #[must_use]
    pub fn with_section_name(mut self, name: String) -> Self {
        self.section_name = Some(name);
        self
    }
}
