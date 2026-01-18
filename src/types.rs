use serde::{Deserialize, Serialize};

/// Represents the encoding of an extracted string
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Encoding {
    Ascii,
    Utf8,
    Utf16Le,
    Utf16Be,
}

/// Semantic tags for classifying strings
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Tag {
    Url,
    Domain,
    #[serde(rename = "ipv4")]
    IPv4,
    #[serde(rename = "ipv6")]
    IPv6,
    #[serde(rename = "filepath")]
    FilePath,
    #[serde(rename = "regpath")]
    RegistryPath,
    #[serde(rename = "guid")]
    Guid,
    Email,
    #[serde(rename = "b64")]
    Base64,
    #[serde(rename = "fmt")]
    FormatString,
    #[serde(rename = "user-agent-ish")]
    UserAgent,
    #[serde(rename = "demangled")]
    DemangledSymbol,
    Import,
    Export,
    Version,
    Manifest,
    Resource,
    #[serde(rename = "dylib-path")]
    DylibPath,
    #[serde(rename = "rpath")]
    Rpath,
    #[serde(rename = "rpath-var")]
    RpathVariable,
    #[serde(rename = "framework-path")]
    FrameworkPath,
}

/// Type of section based on its purpose and likelihood of containing strings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SectionType {
    /// Sections likely to contain string literals (.rodata, .rdata, __cstring)
    StringData,
    /// Read-only data sections (.data.rel.ro, __DATA_CONST)
    ReadOnlyData,
    /// Writable data sections (.data)
    WritableData,
    /// Executable code sections (.text, __TEXT)
    Code,
    /// Debug information sections (.debug_*, __DWARF)
    Debug,
    /// PE resource sections
    Resources,
    /// Other/unknown section types
    Other,
}

/// Source of a string within the binary
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StringSource {
    /// String found in section data
    SectionData,
    /// String from import table
    ImportName,
    /// String from export table
    ExportName,
    /// String from PE resources
    ResourceString,
    /// String from Mach-O load command
    LoadCommand,
    /// String from debug information
    DebugInfo,
}

/// Information about a container (binary file)
///
/// This struct is marked `#[non_exhaustive]` to allow adding new fields without breaking
/// downstream code. Use `ContainerInfo::new()` to construct instances.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ContainerInfo {
    /// The binary format detected
    pub format: BinaryFormat,
    /// List of sections in the binary
    pub sections: Vec<SectionInfo>,
    /// Import information
    pub imports: Vec<ImportInfo>,
    /// Export information
    pub exports: Vec<ExportInfo>,
    /// Resource metadata (PE format only)
    pub resources: Option<Vec<ResourceMetadata>>,
}

impl ContainerInfo {
    /// Create a new `ContainerInfo` instance
    ///
    /// This constructor should be used instead of struct literals to ensure
    /// all fields are properly initialized, especially when new fields are added.
    pub fn new(
        format: BinaryFormat,
        sections: Vec<SectionInfo>,
        imports: Vec<ImportInfo>,
        exports: Vec<ExportInfo>,
        resources: Option<Vec<ResourceMetadata>>,
    ) -> Self {
        Self {
            format,
            sections,
            imports,
            exports,
            resources,
        }
    }
}

/// Binary format types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFormat {
    Elf,
    Pe,
    MachO,
    Unknown,
}

/// Information about a section within the binary
#[derive(Debug, Clone)]
pub struct SectionInfo {
    /// Section name
    pub name: String,
    /// File offset of the section
    pub offset: u64,
    /// Size of the section in bytes
    pub size: u64,
    /// Relative Virtual Address (if available)
    pub rva: Option<u64>,
    /// Classification of the section type
    pub section_type: SectionType,
    /// Whether the section is executable
    pub is_executable: bool,
    /// Whether the section is writable
    pub is_writable: bool,
    /// Weight indicating likelihood of containing meaningful strings (higher = more likely)
    pub weight: f32,
}

/// Information about an import
#[derive(Debug, Clone)]
pub struct ImportInfo {
    /// Name of the imported symbol
    pub name: String,
    /// Library/module name (if available)
    pub library: Option<String>,
    /// Address or ordinal
    pub address: Option<u64>,
    /// Import ordinal (if available, for ordinal imports)
    pub ordinal: Option<u16>,
}

/// Information about an export
#[derive(Debug, Clone)]
pub struct ExportInfo {
    /// Name of the exported symbol
    pub name: String,
    /// Export address
    pub address: u64,
    /// Export ordinal (if available)
    pub ordinal: Option<u16>,
}

/// Type of PE resource
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceType {
    /// RT_VERSION resources (VERSIONINFO)
    VersionInfo,
    /// RT_STRING resources (STRINGTABLE)
    StringTable,
    /// RT_MANIFEST resources
    Manifest,
    /// Other resource types (for future expansion)
    Other(String),
}

/// Metadata about a PE resource
#[derive(Debug, Clone)]
pub struct ResourceMetadata {
    /// Type of resource
    pub resource_type: ResourceType,
    /// Language/locale identifier
    pub language: u32,
    /// Size of resource data in bytes
    pub data_size: usize,
    /// File offset if available
    pub offset: Option<u64>,
}

/// String table resource containing multiple string entries
#[derive(Debug, Clone)]
pub struct ResourceStringTable {
    /// Language identifier
    pub language: u32,
    /// String entries in this table
    pub entries: Vec<ResourceStringEntry>,
}

/// Individual string entry in a resource string table
#[derive(Debug, Clone)]
pub struct ResourceStringEntry {
    /// String resource ID
    pub id: u32,
    /// The actual string content
    pub value: String,
}

/// A string found in the binary with metadata
///
/// The `original_text` field preserves the pre-demangled text when demangling
/// is applied. Debug-only fields provide transparency into how the final score
/// was produced and are only populated when debug mode is enabled.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct FoundString {
    /// The extracted string text
    pub text: String,
    /// Original text before demangling (if applicable)
    ///
    /// When a string is identified as a mangled symbol (e.g., C++ or Rust mangled names),
    /// this field preserves the original mangled form before demangling is applied.
    /// The `text` field will contain the demangled version. This is `None` for strings
    /// that are not mangled symbols or when demangling is not performed.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub original_text: Option<String>,
    /// The encoding used for this string
    pub encoding: Encoding,
    /// File offset where the string was found
    pub offset: u64,
    /// Relative Virtual Address (if available)
    pub rva: Option<u64>,
    /// Section name where the string was found
    pub section: Option<String>,
    /// Length of the string in bytes
    pub length: u32,
    /// Semantic tags applied to this string
    pub tags: Vec<Tag>,
    /// Relevance score for ranking
    pub score: i32,
    /// Section weight contribution to the final score (debug only)
    ///
    /// When debug mode is enabled, this field contains the weight assigned based on
    /// the section where the string was found. Higher weights indicate sections more
    /// likely to contain meaningful strings (e.g., .rodata vs .text). This is `None`
    /// unless explicitly populated by the ranking system in debug mode.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub section_weight: Option<i32>,
    /// Semantic classification boost to the final score (debug only)
    ///
    /// When debug mode is enabled, this field contains the score boost applied based on
    /// semantic tags (URLs, file paths, GUIDs, etc.). Strings with valuable semantic
    /// meaning receive positive boosts. This is `None` unless explicitly populated by
    /// the ranking system in debug mode.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub semantic_boost: Option<i32>,
    /// Noise penalty applied to the final score (debug only)
    ///
    /// When debug mode is enabled, this field contains the penalty applied for noise
    /// characteristics (low confidence, repetitive patterns, etc.). Higher penalties
    /// indicate strings more likely to be noise. This is `None` unless explicitly
    /// populated by the ranking system in debug mode.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub noise_penalty: Option<i32>,
    /// Source of the string (section data, import, etc.)
    pub source: StringSource,
    /// Confidence score from noise filtering (0.0-1.0)
    ///
    /// This represents how confident we are that the string is legitimate vs noise.
    /// A score of 1.0 indicates maximum confidence (e.g., strings from known-good sources
    /// like imports, exports, resources). Lower scores indicate potential noise that
    /// may need filtering. This is separate from the `score` field, which is used for
    /// final ranking (combining section weight, semantic boosts, and noise penalties).
    pub confidence: f32,
}

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

    /// Returns true if confidence is high (>= 0.7)
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.7
    }

    /// Returns true if confidence is low (< 0.5)
    pub fn is_low_confidence(&self) -> bool {
        self.confidence < 0.5
    }
}

/// Error types for the stringy library
#[derive(Debug, thiserror::Error)]
pub enum StringyError {
    #[error("Unsupported file format")]
    UnsupportedFormat,

    #[error("File I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Binary parsing error: {0}")]
    ParseError(String),

    #[error("Invalid encoding in string at offset {offset}")]
    EncodingError { offset: u64 },

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Memory mapping error: {0}")]
    MemoryMapError(String),
}

/// Result type alias for the stringy library
pub type Result<T> = std::result::Result<T, StringyError>;

impl From<goblin::error::Error> for StringyError {
    fn from(err: goblin::error::Error) -> Self {
        StringyError::ParseError(err.to_string())
    }
}

impl From<pelite::Error> for StringyError {
    fn from(err: pelite::Error) -> Self {
        StringyError::ParseError(err.to_string())
    }
}

impl From<pelite::resources::FindError> for StringyError {
    fn from(err: pelite::resources::FindError) -> Self {
        StringyError::ParseError(format!("Resource lookup error: {}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Creates a test FoundString with all optional fields set to None
    fn create_test_found_string() -> FoundString {
        FoundString {
            text: "test_string".to_string(),
            original_text: None,
            encoding: Encoding::Ascii,
            offset: 0x1000,
            rva: Some(0x2000),
            section: Some(".rodata".to_string()),
            length: 11,
            tags: vec![Tag::Url],
            score: 100,
            section_weight: None,
            semantic_boost: None,
            noise_penalty: None,
            source: StringSource::SectionData,
            confidence: 0.85,
        }
    }

    #[test]
    fn test_found_string_serde_optional_fields_none() {
        // Test that optional fields are skipped when None
        let found_string = create_test_found_string();
        let json = serde_json::to_string(&found_string).expect("Serialization failed");

        // Verify optional fields are not present in JSON
        assert!(!json.contains("original_text"));
        assert!(!json.contains("section_weight"));
        assert!(!json.contains("semantic_boost"));
        assert!(!json.contains("noise_penalty"));

        // Verify required fields are present
        assert!(json.contains("text"));
        assert!(json.contains("encoding"));
        assert!(json.contains("offset"));
    }

    #[test]
    fn test_found_string_serde_optional_fields_some() {
        // Test that optional fields are included when Some
        let mut found_string = create_test_found_string();
        found_string.original_text = Some("_ZN4test6mangled".to_string());
        found_string.section_weight = Some(50);
        found_string.semantic_boost = Some(25);
        found_string.noise_penalty = Some(-10);

        let json = serde_json::to_string(&found_string).expect("Serialization failed");

        // Verify optional fields are present in JSON
        assert!(json.contains("original_text"));
        assert!(json.contains("_ZN4test6mangled"));
        assert!(json.contains("section_weight"));
        assert!(json.contains("semantic_boost"));
        assert!(json.contains("noise_penalty"));
    }

    #[test]
    fn test_found_string_serde_roundtrip() {
        // Test serialization/deserialization roundtrip with all fields
        let mut found_string = create_test_found_string();
        found_string.original_text = Some("mangled_name".to_string());
        found_string.section_weight = Some(75);
        found_string.semantic_boost = Some(30);
        found_string.noise_penalty = Some(-5);

        let json = serde_json::to_string(&found_string).expect("Serialization failed");
        let deserialized: FoundString =
            serde_json::from_str(&json).expect("Deserialization failed");

        assert_eq!(found_string.text, deserialized.text);
        assert_eq!(found_string.original_text, deserialized.original_text);
        assert_eq!(found_string.section_weight, deserialized.section_weight);
        assert_eq!(found_string.semantic_boost, deserialized.semantic_boost);
        assert_eq!(found_string.noise_penalty, deserialized.noise_penalty);
    }

    #[test]
    fn test_found_string_deserialize_missing_optional_fields() {
        // Test that missing optional fields default to None during deserialization
        let json = r#"{
            "text": "test",
            "encoding": "Ascii",
            "offset": 0,
            "rva": null,
            "section": null,
            "length": 4,
            "tags": [],
            "score": 0,
            "source": "SectionData",
            "confidence": 1.0
        }"#;

        let deserialized: FoundString = serde_json::from_str(json).expect("Deserialization failed");

        assert_eq!(deserialized.text, "test");
        assert_eq!(deserialized.original_text, None);
        assert_eq!(deserialized.section_weight, None);
        assert_eq!(deserialized.semantic_boost, None);
        assert_eq!(deserialized.noise_penalty, None);
    }
}
