//! Core types for the stringy library

mod constructors;
mod error;
mod found_string;

pub use error::{Result, StringyError};

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

/// Represents the encoding of an extracted string
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Encoding {
    Ascii,
    Utf8,
    Utf16Le,
    Utf16Be,
}

/// Semantic tags for classifying strings
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ValueEnum)]
pub enum Tag {
    #[value(name = "url")]
    Url,
    #[value(name = "domain")]
    Domain,
    #[serde(rename = "ipv4")]
    #[value(name = "ipv4")]
    IPv4,
    #[serde(rename = "ipv6")]
    #[value(name = "ipv6")]
    IPv6,
    #[serde(rename = "filepath")]
    #[value(name = "filepath")]
    FilePath,
    #[serde(rename = "regpath")]
    #[value(name = "regpath")]
    RegistryPath,
    #[serde(rename = "guid")]
    #[value(name = "guid")]
    Guid,
    #[value(name = "email")]
    Email,
    #[serde(rename = "b64")]
    #[value(name = "b64")]
    Base64,
    #[serde(rename = "fmt")]
    #[value(name = "fmt")]
    FormatString,
    #[serde(rename = "user-agent-ish")]
    #[value(name = "user-agent-ish")]
    UserAgent,
    #[serde(rename = "demangled")]
    #[value(name = "demangled")]
    DemangledSymbol,
    #[value(name = "import")]
    Import,
    #[value(name = "export")]
    Export,
    #[value(name = "version")]
    Version,
    #[value(name = "manifest")]
    Manifest,
    #[value(name = "resource")]
    Resource,
    #[serde(rename = "dylib-path")]
    #[value(name = "dylib-path")]
    DylibPath,
    #[serde(rename = "rpath")]
    #[value(name = "rpath")]
    Rpath,
    #[serde(rename = "rpath-var")]
    #[value(name = "rpath-var")]
    RpathVariable,
    #[serde(rename = "framework-path")]
    #[value(name = "framework-path")]
    FrameworkPath,
    #[serde(rename = "crypto")]
    #[value(name = "crypto")]
    Crypto,
    #[serde(rename = "network")]
    #[value(name = "network")]
    Network,
    #[serde(rename = "fileio")]
    #[value(name = "fileio")]
    FileIO,
    #[serde(rename = "entry-point")]
    #[value(name = "entry-point")]
    EntryPoint,
}

impl std::str::FromStr for Tag {
    type Err = String;

    /// Parses a canonical CLI tag name into a `Tag`, delegating to the
    /// `ValueEnum` definition so the accepted names have a single source of
    /// truth (the `#[value(name = ...)]` attributes above).
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        <Self as ValueEnum>::from_str(s, false).map_err(|_| format!("unknown tag: {s}"))
    }
}

impl std::fmt::Display for Tag {
    /// Renders the canonical CLI tag name -- the form users type and that
    /// `--only-tags`/`--no-tags` accept -- sourced from the `ValueEnum`
    /// definition rather than the `Debug` variant name (`import`, not `Import`).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.to_possible_value() {
            Some(value) => f.write_str(value.get_name()),
            None => f.write_str("<unknown>"),
        }
    }
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
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StringSource {
    /// String found in section data
    SectionData,
    /// Section name emitted as a standalone string
    SectionName,
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

/// Binary format types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFormat {
    Elf,
    Pe,
    MachO,
    Unknown,
}

/// Information about a section within the binary
///
/// This struct is marked `#[non_exhaustive]` to allow adding new fields without breaking
/// downstream code. Use `SectionInfo::new()` to construct instances.
#[non_exhaustive]
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
///
/// This struct is marked `#[non_exhaustive]` to allow adding new fields without breaking
/// downstream code. Use `ImportInfo::new()` to construct instances.
#[non_exhaustive]
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
///
/// This struct is marked `#[non_exhaustive]` to allow adding new fields without breaking
/// downstream code. Use `ExportInfo::new()` to construct instances.
#[non_exhaustive]
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
///
/// This struct is marked `#[non_exhaustive]` to allow adding new fields without breaking
/// downstream code. Use `ResourceMetadata::new()` to construct instances.
#[non_exhaustive]
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
///
/// This struct is marked `#[non_exhaustive]` to allow adding new fields without breaking
/// downstream code. Use `ResourceStringTable::new()` to construct instances.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ResourceStringTable {
    /// Language identifier
    pub language: u32,
    /// String entries in this table
    pub entries: Vec<ResourceStringEntry>,
}

/// Individual string entry in a resource string table
///
/// This struct is marked `#[non_exhaustive]` to allow adding new fields without breaking
/// downstream code. Use `ResourceStringEntry::new()` to construct instances.
#[non_exhaustive]
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
    /// Display score shown in output (debug only)
    ///
    /// When debug mode is enabled, this field contains the final computed score
    /// used for display purposes. This is `None` unless explicitly populated
    /// by the ranking system in debug mode.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub display_score: Option<i32>,
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

/// Context information for semantic classification
///
/// This struct is marked `#[non_exhaustive]` to allow adding new fields without breaking
/// downstream code. Use `StringContext::new()` to construct instances.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringContext {
    /// The type of section where the string was found
    pub section_type: SectionType,
    /// The name of the section where the string was found
    pub section_name: Option<String>,
    /// The format of the binary (ELF, PE, Mach-O)
    pub binary_format: BinaryFormat,
    /// The encoding of the string
    pub encoding: Encoding,
    /// The source of the string (section data, import, etc.)
    pub source: StringSource,
}

#[cfg(test)]
mod tests;
