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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundString {
    /// The extracted string text
    pub text: String,
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
    /// Source of the string (section data, import, etc.)
    pub source: StringSource,
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
