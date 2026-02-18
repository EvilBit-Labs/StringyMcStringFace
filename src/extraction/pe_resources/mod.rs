//! PE Resource Extraction Module
//!
//! This module provides functionality for extracting resource metadata from PE binaries
//! using the pelite library. It implements a dual-parser strategy where goblin handles
//! general PE structure parsing (sections, imports, exports) while pelite specifically
//! handles resource directory parsing.
//!
//! **Note**: General UTF-16 string extraction from binary sections is now handled by the
//! `utf16` module (`src/extraction/utf16/`), which supports both UTF-16LE and UTF-16BE
//! with advanced confidence scoring. This module focuses specifically on PE resource-specific
//! extraction (VERSIONINFO, STRINGTABLE, MANIFEST).
//!
//! # Phase 1 vs Phase 2
//!
//! **Phase 1 (Complete)**: Resource enumeration and metadata extraction
//! - Detects VERSIONINFO, STRINGTABLE, and MANIFEST resources
//! - Extracts resource type, language, and size metadata
//! - Returns ResourceMetadata structures for discovered resources
//! - Phase 1 implementation complete as of Issue #4
//!
//! **Phase 2 (Complete)**: Actual string extraction from resources
//! - Parse VERSIONINFO structures to extract version strings
//! - Extract strings from STRINGTABLE resources
//! - Parse XML manifest content
//! - Return FoundString entries with proper encoding and tags
//!
//! # Testing
//!
//! The module includes comprehensive unit tests covering:
//! - Invalid/malformed PE data handling
//! - Missing resource directories (graceful degradation)
//! - Empty resource sections
//! - Multiple language variants
//! - Edge cases in VERSIONINFO, STRINGTABLE, and MANIFEST detection
//! - Integration with real PE fixtures
//!
//! All error paths are tested to ensure graceful degradation (returning empty Vec
//! rather than panicking or propagating errors).
//!
//! # Known Limitations
//!
//! - Offset field in ResourceMetadata is always None (pelite API limitation)
//! - Dialog and menu resource parsing not yet implemented (future enhancement)
//!
//! # Examples
//!
//! ## Phase 1: Resource Metadata Extraction
//!
//! ```rust
//! use stringy::extraction::pe_resources::extract_resources;
//! use stringy::types::ResourceType;
//!
//! # fn example() -> stringy::Result<()> {
//! let pe_data = std::fs::read("example.exe")?;
//! let resources = extract_resources(&pe_data);
//!
//! for resource in resources {
//!     match resource.resource_type {
//!         ResourceType::VersionInfo => {
//!             println!("Found VERSIONINFO: {} bytes, language {}",
//!                      resource.data_size, resource.language);
//!         }
//!         ResourceType::StringTable => {
//!             println!("Found STRINGTABLE: {} bytes, language {}",
//!                      resource.data_size, resource.language);
//!         }
//!         _ => {}
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Phase 2: Resource String Extraction
//!
//! ```rust
//! use stringy::extraction::pe_resources::extract_resource_strings;
//! use stringy::types::Tag;
//!
//! # fn example() -> stringy::Result<()> {
//! let pe_data = std::fs::read("example.exe")?;
//! let strings = extract_resource_strings(&pe_data);
//!
//! // Filter version info strings
//! let version_strings: Vec<_> = strings.iter()
//!     .filter(|s| s.tags.contains(&Tag::Version))
//!     .collect();
//!
//! // Filter string table entries
//! let ui_strings: Vec<_> = strings.iter()
//!     .filter(|s| s.tags.contains(&Tag::Resource) && !s.tags.contains(&Tag::Version))
//!     .collect();
//! # Ok(())
//! # }
//! ```

mod detection;
mod manifests;
mod string_tables;
mod version_info;

#[cfg(test)]
mod tests;

use crate::types::{FoundString, ResourceMetadata, Result};
use detection::{detect_manifests, detect_string_tables, detect_version_info};
use pelite::PeFile;

// Re-export public API functions from submodules to preserve the public interface.
// These were previously `pub fn` in the single-file module.
pub use manifests::{detect_manifest_encoding, extract_manifest_strings};
pub use string_tables::extract_string_table_strings;
pub use version_info::extract_version_info_strings;

// PE resource type constants
pub(crate) const RT_STRING: u32 = 6;
pub(crate) const RT_MANIFEST: u32 = 24;

/// Decode UTF-16LE byte slice to UTF-8 String
///
/// Handles odd-length inputs gracefully by truncating the last byte.
/// Strips trailing null terminators.
///
/// # Arguments
///
/// * `bytes` - UTF-16LE encoded byte slice
///
/// # Returns
///
/// Decoded UTF-8 string, or error if decoding fails
pub(crate) fn decode_utf16le(bytes: &[u8]) -> Result<String> {
    crate::extraction::util::decode_utf16le_bytes(bytes, true)
}

/// Extract resource metadata from a PE binary
///
/// This function attempts to parse the PE file using pelite and enumerate
/// all resources found in the resource directory. It gracefully handles
/// errors by returning an empty vector rather than failing, ensuring that
/// resource extraction failures don't break PE parsing.
///
/// # Arguments
///
/// * `data` - Raw PE binary data
///
/// # Returns
///
/// Vector of ResourceMetadata entries, or empty vector on error
pub fn extract_resources(data: &[u8]) -> Vec<ResourceMetadata> {
    // Attempt to parse PE using pelite
    let pe = match PeFile::from_bytes(data) {
        Ok(pe) => pe,
        Err(_) => {
            // Graceful degradation: return empty vec on parse error
            // This allows PE parsing to succeed even if resource extraction fails
            return Vec::new();
        }
    };

    // Get resource directory
    let resources = match pe.resources() {
        Ok(resources) => resources,
        Err(_) => {
            // No resource directory or error accessing it - not an error condition
            return Vec::new();
        }
    };

    // Enumerate all resources - handle errors gracefully
    enumerate_resources(&resources).unwrap_or_default()
}

/// Enumerate resources from the resource directory
///
/// Walks the resource directory tree using typed lookups and directory traversal
/// to identify VERSIONINFO, STRINGTABLE, and MANIFEST resources. Creates ResourceMetadata
/// entries for each discovered resource.
fn enumerate_resources(resources: &pelite::resources::Resources) -> Result<Vec<ResourceMetadata>> {
    let mut metadata = Vec::new();

    // Get root directory for tree traversal
    let root = match resources.root() {
        Ok(root) => root,
        Err(_) => return Ok(Vec::new()),
    };

    // Detect VERSIONINFO resources by enumerating the resource tree
    if let Ok(version_metas) = detect_version_info(&root, resources) {
        metadata.extend(version_metas);
    }

    // Detect STRINGTABLE resources by enumerating the resource tree
    if let Ok(string_tables) = detect_string_tables(&root) {
        metadata.extend(string_tables);
    }

    // Detect MANIFEST resources by enumerating the resource tree
    if let Ok(manifests) = detect_manifests(&root) {
        metadata.extend(manifests);
    }

    Ok(metadata)
}

/// Extract all resource strings from a PE binary
///
/// Main orchestrator function that combines VERSIONINFO, STRINGTABLE, and MANIFEST
/// string extraction. Returns all extracted strings with proper encoding and tags.
///
/// # Arguments
///
/// * `data` - Raw PE binary data
///
/// # Returns
///
/// Combined vector of FoundString entries from all resource types
pub fn extract_resource_strings(data: &[u8]) -> Vec<FoundString> {
    let mut all_strings = Vec::new();

    // Extract VERSIONINFO strings
    all_strings.extend(extract_version_info_strings(data));

    // Extract STRINGTABLE strings
    all_strings.extend(extract_string_table_strings(data));

    // Extract MANIFEST strings
    all_strings.extend(extract_manifest_strings(data));

    all_strings
}
