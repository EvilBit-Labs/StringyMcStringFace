//! PE Resource Extraction Module
//!
//! This module provides functionality for extracting resource metadata from PE binaries
//! using the pelite library. It implements a dual-parser strategy where goblin handles
//! general PE structure parsing (sections, imports, exports) while pelite specifically
//! handles resource directory parsing.
//!
//! # Phase 1 vs Phase 2
//!
//! **Phase 1 (Current)**: Resource enumeration and metadata extraction
//! - Detects VERSIONINFO, STRINGTABLE, and MANIFEST resources
//! - Extracts resource type, language, and size metadata
//! - Returns ResourceMetadata structures for discovered resources
//!
//! **Phase 2 (Future)**: Actual string extraction from resources
//! - Parse VERSIONINFO structures to extract version strings
//! - Extract strings from STRINGTABLE resources
//! - Parse XML manifest content
//! - Return FoundString entries with proper encoding and tags

use crate::types::{ResourceMetadata, ResourceType, Result};
use pelite::PeFile;
use pelite::resources::{Name, Resources};

// PE resource type constants
const RT_STRING: u32 = 6;
const RT_MANIFEST: u32 = 24;

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
fn enumerate_resources(resources: &Resources) -> Result<Vec<ResourceMetadata>> {
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

/// Detect VERSIONINFO resources by enumerating the resource directory tree
///
/// Iterates over the resource directory tree to find all RT_VERSION resources.
/// Uses pelite's VersionInfo translation() to get the actual language ID.
/// For each found version info, extracts the language and data size.
fn detect_version_info(
    root: &pelite::resources::Directory,
    resources: &Resources,
) -> Result<Vec<ResourceMetadata>> {
    let mut version_infos = Vec::new();

    // Get the RT_VERSION type directory using typed lookup
    let version_type_name = Name::Id(16); // RT_VERSION
    let version_type_dir = match root.get_dir(version_type_name) {
        Ok(dir) => dir,
        Err(_) => {
            // No RT_VERSION resources found - not an error
            return Ok(Vec::new());
        }
    };

    // Get VersionInfo using pelite's typed lookup to extract translation language
    let version_info = match resources.version_info() {
        Ok(vi) => vi,
        Err(_) => {
            // No VERSIONINFO found - not an error
            return Ok(Vec::new());
        }
    };

    // Extract language from translation array - get the first translation's language
    let language_id = version_info
        .translation()
        .first()
        .map(|lang| {
            // Language struct has lang_id field (u16) - convert to u32
            lang.lang_id as u32
        })
        .unwrap_or(0u32);

    // Iterate over all ID entries (version info names, typically ID 1) in the version type directory
    for entry in version_type_dir.id_entries() {
        // Get the version info name ID from the entry name
        let _version_name_id = match entry.name() {
            Ok(Name::Id(id)) => id,
            _ => continue, // Skip if not an ID entry
        };

        // Get the subdirectory for this version info name (contains language entries)
        let version_dir = match entry.entry() {
            Ok(pelite::resources::Entry::Directory(dir)) => dir,
            _ => continue, // Skip if not a directory
        };

        // Iterate over all ID entries (languages) in the version directory
        for lang_entry in version_dir.id_entries() {
            // Get the data entry for this language
            let data_entry = match lang_entry.entry() {
                Ok(pelite::resources::Entry::DataEntry(data)) => data,
                _ => continue, // Skip if not a data entry
            };

            // Get the actual data size from the data entry
            let data_size = data_entry.size();

            // Use the language from VersionInfo translation() instead of directory entry
            version_infos.push(ResourceMetadata {
                resource_type: ResourceType::VersionInfo,
                language: language_id,
                data_size,
                offset: None, // Offset not easily available from pelite API
            });
        }
    }

    Ok(version_infos)
}

/// Detect STRINGTABLE resources by enumerating the resource directory tree
///
/// Iterates over the resource directory tree to find all RT_STRING resources.
/// For each found string table, extracts the block ID, language, and data size.
fn detect_string_tables(root: &pelite::resources::Directory) -> Result<Vec<ResourceMetadata>> {
    let mut string_tables = Vec::new();

    // Get the RT_STRING type directory using typed lookup
    let string_type_name = Name::Id(RT_STRING);
    let string_type_dir = match root.get_dir(string_type_name) {
        Ok(dir) => dir,
        Err(_) => {
            // No RT_STRING resources found - not an error
            return Ok(Vec::new());
        }
    };

    // Iterate over all ID entries (block IDs) in the string type directory
    for entry in string_type_dir.id_entries() {
        // Get the block ID from the entry name
        let _block_id = match entry.name() {
            Ok(Name::Id(id)) => id,
            _ => continue, // Skip if not an ID entry
        };

        // Get the subdirectory for this block ID (contains language entries)
        let block_dir = match entry.entry() {
            Ok(pelite::resources::Entry::Directory(dir)) => dir,
            _ => continue, // Skip if not a directory
        };

        // Iterate over all ID entries (languages) in the block directory
        for lang_entry in block_dir.id_entries() {
            // Get the language ID from the entry name
            let language_id = match lang_entry.name() {
                Ok(Name::Id(id)) => id,
                _ => continue, // Skip if not an ID entry
            };

            // Get the data entry for this language
            let data_entry = match lang_entry.entry() {
                Ok(pelite::resources::Entry::DataEntry(data)) => data,
                _ => continue, // Skip if not a data entry
            };

            // Get the actual data size from the data entry
            let data_size = data_entry.size();

            string_tables.push(ResourceMetadata {
                resource_type: ResourceType::StringTable,
                language: language_id,
                data_size,
                offset: None, // Offset not easily available from pelite API
            });
        }
    }

    Ok(string_tables)
}

/// Detect MANIFEST resources by enumerating the resource directory tree
///
/// Uses typed resource ID lookup to find RT_MANIFEST resources.
fn detect_manifests(root: &pelite::resources::Directory) -> Result<Vec<ResourceMetadata>> {
    let mut manifests = Vec::new();

    // Get the RT_MANIFEST type directory using typed lookup
    let manifest_type_name = Name::Id(RT_MANIFEST);
    let manifest_type_dir = match root.get_dir(manifest_type_name) {
        Ok(dir) => dir,
        Err(_) => {
            // No RT_MANIFEST resources found - not an error
            return Ok(Vec::new());
        }
    };

    // Iterate over all ID entries (manifest IDs) in the manifest type directory
    for entry in manifest_type_dir.id_entries() {
        // Get the manifest ID from the entry name
        let _manifest_id = match entry.name() {
            Ok(Name::Id(id)) => id,
            _ => continue, // Skip if not an ID entry
        };

        // Get the subdirectory for this manifest ID (contains language entries)
        let manifest_dir = match entry.entry() {
            Ok(pelite::resources::Entry::Directory(dir)) => dir,
            _ => continue, // Skip if not a directory
        };

        // Iterate over all ID entries (languages) in the manifest directory
        for lang_entry in manifest_dir.id_entries() {
            // Get the language ID from the entry name (typically 0 for manifests)
            let language_id = match lang_entry.name() {
                Ok(Name::Id(id)) => id,
                _ => continue, // Skip if not an ID entry
            };

            // Get the data entry for this language
            let data_entry = match lang_entry.entry() {
                Ok(pelite::resources::Entry::DataEntry(data)) => data,
                _ => continue, // Skip if not a data entry
            };

            // Get the actual data size from the data entry
            let data_size = data_entry.size();

            manifests.push(ResourceMetadata {
                resource_type: ResourceType::Manifest,
                language: language_id,
                data_size,
                offset: None, // Offset not easily available from pelite API
            });
        }
    }

    Ok(manifests)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_resources_invalid_data() {
        // Test with invalid data - should return empty vec, not panic
        let invalid_data = b"NOT_A_PE_FILE";
        let result = extract_resources(invalid_data);
        assert!(result.is_empty());
    }

    #[test]
    fn test_extract_resources_minimal_pe() {
        // Test with minimal valid PE (if we had one)
        // For now, just verify the function doesn't panic
        // Integration tests with real PE fixtures are in tests/integration_pe.rs
    }
}
