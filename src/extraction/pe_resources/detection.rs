//! Resource type detection functions
//!
//! Functions that detect VERSIONINFO, STRINGTABLE, and MANIFEST resources
//! by enumerating the PE resource directory tree.

use crate::types::{ResourceMetadata, ResourceType, Result};
use pelite::resources::{Name, Resources};

use super::{RT_MANIFEST, RT_STRING};

/// Detect VERSIONINFO resources by enumerating the resource directory tree
///
/// Iterates over the resource directory tree to find all RT_VERSION resources.
/// For each found version info, extracts the language from the directory entry
/// and uses VersionInfo translation() as a fallback if needed.
pub(super) fn detect_version_info(
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

    // Get VersionInfo using pelite's typed lookup for fallback language mapping
    // Do not gate enumeration on this - continue even if it fails
    let fallback_language = resources
        .version_info()
        .ok()
        .and_then(|vi| vi.translation().first().map(|lang| lang.lang_id as u32))
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
            // Get the language ID from the directory entry name
            let language_id = match lang_entry.name() {
                Ok(Name::Id(id)) => id,
                _ => {
                    // If directory language is unavailable, use fallback
                    fallback_language
                }
            };

            // Get the data entry for this language
            let data_entry = match lang_entry.entry() {
                Ok(pelite::resources::Entry::DataEntry(data)) => data,
                _ => continue, // Skip if not a data entry
            };

            // Get the actual data size from the data entry
            let data_size = data_entry.size();

            // Use the language from the directory entry for per-entry language fidelity
            version_infos.push(ResourceMetadata::new(
                ResourceType::VersionInfo,
                language_id,
                data_size,
            ));
        }
    }

    Ok(version_infos)
}

/// Detect STRINGTABLE resources by enumerating the resource directory tree
///
/// Iterates over the resource directory tree to find all RT_STRING resources.
/// For each found string table, extracts the block ID, language, and data size.
pub(super) fn detect_string_tables(
    root: &pelite::resources::Directory,
) -> Result<Vec<ResourceMetadata>> {
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

            string_tables.push(ResourceMetadata::new(
                ResourceType::StringTable,
                language_id,
                data_size,
            ));
        }
    }

    Ok(string_tables)
}

/// Detect MANIFEST resources by enumerating the resource directory tree
///
/// Uses typed resource ID lookup to find RT_MANIFEST resources.
pub(super) fn detect_manifests(
    root: &pelite::resources::Directory,
) -> Result<Vec<ResourceMetadata>> {
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

            manifests.push(ResourceMetadata::new(
                ResourceType::Manifest,
                language_id,
                data_size,
            ));
        }
    }

    Ok(manifests)
}
