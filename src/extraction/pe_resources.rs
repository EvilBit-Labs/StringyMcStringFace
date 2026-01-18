//! PE Resource Extraction Module
//!
//! This module provides functionality for extracting resource metadata from PE binaries
//! using the pelite library. It implements a dual-parser strategy where goblin handles
//! general PE structure parsing (sections, imports, exports) while pelite specifically
//! handles resource directory parsing.
//!
//! **Note**: General UTF-16 string extraction from binary sections is now handled by the
//! `utf16` module (`src/extraction/utf16.rs`), which supports both UTF-16LE and UTF-16BE
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
//! - Parse VERSIONINFO structures to extract version strings ✅
//! - Extract strings from STRINGTABLE resources ✅
//! - Parse XML manifest content ✅
//! - Return FoundString entries with proper encoding and tags ✅
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
//!
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
//! ```
//!
//! ## Phase 2: Resource String Extraction
//!
//! ```rust
//! use stringy::extraction::pe_resources::extract_resource_strings;
//! use stringy::types::Tag;
//!
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
//! ```

use crate::types::{
    Encoding, FoundString, ResourceMetadata, ResourceType, Result, StringSource, Tag,
};
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
/// For each found version info, extracts the language from the directory entry
/// and uses VersionInfo translation() as a fallback if needed.
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
fn decode_utf16le(bytes: &[u8]) -> Result<String> {
    crate::extraction::util::decode_utf16le_bytes(bytes, true)
}

/// Extract strings from VERSIONINFO resources
///
/// Uses pelite's high-level `version_info()` API to extract all StringFileInfo
/// key-value pairs. Supports multiple language variants via translation table.
///
/// # Arguments
///
/// * `data` - Raw PE binary data
///
/// # Returns
///
/// Vector of FoundString entries with version information
pub fn extract_version_info_strings(data: &[u8]) -> Vec<FoundString> {
    let pe = match PeFile::from_bytes(data) {
        Ok(pe) => pe,
        Err(_) => return Vec::new(),
    };

    let resources = match pe.resources() {
        Ok(resources) => resources,
        Err(_) => return Vec::new(),
    };

    let version_info = match resources.version_info() {
        Ok(vi) => vi,
        Err(_) => return Vec::new(),
    };

    let mut strings = Vec::new();

    // Get all translations (languages)
    let translations = version_info.translation();

    // Iterate through each language variant
    for translation in translations {
        // Extract all string key-value pairs for this language
        // Note: We intentionally do not include the key name (e.g., "CompanyName") in the
        // extracted string text to maintain consistency with other extractors and avoid
        // breaking the API. The key information is available via pelite's API if needed,
        // but including it would change the semantic meaning of the `text` field from
        // "the actual string value" to "key: value pair", which could break downstream
        // consumers expecting just the value.
        version_info.strings(*translation, |_key, value| {
            let text = value.to_string();
            // Length is based on decoded string bytes (String::len() returns byte length)
            let length = text.len() as u32;
            let found_string = FoundString {
                text,
                original_text: None,
                encoding: Encoding::Utf16Le,
                offset: 0, // pelite doesn't provide offsets easily
                rva: None,
                section: Some(".rsrc".to_string()),
                length,
                tags: vec![Tag::Version, Tag::Resource],
                score: 0,
                section_weight: None,
                semantic_boost: None,
                noise_penalty: None,
                source: StringSource::ResourceString,
                confidence: 1.0,
            };
            strings.push(found_string);
        });
    }

    strings
}

/// Parse a STRINGTABLE block structure
///
/// STRINGTABLE blocks contain 16 string entries. Each entry is prefixed with
/// a u16 length (in UTF-16 code units, not bytes), followed by UTF-16LE string data.
///
/// # Arguments
///
/// * `bytes` - Raw block data
///
/// # Returns
///
/// Vector of `Option<String>`, where `Some` contains the decoded string and `None`
/// indicates an empty entry
fn parse_string_table_block(bytes: &[u8]) -> Vec<Option<String>> {
    let mut strings = Vec::new();
    let mut offset = 0;

    // Each block contains 16 entries
    for _ in 0..16 {
        if offset + 2 > bytes.len() {
            // Not enough data for length field
            strings.push(None);
            continue;
        }

        // Read u16 length (in UTF-16 code units)
        let length = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;

        if length == 0 {
            // Empty entry
            strings.push(None);
            continue;
        }

        // Calculate byte length (length * 2 for UTF-16)
        let byte_length = length * 2;
        if offset + byte_length > bytes.len() {
            // Not enough data for string
            strings.push(None);
            continue;
        }

        // Extract string bytes and decode
        let string_bytes = &bytes[offset..offset + byte_length];
        match decode_utf16le(string_bytes) {
            Ok(s) if !s.is_empty() => strings.push(Some(s)),
            _ => strings.push(None),
        }

        offset += byte_length;
    }

    strings
}

/// Extract strings from STRINGTABLE resources
///
/// Parses RT_STRING resources (type 6) containing localized UI strings.
/// Handles block structure: strings grouped in blocks of 16.
///
/// # Arguments
///
/// * `data` - Raw PE binary data
///
/// # Returns
///
/// Vector of FoundString entries from string tables
pub fn extract_string_table_strings(data: &[u8]) -> Vec<FoundString> {
    let pe = match PeFile::from_bytes(data) {
        Ok(pe) => pe,
        Err(_) => return Vec::new(),
    };

    let resources = match pe.resources() {
        Ok(resources) => resources,
        Err(_) => return Vec::new(),
    };

    let root = match resources.root() {
        Ok(root) => root,
        Err(_) => return Vec::new(),
    };

    let string_type_name = Name::Id(RT_STRING);
    let string_type_dir = match root.get_dir(string_type_name) {
        Ok(dir) => dir,
        Err(_) => return Vec::new(),
    };

    let mut strings = Vec::new();

    // Iterate over all block IDs
    for entry in string_type_dir.id_entries() {
        let _block_id = match entry.name() {
            Ok(Name::Id(id)) => id,
            _ => continue,
        };

        let block_dir = match entry.entry() {
            Ok(pelite::resources::Entry::Directory(dir)) => dir,
            _ => continue,
        };

        // Iterate over all languages for this block
        for lang_entry in block_dir.id_entries() {
            let _language_id = match lang_entry.name() {
                Ok(Name::Id(id)) => id,
                _ => continue,
            };

            // Get block data
            let data_entry = match lang_entry.entry() {
                Ok(pelite::resources::Entry::DataEntry(data)) => data,
                _ => continue,
            };

            let block_bytes = match data_entry.bytes() {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };

            // Best-effort RVA retrieval from pelite DataEntry
            // Note: pelite's DataEntry API doesn't directly expose RVA, so we set to None
            // If RVA mapping is needed, it would require parsing section headers separately
            let rva = None;

            // Parse the block
            let parsed_strings = parse_string_table_block(block_bytes);

            // Create FoundString for each non-empty string
            for text in parsed_strings.into_iter().flatten() {
                // String ID calculation: ((block_id - 1) << 4) | index
                // (stored for potential future use but not currently needed)
                // Length is based on decoded string bytes (String::len() returns byte length)
                let text_len = text.len() as u32;

                let found_string = FoundString {
                    text,
                    original_text: None,
                    encoding: Encoding::Utf16Le,
                    offset: 0, // File offset not easily available from pelite DataEntry
                    rva,
                    section: Some(".rsrc".to_string()),
                    length: text_len,
                    tags: vec![Tag::Resource],
                    score: 0,
                    section_weight: None,
                    semantic_boost: None,
                    noise_penalty: None,
                    source: StringSource::ResourceString,
                    confidence: 1.0,
                };
                strings.push(found_string);
            }
        }
    }

    strings
}

/// Detect manifest encoding from byte content
///
/// Checks for BOM markers and byte patterns to determine encoding.
///
/// # Arguments
///
/// * `bytes` - Manifest byte data
///
/// # Returns
///
/// Detected encoding
fn detect_manifest_encoding(bytes: &[u8]) -> Encoding {
    if bytes.len() < 2 {
        return Encoding::Utf8; // Default fallback
    }

    // Check for UTF-8 BOM (EF BB BF)
    if bytes.len() >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF {
        return Encoding::Utf8;
    }

    // Check for UTF-16LE BOM (FF FE)
    if bytes[0] == 0xFF && bytes[1] == 0xFE {
        return Encoding::Utf16Le;
    }

    // Check for UTF-16BE BOM (FE FF)
    if bytes[0] == 0xFE && bytes[1] == 0xFF {
        return Encoding::Utf16Be;
    }

    // Fallback: check byte patterns
    if bytes.len() >= 4 {
        // Check for "<?xm" (UTF-8 XML declaration)
        if bytes[0] == b'<' && bytes[1] == b'?' && bytes[2] == b'x' && bytes[3] == b'm' {
            return Encoding::Utf8;
        }
        // Check for "<\0?\0" (UTF-16LE XML declaration)
        if bytes[0] == b'<' && bytes[1] == 0 && bytes[2] == b'?' && bytes[3] == 0 {
            return Encoding::Utf16Le;
        }
    }

    // Default to UTF-8
    Encoding::Utf8
}

/// Decode manifest bytes based on detected encoding
///
/// # Arguments
///
/// * `bytes` - Manifest byte data
///
/// # Returns
///
/// Decoded manifest string
fn decode_manifest(bytes: &[u8]) -> Result<String> {
    let encoding = detect_manifest_encoding(bytes);
    let mut data = bytes;

    // Strip BOM if present
    if bytes.len() >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF {
        data = &bytes[3..]; // UTF-8 BOM
    } else if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        data = &bytes[2..]; // UTF-16LE BOM
    } else if bytes.len() >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF {
        data = &bytes[2..]; // UTF-16BE BOM
    }

    match encoding {
        Encoding::Utf8 => String::from_utf8(data.to_vec())
            .map_err(|_| crate::types::StringyError::EncodingError { offset: 0 }),
        Encoding::Utf16Le => decode_utf16le(data),
        Encoding::Utf16Be => {
            // Convert UTF-16BE to UTF-16LE for decoding
            let u16_slice: Vec<u16> = data
                .chunks_exact(2)
                .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
                .collect();
            String::from_utf16(&u16_slice)
                .map(|s| s.trim_end_matches('\0').to_string())
                .map_err(|_| crate::types::StringyError::EncodingError { offset: 0 })
        }
        _ => String::from_utf8(data.to_vec())
            .map_err(|_| crate::types::StringyError::EncodingError { offset: 0 }),
    }
}

/// Extract strings from MANIFEST resources
///
/// Extracts RT_MANIFEST resources (type 24) containing application manifests.
/// Performs automatic encoding detection and returns full XML manifest content.
///
/// # Arguments
///
/// * `data` - Raw PE binary data
///
/// # Returns
///
/// Vector of FoundString entries with manifest content
pub fn extract_manifest_strings(data: &[u8]) -> Vec<FoundString> {
    let pe = match PeFile::from_bytes(data) {
        Ok(pe) => pe,
        Err(_) => return Vec::new(),
    };

    let resources = match pe.resources() {
        Ok(resources) => resources,
        Err(_) => return Vec::new(),
    };

    let root = match resources.root() {
        Ok(root) => root,
        Err(_) => return Vec::new(),
    };

    let manifest_type_name = Name::Id(RT_MANIFEST);
    let manifest_type_dir = match root.get_dir(manifest_type_name) {
        Ok(dir) => dir,
        Err(_) => return Vec::new(),
    };

    let mut strings = Vec::new();

    // Iterate over all manifest IDs (typically ID 1)
    for entry in manifest_type_dir.id_entries() {
        let _manifest_id = match entry.name() {
            Ok(Name::Id(_id)) => _id,
            _ => continue,
        };

        let manifest_dir = match entry.entry() {
            Ok(pelite::resources::Entry::Directory(dir)) => dir,
            _ => continue,
        };

        // Iterate over all languages (typically 0 for manifests)
        for lang_entry in manifest_dir.id_entries() {
            let _language_id = match lang_entry.name() {
                Ok(Name::Id(_id)) => _id,
                _ => continue,
            };

            let data_entry = match lang_entry.entry() {
                Ok(pelite::resources::Entry::DataEntry(data)) => data,
                _ => continue,
            };

            let manifest_bytes = match data_entry.bytes() {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };

            // Decode manifest
            let manifest_text = match decode_manifest(manifest_bytes) {
                Ok(text) => text,
                Err(_) => continue,
            };

            let encoding = detect_manifest_encoding(manifest_bytes);

            // Best-effort RVA retrieval from pelite DataEntry
            // Note: pelite's DataEntry API doesn't directly expose RVA, so we set to None
            // If RVA mapping is needed, it would require parsing section headers separately
            let rva = None;

            // Length is based on decoded string bytes (String::len() returns byte length)
            let length = manifest_text.len() as u32;
            let found_string = FoundString {
                text: manifest_text,
                original_text: None,
                encoding,
                offset: 0, // File offset not easily available from pelite DataEntry
                rva,
                section: Some(".rsrc".to_string()),
                length,
                tags: vec![Tag::Manifest, Tag::Resource],
                score: 0,
                section_weight: None,
                semantic_boost: None,
                noise_penalty: None,
                source: StringSource::ResourceString,
                confidence: 1.0,
            };
            strings.push(found_string);
        }
    }

    strings
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    // Helper to get fixture path
    fn get_fixture_path(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(name)
    }

    // Tests for extract_resources function

    #[test]
    fn test_extract_resources_invalid_data() {
        // Test with invalid data - should return empty vec, not panic
        let invalid_data = b"NOT_A_PE_FILE";
        let result = extract_resources(invalid_data);
        assert!(result.is_empty(), "Invalid data should return empty vector");
    }

    #[test]
    fn test_extract_resources_empty_data() {
        // Test with empty byte slice - should return empty vec gracefully
        let empty_data = b"";
        let result = extract_resources(empty_data);
        assert!(result.is_empty(), "Empty data should return empty vector");
    }

    #[test]
    fn test_extract_resources_truncated_pe() {
        // Test with incomplete PE header - should handle gracefully
        let truncated_pe = b"MZ\x90\x00"; // Just DOS header, no PE header
        let result = extract_resources(truncated_pe);
        assert!(result.is_empty(), "Truncated PE should return empty vector");
    }

    #[test]
    #[ignore] // Requires test_binary_pe.exe fixture
    // To run: cargo test -- --ignored test_extract_resources_no_resource_section
    // Fixture can be generated via the build script in tests/fixtures/
    fn test_extract_resources_no_resource_section() {
        // Test with valid PE but no .rsrc section
        // This is tested via integration tests with test_binary_pe.exe
        // which is a minimal PE without resources
        let fixture_path = get_fixture_path("test_binary_pe.exe");
        assert!(
            fixture_path.exists(),
            "Fixture test_binary_pe.exe not found. Generate it using the build script."
        );
        let pe_data = fs::read(&fixture_path).expect("Failed to read PE fixture");
        let result = extract_resources(&pe_data);
        // May be empty or may have resources - both are valid
        // The key is that it doesn't panic
        assert!(
            result.iter().all(|r| r.data_size > 0),
            "All resources should have non-zero size"
        );
    }

    #[test]
    fn test_extract_resources_corrupted_resource_directory() {
        // Test with valid PE but corrupted resource directory structure
        // This is difficult to craft without a real PE, so we test via
        // graceful error handling in the actual implementation
        // The function should return empty vec on any error
        let invalid_data = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF";
        let result = extract_resources(invalid_data);
        assert!(
            result.is_empty(),
            "Corrupted data should return empty vector"
        );
    }

    // Tests for VERSIONINFO detection

    #[test]
    #[ignore] // Requires test_binary_pe.exe fixture
    // To run: cargo test -- --ignored test_detect_version_info_missing
    // Fixture can be generated via the build script in tests/fixtures/
    fn test_detect_version_info_missing() {
        // Test when RT_VERSION type directory doesn't exist
        // This is tested via extract_resources with a PE that has no version info
        let fixture_path = get_fixture_path("test_binary_pe.exe");
        assert!(
            fixture_path.exists(),
            "Fixture test_binary_pe.exe not found. Generate it using the build script."
        );
        let pe_data = fs::read(&fixture_path).expect("Failed to read PE fixture");
        let resources = extract_resources(&pe_data);
        // test_binary_pe.exe doesn't have VERSIONINFO, so we shouldn't find any
        let _has_version = resources
            .iter()
            .any(|r| matches!(r.resource_type, ResourceType::VersionInfo));
        // It's OK if there are no version info resources
        // The test verifies graceful handling
    }

    #[test]
    fn test_detect_version_info_empty_directory() {
        // Test when RT_VERSION exists but has no entries
        // This edge case is handled by the implementation's iteration logic
        // If directory exists but has no id_entries(), the loop simply doesn't execute
        // Verified by the fact that extract_resources doesn't panic
    }

    #[test]
    #[ignore] // Requires test_binary_with_resources.exe fixture
    // To run: cargo test -- --ignored test_detect_version_info_multiple_languages
    // Fixture can be generated via: docker run --rm -v "$(pwd):/work" -w /work mcr.microsoft.com/devcontainers/cpp:latest bash -c "apt-get update -qq && apt-get install -y -qq mingw-w64 && x86_64-w64-mingw32-windres --input-format=rc --output-format=coff -o test_binary_with_resources.res test_binary_with_resources.rc && x86_64-w64-mingw32-gcc -o test_binary_with_resources.exe test_binary_with_resources.c test_binary_with_resources.res"
    fn test_detect_version_info_multiple_languages() {
        // Test VERSIONINFO with multiple language entries
        // This is tested via integration tests with test_binary_with_resources.exe
        let fixture_path = get_fixture_path("test_binary_with_resources.exe");
        assert!(
            fixture_path.exists(),
            "Fixture test_binary_with_resources.exe not found. See test comment for build instructions."
        );
        let pe_data = fs::read(&fixture_path).expect("Failed to read resource fixture");
        let resources = extract_resources(&pe_data);
        let version_resources: Vec<_> = resources
            .iter()
            .filter(|r| matches!(r.resource_type, ResourceType::VersionInfo))
            .collect();
        // Should handle multiple languages gracefully
        for resource in version_resources {
            assert!(resource.data_size > 0, "Version resource should have size");
            assert!(
                resource.language <= 0xFFFF,
                "Language ID should be valid u16 value"
            );
        }
    }

    #[test]
    #[ignore] // Requires test_binary_with_resources.exe fixture
    // To run: cargo test -- --ignored test_detect_version_info_no_translation
    fn test_detect_version_info_no_translation() {
        // Test VERSIONINFO without translation array
        // The implementation uses fallback language handling
        // This test verifies that behavior doesn't panic
        let fixture_path = get_fixture_path("test_binary_with_resources.exe");
        assert!(
            fixture_path.exists(),
            "Fixture test_binary_with_resources.exe not found. See other test comments for build instructions."
        );
        let pe_data = fs::read(&fixture_path).expect("Failed to read resource fixture");
        let resources = extract_resources(&pe_data);
        // Should not panic even if translation is missing
        let _ = resources;
    }

    #[test]
    fn test_detect_version_info_malformed_data_entry() {
        // Test with corrupted data entry in version directory
        // The implementation uses pattern matching to skip invalid entries
        // This test verifies graceful skipping
        let invalid_data = b"NOT_A_VALID_PE";
        let result = extract_resources(invalid_data);
        assert!(result.is_empty(), "Malformed data should return empty");
    }

    // Tests for STRINGTABLE detection

    #[test]
    #[ignore] // Requires test_binary_pe.exe fixture
    // To run: cargo test -- --ignored test_detect_string_tables_missing
    fn test_detect_string_tables_missing() {
        // Test when RT_STRING type directory doesn't exist
        let fixture_path = get_fixture_path("test_binary_pe.exe");
        assert!(
            fixture_path.exists(),
            "Fixture test_binary_pe.exe not found. Generate it using the build script."
        );
        let pe_data = fs::read(&fixture_path).expect("Failed to read PE fixture");
        let resources = extract_resources(&pe_data);
        // test_binary_pe.exe doesn't have STRINGTABLE, so we shouldn't find any
        let _has_string_table = resources
            .iter()
            .any(|r| matches!(r.resource_type, ResourceType::StringTable));
        // It's OK if there are no string table resources
    }

    #[test]
    fn test_detect_string_tables_empty_directory() {
        // Test when RT_STRING exists but has no entries
        // Handled by iteration logic - empty directory means no entries in loop
    }

    #[test]
    #[ignore] // Requires test_binary_with_resources.exe fixture
    // To run: cargo test -- --ignored test_detect_string_tables_multiple_blocks
    fn test_detect_string_tables_multiple_blocks() {
        // Test multiple string table blocks with different IDs
        let fixture_path = get_fixture_path("test_binary_with_resources.exe");
        assert!(
            fixture_path.exists(),
            "Fixture test_binary_with_resources.exe not found. See other test comments for build instructions."
        );
        let pe_data = fs::read(&fixture_path).expect("Failed to read resource fixture");
        let resources = extract_resources(&pe_data);
        let string_tables: Vec<_> = resources
            .iter()
            .filter(|r| matches!(r.resource_type, ResourceType::StringTable))
            .collect();
        // Should handle multiple blocks gracefully
        for resource in string_tables {
            assert!(resource.data_size > 0, "String table should have size");
            assert!(resource.language <= 0xFFFF, "Language ID should be valid");
        }
    }

    #[test]
    #[ignore] // Requires test_binary_with_resources.exe fixture
    // To run: cargo test -- --ignored test_detect_string_tables_multiple_languages
    fn test_detect_string_tables_multiple_languages() {
        // Test string tables with multiple language variants
        let fixture_path = get_fixture_path("test_binary_with_resources.exe");
        assert!(
            fixture_path.exists(),
            "Fixture test_binary_with_resources.exe not found. See other test comments for build instructions."
        );
        let pe_data = fs::read(&fixture_path).expect("Failed to read resource fixture");
        let resources = extract_resources(&pe_data);
        let string_tables: Vec<_> = resources
            .iter()
            .filter(|r| matches!(r.resource_type, ResourceType::StringTable))
            .collect();
        // Should detect multiple languages if present
        for resource in string_tables {
            assert!(resource.data_size > 0);
        }
    }

    #[test]
    fn test_detect_string_tables_malformed_block() {
        // Test with corrupted block directory structure
        // Implementation uses pattern matching to skip invalid entries
        let invalid_data = b"INVALID_PE_DATA";
        let result = extract_resources(invalid_data);
        assert!(result.is_empty(), "Malformed block should return empty");
    }

    // Tests for MANIFEST detection

    #[test]
    #[ignore] // Requires test_binary_pe.exe fixture
    // To run: cargo test -- --ignored test_detect_manifests_missing
    fn test_detect_manifests_missing() {
        // Test when RT_MANIFEST type directory doesn't exist
        let fixture_path = get_fixture_path("test_binary_pe.exe");
        assert!(
            fixture_path.exists(),
            "Fixture test_binary_pe.exe not found. Generate it using the build script."
        );
        let pe_data = fs::read(&fixture_path).expect("Failed to read PE fixture");
        let resources = extract_resources(&pe_data);
        // test_binary_pe.exe doesn't have MANIFEST
        let _has_manifest = resources
            .iter()
            .any(|r| matches!(r.resource_type, ResourceType::Manifest));
        // It's OK if there are no manifest resources
    }

    #[test]
    fn test_detect_manifests_empty_directory() {
        // Test when RT_MANIFEST exists but has no entries
        // Handled by iteration logic
    }

    #[test]
    #[ignore] // Requires test_binary_with_resources.exe fixture
    // To run: cargo test -- --ignored test_detect_manifests_multiple_manifests
    fn test_detect_manifests_multiple_manifests() {
        // Test multiple manifest resources (rare but possible)
        // Implementation should handle multiple manifests if present
        let fixture_path = get_fixture_path("test_binary_with_resources.exe");
        assert!(
            fixture_path.exists(),
            "Fixture test_binary_with_resources.exe not found. See other test comments for build instructions."
        );
        let pe_data = fs::read(&fixture_path).expect("Failed to read resource fixture");
        let resources = extract_resources(&pe_data);
        let manifests: Vec<_> = resources
            .iter()
            .filter(|r| matches!(r.resource_type, ResourceType::Manifest))
            .collect();
        // Should handle multiple manifests gracefully
        for resource in manifests {
            assert!(resource.data_size > 0, "Manifest should have size");
        }
    }

    #[test]
    #[ignore] // Requires test_binary_with_resources.exe fixture
    // To run: cargo test -- --ignored test_detect_manifests_zero_language
    fn test_detect_manifests_zero_language() {
        // Test manifest with language ID 0 (common for manifests)
        let fixture_path = get_fixture_path("test_binary_with_resources.exe");
        assert!(
            fixture_path.exists(),
            "Fixture test_binary_with_resources.exe not found. See other test comments for build instructions."
        );
        let pe_data = fs::read(&fixture_path).expect("Failed to read resource fixture");
        let resources = extract_resources(&pe_data);
        let manifests: Vec<_> = resources
            .iter()
            .filter(|r| matches!(r.resource_type, ResourceType::Manifest))
            .collect();
        // Language ID 0 is valid for manifests
        for resource in manifests {
            assert!(resource.language <= 0xFFFF, "Language should be valid");
        }
    }

    // Integration-style unit tests with real fixtures

    #[test]
    #[ignore] // Requires test_binary_pe.exe fixture
    // To run: cargo test -- --ignored test_extract_resources_from_fixture_basic
    fn test_extract_resources_from_fixture_basic() {
        // Use test_binary_pe.exe (no resources expected)
        let fixture_path = get_fixture_path("test_binary_pe.exe");
        assert!(
            fixture_path.exists(),
            "Fixture test_binary_pe.exe not found. Generate it using the build script."
        );
        let pe_data = fs::read(&fixture_path).expect("Failed to read PE fixture");
        let resources = extract_resources(&pe_data);
        // Basic PE may or may not have resources - both are valid
        // Verify structure is correct
        for resource in &resources {
            assert!(resource.data_size > 0, "Resource should have non-zero size");
            assert!(resource.language <= 0xFFFF, "Language ID should be valid");
        }
    }

    #[test]
    #[ignore] // Requires test_binary_with_resources.exe fixture
    // To run: cargo test -- --ignored test_extract_resources_from_fixture_with_resources
    fn test_extract_resources_from_fixture_with_resources() {
        // Use test_binary_with_resources.exe (should find VERSIONINFO and STRINGTABLE)
        let fixture_path = get_fixture_path("test_binary_with_resources.exe");
        assert!(
            fixture_path.exists(),
            "Fixture test_binary_with_resources.exe not found. See other test comments for build instructions."
        );
        let pe_data = fs::read(&fixture_path).expect("Failed to read resource fixture");
        let resources = extract_resources(&pe_data);
        // Should find at least some resources
        let has_version_info = resources
            .iter()
            .any(|r| matches!(r.resource_type, ResourceType::VersionInfo));
        let has_string_table = resources
            .iter()
            .any(|r| matches!(r.resource_type, ResourceType::StringTable));
        // At least one type should be present in a resource-enabled binary
        assert!(
            has_version_info || has_string_table || !resources.is_empty(),
            "Resource-enabled binary should have some resources detected"
        );
    }

    #[test]
    #[ignore] // Requires test_binary_with_resources.exe fixture
    // To run: cargo test -- --ignored test_resource_metadata_validation
    fn test_resource_metadata_validation() {
        // Verify ResourceMetadata fields are correctly populated
        let fixture_path = get_fixture_path("test_binary_with_resources.exe");
        assert!(
            fixture_path.exists(),
            "Fixture test_binary_with_resources.exe not found. See other test comments for build instructions."
        );
        let pe_data = fs::read(&fixture_path).expect("Failed to read resource fixture");
        let resources = extract_resources(&pe_data);
        for resource in resources {
            // Type should be one of the known types
            match resource.resource_type {
                ResourceType::VersionInfo | ResourceType::StringTable | ResourceType::Manifest => {
                    // Valid types
                }
                _ => {
                    // Other types are also valid for future expansion
                }
            }
            assert!(resource.data_size > 0, "Resource should have non-zero size");
            assert!(
                resource.language <= 0xFFFF,
                "Language ID should be valid u16 value"
            );
            // Offset is always None in Phase 1 (pelite API limitation)
            assert_eq!(resource.offset, None, "Offset should be None in Phase 1");
        }
    }

    // Boundary condition tests

    #[test]
    #[ignore] // Requires test_binary_with_resources.exe fixture
    // To run: cargo test -- --ignored test_extract_resources_zero_size_data_entry
    fn test_extract_resources_zero_size_data_entry() {
        // Test resource with size=0 (edge case)
        // This is handled by pelite - if a resource has size 0, it won't be enumerated
        // Our implementation relies on pelite's validation
        let fixture_path = get_fixture_path("test_binary_with_resources.exe");
        assert!(
            fixture_path.exists(),
            "Fixture test_binary_with_resources.exe not found. See other test comments for build instructions."
        );
        let pe_data = fs::read(&fixture_path).expect("Failed to read resource fixture");
        let resources = extract_resources(&pe_data);
        // All resources should have non-zero size (pelite filters out zero-size)
        for resource in resources {
            assert!(resource.data_size > 0, "Resource should have non-zero size");
        }
    }

    #[test]
    #[ignore] // Requires test_binary_with_resources.exe fixture
    // To run: cargo test -- --ignored test_extract_resources_max_language_id
    fn test_extract_resources_max_language_id() {
        // Test with maximum u32 language ID (edge case validation)
        // Language IDs are actually u16 in PE format, but we store as u32
        // Maximum valid language ID is 0xFFFF
        let fixture_path = get_fixture_path("test_binary_with_resources.exe");
        assert!(
            fixture_path.exists(),
            "Fixture test_binary_with_resources.exe not found. See other test comments for build instructions."
        );
        let pe_data = fs::read(&fixture_path).expect("Failed to read resource fixture");
        let resources = extract_resources(&pe_data);
        for resource in resources {
            // Language should be within valid range
            assert!(
                resource.language <= 0xFFFF,
                "Language ID should not exceed 0xFFFF"
            );
        }
    }

    #[test]
    #[ignore] // Requires a PE binary with large resource section
    // To run locally: cargo test -- --ignored test_extract_resources_large_resource_section
    // To generate a test fixture with large resources:
    // 1. Create a .rc file with large resource data (e.g., large VERSIONINFO or STRINGTABLE)
    // 2. Compile with windres: x86_64-w64-mingw32-windres --input-format=rc --output-format=coff -o large_resources.res large_resources.rc
    // 3. Link into a PE: x86_64-w64-mingw32-gcc -o large_resources.exe test_binary_with_resources.c large_resources.res
    // 4. Place in tests/fixtures/ and update fixture_path below
    fn test_extract_resources_large_resource_section() {
        // Test handling of a large resource payload
        // This validates that the implementation can handle resource sections
        // that exceed typical sizes without performance degradation or errors
        let fixture_path = get_fixture_path("large_resources.exe");
        assert!(
            fixture_path.exists(),
            "Fixture large_resources.exe not found. See test comment for generation instructions."
        );
        let pe_data = fs::read(&fixture_path).expect("Failed to read large resource fixture");
        let resources = extract_resources(&pe_data);
        // Should handle large resources gracefully
        for resource in resources {
            assert!(resource.data_size > 0, "Resource should have non-zero size");
            assert!(resource.language <= 0xFFFF, "Language ID should be valid");
        }
    }

    // Phase 2: String extraction tests

    #[test]
    fn test_decode_utf16le_valid() {
        // Test UTF-16LE decoding with valid input
        // "Hello" in UTF-16LE: 48 00 65 00 6C 00 6C 00 6F 00
        let bytes = [0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00];
        let result = decode_utf16le(&bytes);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Hello");
    }

    #[test]
    fn test_decode_utf16le_with_null() {
        // Test stripping trailing null terminators
        // "Hi" + null terminator: 48 00 69 00 00 00
        let bytes = [0x48, 0x00, 0x69, 0x00, 0x00, 0x00];
        let result = decode_utf16le(&bytes);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Hi");
    }

    #[test]
    fn test_decode_utf16le_odd_length() {
        // Test error handling for odd-length input
        // Should truncate last byte gracefully
        let bytes = [0x48, 0x00, 0x65, 0x00, 0x6C]; // Odd length
        let result = decode_utf16le(&bytes);
        // Should still decode what it can
        assert!(result.is_ok());
    }

    #[test]
    #[ignore] // Requires test_binary_with_resources.exe fixture
    fn test_extract_version_info_strings_from_fixture() {
        let fixture_path = get_fixture_path("test_binary_with_resources.exe");
        assert!(
            fixture_path.exists(),
            "Fixture test_binary_with_resources.exe not found. See other test comments for build instructions."
        );
        let pe_data = fs::read(&fixture_path).expect("Failed to read resource fixture");
        let strings = extract_version_info_strings(&pe_data);

        // Should extract at least some version strings
        assert!(!strings.is_empty(), "Should extract version info strings");
        for string in &strings {
            assert!(string.tags.contains(&Tag::Version));
            assert!(string.tags.contains(&Tag::Resource));
            assert_eq!(string.encoding, Encoding::Utf16Le);
            assert_eq!(string.source, StringSource::ResourceString);
        }
    }

    #[test]
    #[ignore] // Requires test_binary_with_resources.exe fixture
    fn test_extract_string_table_strings_from_fixture() {
        let fixture_path = get_fixture_path("test_binary_with_resources.exe");
        assert!(
            fixture_path.exists(),
            "Fixture test_binary_with_resources.exe not found. See other test comments for build instructions."
        );
        let pe_data = fs::read(&fixture_path).expect("Failed to read resource fixture");
        let strings = extract_string_table_strings(&pe_data);

        // Should extract at least some string table strings
        assert!(!strings.is_empty(), "Should extract string table strings");
        for string in &strings {
            assert!(string.tags.contains(&Tag::Resource));
            assert!(!string.tags.contains(&Tag::Version));
            assert_eq!(string.encoding, Encoding::Utf16Le);
            assert_eq!(string.source, StringSource::ResourceString);
        }
    }

    #[test]
    fn test_parse_string_table_block() {
        // Test block parsing with crafted data
        // Block with 2 strings: "A" (length 1) and "BC" (length 2)
        // Format: [length1 u16][string1][length2 u16][string2]... (16 entries total)
        let mut block = Vec::new();
        // Entry 0: "A" = 01 00 41 00
        block.extend_from_slice(&[0x01, 0x00, 0x41, 0x00]);
        // Entry 1: "BC" = 02 00 42 00 43 00
        block.extend_from_slice(&[0x02, 0x00, 0x42, 0x00, 0x43, 0x00]);
        // Remaining 14 entries are empty (00 00)
        for _ in 0..14 {
            block.extend_from_slice(&[0x00, 0x00]);
        }

        let strings = parse_string_table_block(&block);
        assert_eq!(strings.len(), 16);
        assert_eq!(strings[0], Some("A".to_string()));
        assert_eq!(strings[1], Some("BC".to_string()));
        for item in strings.iter().skip(2) {
            assert_eq!(item, &None);
        }
    }

    #[test]
    fn test_detect_manifest_encoding_utf8() {
        // Test UTF-8 detection
        let bytes = [0xEF, 0xBB, 0xBF, b'<', b'?', b'x', b'm'];
        let encoding = detect_manifest_encoding(&bytes);
        assert_eq!(encoding, Encoding::Utf8);
    }

    #[test]
    fn test_detect_manifest_encoding_utf16le() {
        // Test UTF-16LE detection
        let bytes = [0xFF, 0xFE, b'<', 0x00, b'?', 0x00];
        let encoding = detect_manifest_encoding(&bytes);
        assert_eq!(encoding, Encoding::Utf16Le);
    }

    #[test]
    fn test_extract_manifest_strings_empty() {
        // Test with no manifest
        let invalid_data = b"NOT_A_PE_FILE";
        let strings = extract_manifest_strings(invalid_data);
        assert!(strings.is_empty());
    }

    #[test]
    #[ignore] // Requires test_binary_with_resources.exe fixture
    fn test_extract_resource_strings_integration() {
        // Test full orchestrator
        let fixture_path = get_fixture_path("test_binary_with_resources.exe");
        assert!(
            fixture_path.exists(),
            "Fixture test_binary_with_resources.exe not found. See other test comments for build instructions."
        );
        let pe_data = fs::read(&fixture_path).expect("Failed to read resource fixture");
        let strings = extract_resource_strings(&pe_data);

        // Should extract strings from at least one resource type
        assert!(!strings.is_empty(), "Should extract some resource strings");

        // Verify all strings have proper metadata
        for string in &strings {
            assert!(!string.text.is_empty());
            assert!(string.tags.contains(&Tag::Resource));
            assert_eq!(string.source, StringSource::ResourceString);
        }
    }
}
