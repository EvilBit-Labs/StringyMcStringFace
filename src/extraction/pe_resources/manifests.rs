//! MANIFEST encoding detection, decoding, and string extraction
//!
//! Extracts RT_MANIFEST resources (type 24) containing application manifests.
//! Performs automatic encoding detection and returns full XML manifest content.

use crate::types::{Encoding, FoundString, StringSource, Tag};
use pelite::PeFile;
use pelite::resources::Name;

use super::{RT_MANIFEST, decode_utf16le};

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
pub fn detect_manifest_encoding(bytes: &[u8]) -> Encoding {
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
fn decode_manifest(bytes: &[u8]) -> crate::types::Result<String> {
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

            // Length is based on decoded string bytes (String::len() returns byte length)
            let length = manifest_text.len() as u32;
            let found_string = FoundString::new(
                manifest_text,
                encoding,
                0, // File offset not easily available from pelite DataEntry
                length,
                StringSource::ResourceString,
            )
            .with_section(".rsrc".to_string())
            .with_tags(vec![Tag::Manifest, Tag::Resource]);
            strings.push(found_string);
        }
    }

    strings
}
