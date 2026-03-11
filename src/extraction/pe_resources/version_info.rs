//! VERSIONINFO string extraction
//!
//! Uses pelite's high-level `version_info()` API to extract all StringFileInfo
//! key-value pairs from PE VERSIONINFO resources.

use crate::types::{Encoding, FoundString, StringSource, Tag};
use pelite::PeFile;

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
            // Source encoding is UTF-16LE: 2 bytes per code unit
            let length = (text.encode_utf16().count() * 2) as u32;
            let found_string = FoundString::new(
                text,
                Encoding::Utf16Le,
                0, // pelite doesn't provide offsets easily
                length,
                StringSource::ResourceString,
            )
            .with_section(".rsrc".to_string())
            .with_tags(vec![Tag::Version, Tag::Resource]);
            strings.push(found_string);
        });
    }

    strings
}
