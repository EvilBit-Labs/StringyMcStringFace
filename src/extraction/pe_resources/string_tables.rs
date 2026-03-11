//! STRINGTABLE parsing and extraction
//!
//! Parses RT_STRING resources (type 6) containing localized UI strings.
//! Handles block structure: strings grouped in blocks of 16.

use crate::types::{Encoding, FoundString, StringSource, Tag};
use pelite::PeFile;
use pelite::resources::Name;

use super::{RT_STRING, decode_utf16le};

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
            // Not enough data for string -- stop parsing to avoid misaligned reads
            strings.push(None);
            break;
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

            // Parse the block
            let parsed_strings = parse_string_table_block(block_bytes);

            // Create FoundString for each non-empty string
            for text in parsed_strings.into_iter().flatten() {
                // String ID calculation: ((block_id - 1) << 4) | index
                // (stored for potential future use but not currently needed)
                // Source encoding is UTF-16LE: 2 bytes per code unit
                let text_len = (text.encode_utf16().count() * 2) as u32;

                let found_string = FoundString::new(
                    text,
                    Encoding::Utf16Le,
                    0, // File offset not easily available from pelite DataEntry
                    text_len,
                    StringSource::ResourceString,
                )
                .with_section(".rsrc".to_string())
                .with_tags(vec![Tag::Resource]);
                strings.push(found_string);
            }
        }
    }

    strings
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_parse_string_table_block_truncated_entry() {
        // When an entry claims more bytes than remain, parsing should stop
        // to avoid misaligned reads on subsequent entries
        let mut block = Vec::new();
        // Entry 0: "A" = 01 00 41 00
        block.extend_from_slice(&[0x01, 0x00, 0x41, 0x00]);
        // Entry 1: claims length 100 (far exceeds remaining buffer)
        block.extend_from_slice(&[0x64, 0x00]);
        // Only 2 bytes of "data" follow (not enough for 100 code units)
        block.extend_from_slice(&[0x42, 0x00]);

        let strings = parse_string_table_block(&block);
        // Entry 0 should parse successfully
        assert_eq!(strings[0], Some("A".to_string()));
        // Entry 1 should be None (truncated)
        assert_eq!(strings[1], None);
        // Should have exactly 2 entries (break after truncation)
        assert_eq!(strings.len(), 2);
    }
}
