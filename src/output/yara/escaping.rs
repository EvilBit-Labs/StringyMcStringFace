//! YARA string escaping and encoding utilities.
//!
//! Provides functions for escaping strings and encoding them to hex formats
//! suitable for YARA rule strings.

/// Escape a string for use in YARA string literals (ASCII/UTF-8).
///
/// Handles control characters, backslashes, quotes, and non-printable bytes.
pub fn escape_yara_string(text: &str) -> String {
    let mut escaped = String::new();
    for byte in text.as_bytes() {
        match *byte {
            b'\\' => escaped.push_str("\\\\"),
            b'"' => escaped.push_str("\\\""),
            b'\n' => escaped.push_str("\\n"),
            b'\r' => escaped.push_str("\\r"),
            b'\t' => escaped.push_str("\\t"),
            0x08 => escaped.push_str("\\b"),
            0x0b => escaped.push_str("\\x0b"),
            0x0c => escaped.push_str("\\x0c"),
            0x00..=0x1f | 0x7f..=0xff => {
                escaped.push_str(&format!("\\x{:02x}", byte));
            }
            _ => escaped.push(*byte as char),
        }
    }
    escaped
}

/// Escape a Unicode string for use with YARA's `wide` modifier.
///
/// This preserves non-control Unicode characters while escaping control characters
/// and special YARA syntax characters.
pub fn escape_yara_unicode_literal(text: &str) -> String {
    let mut escaped = String::new();
    for ch in text.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            _ if ch.is_control() => {
                let mut buf = [0; 4];
                let encoded = ch.encode_utf8(&mut buf);
                for byte in encoded.as_bytes() {
                    escaped.push_str(&format!("\\x{:02x}", byte));
                }
            }
            _ => escaped.push(ch),
        }
    }
    escaped
}

/// Convert a string to UTF-16 big-endian hex format for YARA.
///
/// Returns a hex string like `{ 00 41 00 42 }` for "AB".
pub fn utf16be_hex_string(text: &str) -> String {
    let hex_bytes: Vec<String> = text
        .encode_utf16()
        .flat_map(|unit| unit.to_be_bytes())
        .map(|b| format!("{:02x}", b))
        .collect();

    if hex_bytes.is_empty() {
        return "{ }".to_string();
    }

    format!("{{ {} }}", hex_bytes.join(" "))
}

/// Convert a string to UTF-16 little-endian hex format for YARA.
///
/// Returns a hex string like `{ 41 00 42 00 }` for "AB".
pub fn utf16le_hex_string(text: &str) -> String {
    let hex_bytes: Vec<String> = text
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .map(|b| format!("{:02x}", b))
        .collect();

    if hex_bytes.is_empty() {
        return "{ }".to_string();
    }

    format!("{{ {} }}", hex_bytes.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    mod escape_yara_string_tests {
        use super::*;

        #[test]
        fn basic_escapes() {
            let input = "quote\" backslash\\ line\n tab\t";
            let escaped = escape_yara_string(input);
            assert!(escaped.contains("\\\""));
            assert!(escaped.contains("\\\\"));
            assert!(escaped.contains("\\n"));
            assert!(escaped.contains("\\t"));
        }

        #[test]
        fn control_characters() {
            assert_eq!(escape_yara_string("\r"), "\\r");
            assert_eq!(escape_yara_string("\x00"), "\\x00");
            assert_eq!(escape_yara_string("\x08"), "\\b");
            assert_eq!(escape_yara_string("\x0b"), "\\x0b");
            assert_eq!(escape_yara_string("\x0c"), "\\x0c");
            assert_eq!(escape_yara_string("\x7f"), "\\x7f");
        }
    }

    mod escape_yara_unicode_literal_tests {
        use super::*;

        #[test]
        fn basic_escapes() {
            assert_eq!(escape_yara_unicode_literal("quote\""), "quote\\\"");
            assert_eq!(escape_yara_unicode_literal("back\\slash"), "back\\\\slash");
            assert_eq!(escape_yara_unicode_literal("line\nbreak"), "line\\nbreak");
            assert_eq!(escape_yara_unicode_literal("tab\there"), "tab\\there");
            assert_eq!(escape_yara_unicode_literal("return\rhere"), "return\\rhere");
        }

        #[test]
        fn control_chars_hex_escaped() {
            assert_eq!(escape_yara_unicode_literal("\x00"), "\\x00");
            assert_eq!(escape_yara_unicode_literal("\x1f"), "\\x1f");
        }

        #[test]
        fn unicode_passthrough() {
            let result = escape_yara_unicode_literal("\u{4E2D}\u{6587}");
            assert!(
                result.contains('\u{4E2D}'),
                "Non-control Unicode should not be escaped"
            );
        }

        #[test]
        fn empty_string() {
            assert_eq!(escape_yara_unicode_literal(""), "");
        }
    }

    mod utf16be_hex_string_tests {
        use super::*;

        #[test]
        fn basic_ascii() {
            assert_eq!(utf16be_hex_string("A"), "{ 00 41 }");
            assert_eq!(utf16be_hex_string("AB"), "{ 00 41 00 42 }");
        }

        #[test]
        fn empty_string() {
            assert_eq!(utf16be_hex_string(""), "{ }");
        }

        #[test]
        fn non_ascii_unicode() {
            let chinese = utf16be_hex_string("\u{4E2D}");
            assert_eq!(chinese, "{ 4e 2d }");
        }

        #[test]
        fn surrogate_pair() {
            let emoji = utf16be_hex_string("\u{1F600}");
            assert_eq!(emoji, "{ d8 3d de 00 }");
        }
    }

    mod utf16le_hex_string_tests {
        use super::*;

        #[test]
        fn basic_ascii() {
            assert_eq!(utf16le_hex_string("A"), "{ 41 00 }");
            assert_eq!(utf16le_hex_string("AB"), "{ 41 00 42 00 }");
        }

        #[test]
        fn empty_string() {
            assert_eq!(utf16le_hex_string(""), "{ }");
        }

        #[test]
        fn non_ascii_unicode() {
            let chinese = utf16le_hex_string("\u{4E2D}");
            assert_eq!(chinese, "{ 2d 4e }");
        }

        #[test]
        fn surrogate_pair() {
            let emoji = utf16le_hex_string("\u{1F600}");
            assert_eq!(emoji, "{ 3d d8 00 de }");
        }
    }
}
