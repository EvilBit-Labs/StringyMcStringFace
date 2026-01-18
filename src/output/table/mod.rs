//! Table output formatter for Stringy.
//!
//! This module provides human-readable table output with automatic TTY detection.
//! When output is directed to a terminal (TTY), strings are displayed in an aligned
//! table with headers showing String, Tags, Score, and Section columns. When output
//! is piped or redirected (non-TTY), only the raw string text is emitted, one per line,
//! for seamless integration with other command-line tools.
//!
//! # TTY Mode Example
//!
//! ```text
//! String                                                       | Tags         | Score | Section
//! -------------------------------------------------------------|--------------|-------|--------
//! https://malware.example.com/beacon                           | url          |   150 | .rdata
//! C:\Windows\System32\cmd.exe                                  | filepath     |   120 | .data
//! GetProcAddress                                               | import       |    80 |
//! ```
//!
//! # Non-TTY Mode Example
//!
//! ```text
//! https://malware.example.com/beacon
//! C:\Windows\System32\cmd.exe
//! GetProcAddress
//! ```
//!
//! # Column Layout
//!
//! - **String**: Up to 60 characters, truncated with `...` if longer
//! - **Tags**: First 2-3 tags, comma-separated, max 20 characters
//! - **Score**: Right-aligned integer score
//! - **Section**: Section name where the string was found

mod formatting;
mod plain;
mod tty;

use std::io::IsTerminal;

use crate::types::{FoundString, Result};

use super::OutputMetadata;

// Re-export public items from submodules
pub use formatting::{Alignment, format_tags, pad_string, truncate_string};

/// Maximum width for the string column before truncation.
pub(crate) const STRING_COLUMN_WIDTH: usize = 60;

/// Maximum width for the tags column.
pub(crate) const TAGS_COLUMN_WIDTH: usize = 20;

/// Maximum width for the score column.
pub(crate) const SCORE_COLUMN_WIDTH: usize = 6;

/// Maximum width for the section column.
pub(crate) const SECTION_COLUMN_WIDTH: usize = 15;

/// Format strings in a human-readable table format.
///
/// Automatically detects whether output is going to a TTY (terminal) and adjusts
/// the format accordingly. In TTY mode, outputs an aligned table with headers.
/// In non-TTY mode (piped/redirected), outputs plain strings one per line.
///
/// # Arguments
///
/// * `strings` - The extracted strings to format
/// * `metadata` - Output context (currently unused but reserved for future features)
///
/// # Returns
///
/// A formatted string ready for output.
pub fn format_table(strings: &[FoundString], metadata: &OutputMetadata) -> Result<String> {
    let is_tty = std::io::stdout().is_terminal();
    format_table_with_mode(strings, metadata, is_tty)
}

/// Format table with explicit TTY mode specification.
///
/// This function allows explicit control over the output mode, useful for testing
/// and programmatic control over output format.
///
/// # Arguments
///
/// * `strings` - The extracted strings to format
/// * `metadata` - Output context
/// * `is_tty` - Whether to use TTY mode (true) or plain mode (false)
pub fn format_table_with_mode(
    strings: &[FoundString],
    metadata: &OutputMetadata,
    is_tty: bool,
) -> Result<String> {
    if is_tty {
        tty::format_table_tty(strings, metadata)
    } else {
        plain::format_table_plain(strings)
    }
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use crate::output::OutputFormat;
    use crate::types::{Encoding, FoundString, StringSource};

    use super::OutputMetadata;

    pub fn make_test_string(text: &str) -> FoundString {
        FoundString::new(
            text.to_string(),
            Encoding::Ascii,
            0x1000,
            text.len() as u32,
            StringSource::SectionData,
        )
    }

    pub fn make_metadata() -> OutputMetadata {
        OutputMetadata::new("test.bin".to_string(), OutputFormat::Table, 10, 10)
    }
}
