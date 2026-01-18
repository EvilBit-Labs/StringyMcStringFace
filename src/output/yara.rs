use crate::types::{FoundString, Result};

use super::OutputMetadata;

/// Format strings as YARA rule templates.
pub fn format_yara(_strings: &[FoundString], _metadata: &OutputMetadata) -> Result<String> {
    // TODO: Implement YARA formatter in a subsequent phase.
    Ok(String::new())
}
