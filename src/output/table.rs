use crate::types::{FoundString, Result};

use super::OutputMetadata;

/// Format strings in a human-readable table format.
pub fn format_table(_strings: &[FoundString], _metadata: &OutputMetadata) -> Result<String> {
    // TODO: Implement table formatter in a subsequent phase.
    Ok(String::new())
}
