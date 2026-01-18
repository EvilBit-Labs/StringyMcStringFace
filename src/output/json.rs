use crate::types::{FoundString, Result};

use super::OutputMetadata;

/// Format strings as JSONL output, one object per line.
pub fn format_json(_strings: &[FoundString], _metadata: &OutputMetadata) -> Result<String> {
    // TODO: Implement JSON formatter in a subsequent phase.
    Ok(String::new())
}
