//! Tests for PE resource extraction
//!
//! Split into submodules:
//! - `detection`: Phase 1 tests (resource detection, metadata, boundary conditions)
//! - `extraction`: Phase 2 tests (string extraction, encoding detection)

mod detection;
mod extraction;

use super::*;
use std::fs;
use std::path::Path;

/// Helper to get fixture path
fn get_fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}
