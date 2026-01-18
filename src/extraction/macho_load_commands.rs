//! Mach-O Load Command String Extraction Module
//!
//! This module provides functionality for extracting load command strings from Mach-O binaries
//! using the goblin library. It extracts library dependency paths (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB,
//! LC_REEXPORT_DYLIB) and runtime search paths (LC_RPATH) from Mach-O load commands.
//!
//! # Examples
//!
//! ```rust,no_run
//! use std::error::Error;
//! use stringy::extraction::macho_load_commands::extract_load_command_strings;
//! use stringy::types::{Tag, StringSource};
//!
//! fn main() -> Result<(), Box<dyn Error>> {
//!     let macho_data = std::fs::read("example.dylib")?;
//!     let strings = extract_load_command_strings(&macho_data);
//!
//!     // Filter dylib paths
//!     let dylib_paths: Vec<_> = strings.iter()
//!         .filter(|s| s.tags.contains(&Tag::DylibPath))
//!         .collect();
//!
//!     // Filter rpaths
//!     let rpaths: Vec<_> = strings.iter()
//!         .filter(|s| s.tags.contains(&Tag::Rpath))
//!         .collect();
//!
//!     // Filter framework paths
//!     let framework_paths: Vec<_> = strings.iter()
//!         .filter(|s| s.tags.contains(&Tag::FrameworkPath))
//!         .collect();
//!     Ok(())
//! }
//! ```

use crate::types::{Encoding, FoundString, StringSource, Tag};
use goblin::Object;
use goblin::mach::{Mach, MachO};

/// Extract load command strings from a Mach-O binary
///
/// This function parses the Mach-O binary using goblin and extracts library dependency
/// paths and runtime search paths from load commands. It handles both single architecture
/// binaries and universal (fat) binaries by extracting from the first architecture.
///
/// # Arguments
///
/// * `data` - Raw Mach-O binary data
///
/// # Returns
///
/// Vector of FoundString entries with load command strings
pub fn extract_load_command_strings(data: &[u8]) -> Vec<FoundString> {
    // Parse the Mach-O binary
    let mach = match Object::parse(data) {
        Ok(Object::Mach(mach)) => mach,
        _ => return Vec::new(),
    };

    // Handle both single binaries and fat binaries
    match mach {
        Mach::Binary(macho) => extract_from_single_macho(&macho),
        Mach::Fat(fat) => {
            // For fat binaries, extract from first architecture (consistent with parser behavior)
            if let Some(Ok(arch)) = fat.iter_arches().next()
                && let Ok(arch_data) = extract_architecture_data(&arch, data)
                && let Ok(Object::Mach(Mach::Binary(macho))) = Object::parse(arch_data)
            {
                return extract_from_single_macho(&macho);
            }
            Vec::new()
        }
    }
}

/// Extract load command strings from a single Mach-O binary
fn extract_from_single_macho(macho: &MachO) -> Vec<FoundString> {
    let mut strings = Vec::new();

    // Extract dylib strings
    strings.extend(extract_dylib_strings(macho));

    // Extract rpath strings
    strings.extend(extract_rpath_strings(macho));

    strings
}

/// Extract dylib path strings from macho.libs
///
/// Processes library paths from LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, and LC_REEXPORT_DYLIB
/// load commands. Each path is tagged with DylibPath and FilePath, and FrameworkPath
/// if it contains .framework.
fn extract_dylib_strings(macho: &MachO) -> Vec<FoundString> {
    let mut strings = Vec::new();

    for lib in &macho.libs {
        let tags = classify_dylib_path(lib);
        let length = lib.len() as u32;

        strings.push(FoundString {
            text: lib.to_string(),
            original_text: None,
            encoding: Encoding::Utf8,
            source: StringSource::LoadCommand,
            tags,
            section: None,
            offset: 0,
            rva: None,
            length,
            score: 0,
            section_weight: None,
            semantic_boost: None,
            noise_penalty: None,
            confidence: 1.0,
        });
    }

    strings
}

/// Extract rpath strings from macho.rpaths
///
/// Processes runtime search paths from LC_RPATH load commands. Each path is tagged
/// with Rpath, and RpathVariable if it contains @-variables, and FrameworkPath
/// if it contains .framework.
fn extract_rpath_strings(macho: &MachO) -> Vec<FoundString> {
    let mut strings = Vec::new();

    for rpath in &macho.rpaths {
        let tags = classify_rpath(rpath);
        let length = rpath.len() as u32;

        strings.push(FoundString {
            text: rpath.to_string(),
            original_text: None,
            encoding: Encoding::Utf8,
            source: StringSource::LoadCommand,
            tags,
            section: None,
            offset: 0,
            rva: None,
            length,
            score: 0,
            section_weight: None,
            semantic_boost: None,
            noise_penalty: None,
            confidence: 1.0,
        });
    }

    strings
}

/// Classify a dylib path and return appropriate tags
///
/// Always includes DylibPath and FilePath tags. Adds FrameworkPath if the path
/// contains .framework.
fn classify_dylib_path(path: &str) -> Vec<Tag> {
    let mut tags = vec![Tag::DylibPath, Tag::FilePath];

    if is_framework_path(path) {
        tags.push(Tag::FrameworkPath);
    }

    tags
}

/// Classify an rpath and return appropriate tags
///
/// Always includes Rpath tag. Adds RpathVariable if the path contains @-variables,
/// and FrameworkPath if it contains .framework.
fn classify_rpath(path: &str) -> Vec<Tag> {
    let mut tags = vec![Tag::Rpath];

    if contains_rpath_variable(path) {
        tags.push(Tag::RpathVariable);
    }

    if is_framework_path(path) {
        tags.push(Tag::FrameworkPath);
    }

    tags
}

/// Check if a path contains .framework (indicating a framework path)
fn is_framework_path(path: &str) -> bool {
    path.contains(".framework")
}

/// Check if a path contains @rpath, @executable_path, or @loader_path variables
fn contains_rpath_variable(path: &str) -> bool {
    path.contains("@rpath") || path.contains("@executable_path") || path.contains("@loader_path")
}

/// Extract architecture-specific data from a fat binary
fn extract_architecture_data<'a>(
    arch: &goblin::mach::fat::FatArch,
    data: &'a [u8],
) -> Result<&'a [u8], ()> {
    let offset = arch.offset as usize;
    let size = arch.size as usize;

    if let Some(end) = offset.checked_add(size) {
        if end <= data.len() {
            Ok(&data[offset..end])
        } else {
            Err(())
        }
    } else {
        Err(())
    }
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

    #[test]
    fn test_extract_load_command_strings_invalid_data() {
        // Test with invalid data - should return empty vec, not panic
        let invalid_data = b"NOT_A_MACHO_FILE";
        let result = extract_load_command_strings(invalid_data);
        assert!(result.is_empty(), "Invalid data should return empty vector");
    }

    #[test]
    fn test_extract_load_command_strings_empty_data() {
        // Test with empty byte slice - should return empty vec gracefully
        let empty_data = b"";
        let result = extract_load_command_strings(empty_data);
        assert!(result.is_empty(), "Empty data should return empty vector");
    }

    #[test]
    fn test_is_framework_path() {
        // Test framework path detection
        assert!(is_framework_path(
            "/System/Library/Frameworks/Foundation.framework/Foundation"
        ));
        assert!(is_framework_path(
            "@rpath/MyFramework.framework/MyFramework"
        ));
        assert!(!is_framework_path("/usr/lib/libSystem.B.dylib"));
        assert!(!is_framework_path("@rpath/libMyLib.dylib"));
    }

    #[test]
    fn test_contains_rpath_variable() {
        // Test rpath variable detection
        assert!(contains_rpath_variable("@rpath/libMyLib.dylib"));
        assert!(contains_rpath_variable(
            "@executable_path/../Frameworks/MyLib.dylib"
        ));
        assert!(contains_rpath_variable("@loader_path/libMyLib.dylib"));
        assert!(!contains_rpath_variable("/usr/lib/libSystem.B.dylib"));
        assert!(!contains_rpath_variable(
            "/System/Library/Frameworks/Foundation.framework/Foundation"
        ));
    }

    #[test]
    fn test_classify_dylib_path() {
        // Test dylib path classification
        let system_lib = classify_dylib_path("/usr/lib/libSystem.B.dylib");
        assert!(system_lib.contains(&Tag::DylibPath));
        assert!(system_lib.contains(&Tag::FilePath));
        assert!(!system_lib.contains(&Tag::FrameworkPath));

        let framework =
            classify_dylib_path("/System/Library/Frameworks/Foundation.framework/Foundation");
        assert!(framework.contains(&Tag::DylibPath));
        assert!(framework.contains(&Tag::FilePath));
        assert!(framework.contains(&Tag::FrameworkPath));
    }

    #[test]
    fn test_classify_rpath() {
        // Test rpath classification
        let simple_rpath = classify_rpath("/usr/local/lib");
        assert!(simple_rpath.contains(&Tag::Rpath));
        assert!(!simple_rpath.contains(&Tag::RpathVariable));
        assert!(!simple_rpath.contains(&Tag::FrameworkPath));

        let rpath_with_var = classify_rpath("@rpath/libMyLib.dylib");
        assert!(rpath_with_var.contains(&Tag::Rpath));
        assert!(rpath_with_var.contains(&Tag::RpathVariable));
        assert!(!rpath_with_var.contains(&Tag::FrameworkPath));

        let framework_rpath = classify_rpath("@rpath/MyFramework.framework/MyFramework");
        assert!(framework_rpath.contains(&Tag::Rpath));
        assert!(framework_rpath.contains(&Tag::RpathVariable));
        assert!(framework_rpath.contains(&Tag::FrameworkPath));
    }

    #[test]
    #[ignore] // Requires test_binary_macho fixture
    fn test_extract_load_command_strings_from_fixture() {
        // Test with actual Mach-O fixture
        let fixture_path = get_fixture_path("test_binary_macho");
        if !fixture_path.exists() {
            return; // Skip if fixture doesn't exist
        }

        let macho_data = fs::read(&fixture_path).expect("Failed to read Mach-O fixture");
        let strings = extract_load_command_strings(&macho_data);

        // Verify all extracted strings have correct source and encoding
        for string in &strings {
            assert_eq!(string.source, StringSource::LoadCommand);
            assert_eq!(string.encoding, Encoding::Utf8);
            assert!(!string.text.is_empty());
        }

        // Check for expected tags
        let has_dylib = strings.iter().any(|s| s.tags.contains(&Tag::DylibPath));
        let has_rpath = strings.iter().any(|s| s.tags.contains(&Tag::Rpath));

        // At least one type should be present in a typical Mach-O binary
        println!("Extracted {} load command strings", strings.len());
        println!("Has dylib paths: {}, Has rpaths: {}", has_dylib, has_rpath);
    }

    #[test]
    #[ignore] // Requires test_binary_macho fixture
    fn test_extract_load_command_strings_tag_validation() {
        // Test tag validation with real fixture
        let fixture_path = get_fixture_path("test_binary_macho");
        if !fixture_path.exists() {
            return; // Skip if fixture doesn't exist
        }

        let macho_data = fs::read(&fixture_path).expect("Failed to read Mach-O fixture");
        let strings = extract_load_command_strings(&macho_data);

        for string in &strings {
            // All strings should have at least one tag
            assert!(
                !string.tags.is_empty(),
                "String should have at least one tag"
            );

            // Verify tag combinations are valid
            if string.tags.contains(&Tag::DylibPath) {
                assert!(
                    string.tags.contains(&Tag::FilePath),
                    "DylibPath should also have FilePath"
                );
            }

            if string.tags.contains(&Tag::FrameworkPath) {
                // Framework paths should be either dylib paths or rpaths
                assert!(
                    string.tags.contains(&Tag::DylibPath) || string.tags.contains(&Tag::Rpath),
                    "FrameworkPath should be associated with DylibPath or Rpath"
                );
            }

            if string.tags.contains(&Tag::RpathVariable) {
                assert!(
                    string.tags.contains(&Tag::Rpath),
                    "RpathVariable should also have Rpath"
                );
            }
        }
    }
}
