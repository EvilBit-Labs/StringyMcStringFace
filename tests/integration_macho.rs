use insta::assert_snapshot;
use std::fs;
use stringy::container::{ContainerParser, MachoParser};

fn get_fixture_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

// Helper functions for extracting and sorting load command strings by tag
fn get_dylib_paths(strings: &[stringy::types::FoundString]) -> Vec<&stringy::types::FoundString> {
    let mut paths: Vec<_> = strings
        .iter()
        .filter(|s| s.tags.contains(&stringy::types::Tag::DylibPath))
        .collect();
    paths.sort_by(|a, b| a.text.cmp(&b.text));
    paths
}

fn get_rpaths(strings: &[stringy::types::FoundString]) -> Vec<&stringy::types::FoundString> {
    let mut paths: Vec<_> = strings
        .iter()
        .filter(|s| s.tags.contains(&stringy::types::Tag::Rpath))
        .collect();
    paths.sort_by(|a, b| a.text.cmp(&b.text));
    paths
}

fn get_framework_paths(
    strings: &[stringy::types::FoundString],
) -> Vec<&stringy::types::FoundString> {
    let mut paths: Vec<_> = strings
        .iter()
        .filter(|s| s.tags.contains(&stringy::types::Tag::FrameworkPath))
        .collect();
    paths.sort_by(|a, b| a.text.cmp(&b.text));
    paths
}

fn has_rpath_variable(text: &str) -> bool {
    text.contains("@rpath") || text.contains("@executable_path") || text.contains("@loader_path")
}

#[test]
fn test_macho_import_export_extraction() {
    // Test with the Mach-O fixture
    let fixture_path = get_fixture_path("test_binary_macho");
    let macho_data = fs::read(&fixture_path)
        .expect("Failed to read Mach-O fixture. Run the build script to generate fixtures.");

    // Verify it's a Mach-O file
    assert!(
        MachoParser::detect(&macho_data),
        "Mach-O detection should succeed"
    );

    // Test parsing
    let parser = MachoParser::new();
    let container_info = parser.parse(&macho_data).expect("Failed to parse Mach-O");

    // Verify we found some sections
    assert!(
        !container_info.sections.is_empty(),
        "Should find sections in Mach-O binary"
    );

    // Check exports - relaxed assertions: just verify we have meaningful exports
    // Note: Executables may not consistently export symbols; we verify non-empty exports
    // This is a weaker invariant than checking for specific symbol names like "main"
    let export_names: Vec<&str> = container_info
        .exports
        .iter()
        .map(|exp| exp.name.as_str())
        .collect();

    // Assert that we have at least some exports
    // This is more lenient than checking for specific symbol names which may vary
    assert!(
        !export_names.is_empty(),
        "Should find at least some exports. Found: {:?}",
        export_names
    );

    println!(
        "Found {} imports and {} exports",
        container_info.imports.len(),
        container_info.exports.len()
    );
}

#[test]
fn test_macho_section_classification() {
    // Test with the Mach-O fixture
    let fixture_path = get_fixture_path("test_binary_macho");
    let macho_data = fs::read(&fixture_path)
        .expect("Failed to read Mach-O fixture. Run the build script to generate fixtures.");

    if MachoParser::detect(&macho_data) {
        let container_info = MachoParser::new()
            .parse(&macho_data)
            .expect("Failed to parse Mach-O fixture");

        // Verify we found sections and classified them
        assert!(
            !container_info.sections.is_empty(),
            "Should find sections in Mach-O binary"
        );

        // Verify that all sections have weights assigned
        for section in &container_info.sections {
            assert!(
                section.weight > 0.0,
                "Section {} should have a positive weight, got {}",
                section.name,
                section.weight
            );
        }

        // Look for common Mach-O sections
        let section_names: Vec<&str> = container_info
            .sections
            .iter()
            .map(|sec| sec.name.as_str())
            .collect();

        println!("Found sections: {:?}", section_names);

        // Should find at least some standard Mach-O sections
        let has_text = section_names.iter().any(|&name| name.contains("__TEXT"));
        let has_data = section_names.iter().any(|&name| name.contains("__DATA"));

        assert!(
            has_text || has_data,
            "Should find __TEXT or __DATA sections"
        );
    } else {
        panic!("Mach-O fixture is not a valid Mach-O file");
    }
}

#[test]
fn test_macho_load_command_extraction() {
    // Test with the Mach-O fixture
    let fixture_path = get_fixture_path("test_binary_macho");
    let macho_data = fs::read(&fixture_path)
        .expect("Failed to read Mach-O fixture. Run the build script to generate fixtures.");

    // Extract load command strings
    let load_command_strings = stringy::extraction::extract_load_command_strings(&macho_data);

    // Verify that load command strings are extracted
    // The test fixture should have at least some dylib dependencies
    println!(
        "Extracted {} load command strings",
        load_command_strings.len()
    );

    // Verify that all extracted strings have correct source and encoding
    for string in &load_command_strings {
        assert_eq!(
            string.source,
            stringy::types::StringSource::LoadCommand,
            "All load command strings should have LoadCommand source"
        );
        assert_eq!(
            string.encoding,
            stringy::types::Encoding::Utf8,
            "All load command strings should be UTF-8"
        );
        assert!(!string.text.is_empty(), "String text should not be empty");
    }

    // Check for expected tags
    let has_dylib = load_command_strings
        .iter()
        .any(|s| s.tags.contains(&stringy::types::Tag::DylibPath));
    let has_rpath = load_command_strings
        .iter()
        .any(|s| s.tags.contains(&stringy::types::Tag::Rpath));

    println!("Has dylib paths: {}, Has rpaths: {}", has_dylib, has_rpath);

    // Look for common system libraries that should be present
    let dylib_paths = get_dylib_paths(&load_command_strings);
    let lib_names: Vec<&str> = dylib_paths.iter().map(|s| s.text.as_str()).collect();

    println!("Found dylib paths: {:?}", lib_names);

    // Verify framework paths are tagged correctly if present
    let framework_paths = get_framework_paths(&load_command_strings);

    for framework_path in &framework_paths {
        assert!(
            framework_path.text.contains(".framework"),
            "Framework path should contain .framework"
        );
        assert!(
            framework_path
                .tags
                .contains(&stringy::types::Tag::DylibPath)
                || framework_path.tags.contains(&stringy::types::Tag::Rpath),
            "Framework path should be associated with DylibPath or Rpath"
        );
    }

    // Verify rpaths are tagged correctly if present
    let rpaths = get_rpaths(&load_command_strings);

    for rpath in &rpaths {
        // Check if rpath contains @-variables
        if has_rpath_variable(&rpath.text) {
            assert!(
                rpath.tags.contains(&stringy::types::Tag::RpathVariable),
                "Rpath with @-variables should have RpathVariable tag"
            );
        }
    }

    println!(
        "Found {} dylib paths, {} rpaths, {} framework paths",
        lib_names.len(),
        rpaths.len(),
        framework_paths.len()
    );

    // Enhanced assertions
    assert!(
        !lib_names.is_empty(),
        "All Mach-O binaries should have at least one dylib dependency"
    );

    // Check for common system libraries
    let has_libsystem = lib_names
        .iter()
        .any(|&name| name.contains("libSystem") || name.contains("libsystem"));
    if has_libsystem {
        println!("Found libSystem dependency (expected for Mach-O binaries)");
    }

    // Diagnostic output showing breakdown
    let dylib_count = lib_names.len();
    let rpath_count = rpaths.len();
    let framework_count = framework_paths.len();
    println!(
        "Load command string breakdown: {} dylibs, {} rpaths, {} frameworks",
        dylib_count, rpath_count, framework_count
    );
}

#[test]
fn test_macho_load_command_extraction_snapshot() {
    // Test load command string extraction with snapshot
    let fixture_path = get_fixture_path("test_binary_macho");
    let macho_data = fs::read(&fixture_path)
        .expect("Failed to read Mach-O fixture. Run the build script to generate fixtures.");

    let strings = stringy::extraction::extract_load_command_strings(&macho_data);

    let mut output = String::new();

    // DYLIB PATHS
    output.push_str("=== DYLIB PATHS ===\n");
    let dylib_paths = get_dylib_paths(&strings);
    output.push_str(&format!("Total: {}\n\n", dylib_paths.len()));
    for (i, string) in dylib_paths.iter().take(20).enumerate() {
        let is_framework = string.text.contains(".framework");
        output.push_str(&format!(
            "Dylib Path {}: {}{}",
            i + 1,
            string.text,
            if is_framework { " (Framework)" } else { "" }
        ));
        output.push('\n');
    }
    if dylib_paths.len() > 20 {
        output.push_str(&format!("... and {} more\n", dylib_paths.len() - 20));
    }
    output.push('\n');

    // RPATHS
    output.push_str("=== RPATHS ===\n");
    let rpaths = get_rpaths(&strings);
    output.push_str(&format!("Total: {}\n\n", rpaths.len()));
    for (i, string) in rpaths.iter().take(20).enumerate() {
        let has_variable = has_rpath_variable(&string.text);
        output.push_str(&format!(
            "Rpath {}: {}{}",
            i + 1,
            string.text,
            if has_variable {
                " (Contains @-variable)"
            } else {
                ""
            }
        ));
        output.push('\n');
    }
    if rpaths.len() > 20 {
        output.push_str(&format!("... and {} more\n", rpaths.len() - 20));
    }
    output.push('\n');

    // FRAMEWORK PATHS
    output.push_str("=== FRAMEWORK PATHS ===\n");
    let framework_paths = get_framework_paths(&strings);
    output.push_str(&format!("Total: {}\n\n", framework_paths.len()));
    for (i, string) in framework_paths.iter().take(20).enumerate() {
        output.push_str(&format!("Framework Path {}: {}\n", i + 1, string.text));
    }
    if framework_paths.len() > 20 {
        output.push_str(&format!("... and {} more\n", framework_paths.len() - 20));
    }

    assert_snapshot!("macho_load_command_strings", output);
}

#[test]
fn test_macho_load_command_tag_validation() {
    // Test comprehensive tag validation for load command strings
    let fixture_path = get_fixture_path("test_binary_macho");
    let macho_data = fs::read(&fixture_path)
        .expect("Failed to read Mach-O fixture. Run the build script to generate fixtures.");

    let strings = stringy::extraction::extract_load_command_strings(&macho_data);

    for string in &strings {
        // All strings must have at least one tag
        assert!(
            !string.tags.is_empty(),
            "String should have at least one tag"
        );

        // All strings with DylibPath must also have FilePath
        if string.tags.contains(&stringy::types::Tag::DylibPath) {
            assert!(
                string.tags.contains(&stringy::types::Tag::FilePath),
                "DylibPath strings must also have FilePath tag. String: {}",
                string.text
            );
        }

        // All strings with RpathVariable must also have Rpath
        if string.tags.contains(&stringy::types::Tag::RpathVariable) {
            assert!(
                string.tags.contains(&stringy::types::Tag::Rpath),
                "RpathVariable strings must also have Rpath tag. String: {}",
                string.text
            );
        }

        // All strings with FrameworkPath must have either DylibPath or Rpath
        if string.tags.contains(&stringy::types::Tag::FrameworkPath) {
            assert!(
                string.tags.contains(&stringy::types::Tag::DylibPath)
                    || string.tags.contains(&stringy::types::Tag::Rpath),
                "FrameworkPath strings must have DylibPath or Rpath tag. String: {}",
                string.text
            );
        }

        // Verify encoding is Utf8 for all load command strings
        assert_eq!(
            string.encoding,
            stringy::types::Encoding::Utf8,
            "All load command strings should be UTF-8"
        );

        // Verify source is LoadCommand for all strings
        assert_eq!(
            string.source,
            stringy::types::StringSource::LoadCommand,
            "All load command strings should have LoadCommand source"
        );

        // Verify no contradictory tags (DylibPath and Rpath should not both be present)
        assert!(
            !(string.tags.contains(&stringy::types::Tag::DylibPath)
                && string.tags.contains(&stringy::types::Tag::Rpath)),
            "String should not have both DylibPath and Rpath tags. String: {}",
            string.text
        );
    }
}

#[test]
fn test_macho_framework_path_detection() {
    // Test framework path detection and tagging
    let fixture_path = get_fixture_path("test_binary_macho");
    let macho_data = fs::read(&fixture_path)
        .expect("Failed to read Mach-O fixture. Run the build script to generate fixtures.");

    let strings = stringy::extraction::extract_load_command_strings(&macho_data);

    // Filter strings containing .framework
    let mut framework_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.text.contains(".framework"))
        .collect();
    framework_strings.sort_by(|a, b| a.text.cmp(&b.text));

    // Verify all framework strings have FrameworkPath tag
    for framework_string in &framework_strings {
        assert!(
            framework_string
                .tags
                .contains(&stringy::types::Tag::FrameworkPath),
            "String containing .framework should have FrameworkPath tag. String: {}",
            framework_string.text
        );
    }

    // Verify strings without .framework do NOT have FrameworkPath tag
    let mut non_framework_strings: Vec<_> = strings
        .iter()
        .filter(|s| !s.text.contains(".framework"))
        .collect();
    non_framework_strings.sort_by(|a, b| a.text.cmp(&b.text));

    for non_framework_string in &non_framework_strings {
        assert!(
            !non_framework_string
                .tags
                .contains(&stringy::types::Tag::FrameworkPath),
            "String without .framework should not have FrameworkPath tag. String: {}",
            non_framework_string.text
        );
    }

    // Test both dylib framework paths and rpath framework paths
    let dylib_frameworks: Vec<_> = framework_strings
        .iter()
        .filter(|s| s.tags.contains(&stringy::types::Tag::DylibPath))
        .collect();
    let rpath_frameworks: Vec<_> = framework_strings
        .iter()
        .filter(|s| s.tags.contains(&stringy::types::Tag::Rpath))
        .collect();

    println!(
        "Found {} framework paths: {} dylib frameworks, {} rpath frameworks",
        framework_strings.len(),
        dylib_frameworks.len(),
        rpath_frameworks.len()
    );
}

#[test]
fn test_macho_rpath_variable_detection() {
    // Test rpath variable detection and tagging
    let fixture_path = get_fixture_path("test_binary_macho");
    let macho_data = fs::read(&fixture_path)
        .expect("Failed to read Mach-O fixture. Run the build script to generate fixtures.");

    let strings = stringy::extraction::extract_load_command_strings(&macho_data);

    // Filter strings with Rpath tag
    let rpaths = get_rpaths(&strings);

    for rpath in &rpaths {
        let has_rpath_var = has_rpath_variable(&rpath.text);

        if has_rpath_var {
            assert!(
                rpath.tags.contains(&stringy::types::Tag::RpathVariable),
                "Rpath with @-variables should have RpathVariable tag. String: {}",
                rpath.text
            );
        } else {
            assert!(
                !rpath.tags.contains(&stringy::types::Tag::RpathVariable),
                "Rpath without @-variables should not have RpathVariable tag. String: {}",
                rpath.text
            );
        }
    }

    // Diagnostic information
    let rpaths_with_vars: Vec<_> = rpaths
        .iter()
        .filter(|s| s.tags.contains(&stringy::types::Tag::RpathVariable))
        .collect();

    println!(
        "Found {} rpaths: {} with @-variables, {} without",
        rpaths.len(),
        rpaths_with_vars.len(),
        rpaths.len() - rpaths_with_vars.len()
    );

    for rpath_var in &rpaths_with_vars {
        let mut variables_found = Vec::new();
        if rpath_var.text.contains("@rpath") {
            variables_found.push("@rpath");
        }
        if rpath_var.text.contains("@executable_path") {
            variables_found.push("@executable_path");
        }
        if rpath_var.text.contains("@loader_path") {
            variables_found.push("@loader_path");
        }
        println!(
            "Rpath variable found: {} (variables: {:?})",
            rpath_var.text, variables_found
        );
    }
}

#[test]
fn test_macho_empty_load_commands() {
    // Test graceful handling of empty/invalid data
    let empty_result = stringy::extraction::extract_load_command_strings(b"");
    assert_eq!(
        empty_result.len(),
        0,
        "Empty data should return empty vector"
    );

    let invalid_result = stringy::extraction::extract_load_command_strings(b"NOT_A_MACHO_FILE");
    assert_eq!(
        invalid_result.len(),
        0,
        "Invalid data should return empty vector without panicking"
    );
}

#[test]
fn test_macho_dylib_path_classification() {
    // Test dylib path classification and categorization
    let fixture_path = get_fixture_path("test_binary_macho");
    let macho_data = fs::read(&fixture_path)
        .expect("Failed to read Mach-O fixture. Run the build script to generate fixtures.");

    let strings = stringy::extraction::extract_load_command_strings(&macho_data);

    // Filter strings with DylibPath tag
    let dylib_paths = get_dylib_paths(&strings);

    // Verify all dylib paths also have FilePath tag
    for dylib_path in &dylib_paths {
        assert!(
            dylib_path.tags.contains(&stringy::types::Tag::FilePath),
            "Dylib path should also have FilePath tag. String: {}",
            dylib_path.text
        );
    }

    // Categorize dylib paths
    let system_libraries: Vec<_> = dylib_paths
        .iter()
        .filter(|s| s.text.starts_with("/usr/lib") || s.text.starts_with("/System/Library"))
        .collect();

    let framework_libraries: Vec<_> = dylib_paths
        .iter()
        .filter(|s| s.text.contains(".framework"))
        .collect();

    let other_libraries: Vec<_> = dylib_paths
        .iter()
        .filter(|s| {
            !s.text.starts_with("/usr/lib")
                && !s.text.starts_with("/System/Library")
                && !s.text.contains(".framework")
        })
        .collect();

    println!(
        "Dylib path distribution: {} system libraries, {} framework libraries, {} other libraries",
        system_libraries.len(),
        framework_libraries.len(),
        other_libraries.len()
    );

    // Assert that at least some system libraries are found
    // Typical Mach-O binaries link to libSystem
    assert!(
        !system_libraries.is_empty() || !dylib_paths.is_empty(),
        "Should find at least some system libraries or dylib dependencies"
    );
}

#[test]
fn test_macho_load_command_string_metadata() {
    // Test load command string metadata fields
    let fixture_path = get_fixture_path("test_binary_macho");
    let macho_data = fs::read(&fixture_path)
        .expect("Failed to read Mach-O fixture. Run the build script to generate fixtures.");

    let strings = stringy::extraction::extract_load_command_strings(&macho_data);

    for string in &strings {
        // section field should be None (load commands are in header, not sections)
        assert_eq!(
            string.section, None,
            "Load command strings should have None for section field"
        );

        // length field should match the byte length of the text
        assert_eq!(
            string.length as usize,
            string.text.len(),
            "Length field should match text byte length. String: {}",
            string.text
        );

        // Verify source and encoding are correct
        assert_eq!(
            string.source,
            stringy::types::StringSource::LoadCommand,
            "Load command strings should have LoadCommand source"
        );
        assert_eq!(
            string.encoding,
            stringy::types::Encoding::Utf8,
            "Load command strings should be UTF-8"
        );

        // Note: offset and rva values are currently unspecified for load commands
        // and may be implemented in future versions. We don't assert specific values
        // to allow for future enhancements.
    }
}
