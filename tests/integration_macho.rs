use std::fs;
use stringy::container::{ContainerParser, MachoParser};

fn get_fixture_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
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

    // Check exports
    let export_names: Vec<&str> = container_info
        .exports
        .iter()
        .map(|exp| exp.name.as_str())
        .collect();

    assert!(
        export_names
            .iter()
            .any(|&name| name == "main" || name == "_main"),
        "Should find main export. Found: {:?}",
        export_names
    );
    assert!(
        export_names
            .iter()
            .any(|&name| name == "exported_function" || name == "_exported_function"),
        "Should find exported_function export. Found: {:?}",
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
    let lib_names: Vec<&str> = load_command_strings
        .iter()
        .filter(|s| s.tags.contains(&stringy::types::Tag::DylibPath))
        .map(|s| s.text.as_str())
        .collect();

    println!("Found dylib paths: {:?}", lib_names);

    // Verify framework paths are tagged correctly if present
    let framework_paths: Vec<_> = load_command_strings
        .iter()
        .filter(|s| s.tags.contains(&stringy::types::Tag::FrameworkPath))
        .collect();

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
    let rpaths: Vec<_> = load_command_strings
        .iter()
        .filter(|s| s.tags.contains(&stringy::types::Tag::Rpath))
        .collect();

    for rpath in &rpaths {
        // Check if rpath contains @-variables
        if rpath.text.contains("@rpath")
            || rpath.text.contains("@executable_path")
            || rpath.text.contains("@loader_path")
        {
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
}
