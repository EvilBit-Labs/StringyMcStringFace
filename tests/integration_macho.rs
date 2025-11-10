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
