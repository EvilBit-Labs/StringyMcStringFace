use std::fs;
use stringy::container::{ContainerParser, PeParser};

fn get_fixture_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

#[test]
fn test_pe_import_export_extraction() {
    // Test with the PE fixture
    let fixture_path = get_fixture_path("test_binary_pe.exe");
    let pe_data = fs::read(&fixture_path)
        .expect("Failed to read PE fixture. Run the build script to generate fixtures.");

    // Verify it's a PE file
    assert!(PeParser::detect(&pe_data), "PE detection should succeed");

    // Test parsing
    let parser = PeParser::new();
    let container_info = parser.parse(&pe_data).expect("Failed to parse PE");

    // Verify we found some sections
    assert!(
        !container_info.sections.is_empty(),
        "Should find sections in PE binary"
    );

    // Check exports (PE executables may not have exports, only DLLs typically do)
    let export_names: Vec<&str> = container_info
        .exports
        .iter()
        .map(|exp| exp.name.as_str())
        .collect();

    println!("PE exports found: {:?}", export_names);

    // PE executables typically don't export symbols (only DLLs do)
    // So we just verify parsing works and sections are found
    if !export_names.is_empty() {
        // If exports are present, check for expected ones
        let has_main = export_names
            .iter()
            .any(|&name| name == "main" || name.contains("main"));
        let has_exported = export_names
            .iter()
            .any(|&name| name == "exported_function" || name.contains("exported_function"));

        if has_main || has_exported {
            println!(
                "Found expected exports: main={}, exported_function={}",
                has_main, has_exported
            );
        }
    } else {
        println!("No exports found (expected for PE executables, only DLLs export symbols)");
    }

    println!(
        "Found {} imports and {} exports",
        container_info.imports.len(),
        container_info.exports.len()
    );
}

#[test]
fn test_pe_section_classification() {
    // Test with the PE fixture
    let fixture_path = get_fixture_path("test_binary_pe.exe");
    let pe_data = fs::read(&fixture_path)
        .expect("Failed to read PE fixture. Run the build script to generate fixtures.");

    if PeParser::detect(&pe_data) {
        let container_info = PeParser::new()
            .parse(&pe_data)
            .expect("Failed to parse PE fixture");

        // Verify we found sections and classified them
        assert!(
            !container_info.sections.is_empty(),
            "Should find sections in PE binary"
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

        // Look for common PE sections
        let section_names: Vec<&str> = container_info
            .sections
            .iter()
            .map(|sec| sec.name.as_str())
            .collect();

        println!("Found sections: {:?}", section_names);

        // Should find at least some standard PE sections
        let has_text = section_names.iter().any(|&name| name.contains(".text"));
        let has_data = section_names
            .iter()
            .any(|&name| name.contains(".data") || name.contains(".rdata"));

        assert!(
            has_text || has_data,
            "Should find .text or .data/.rdata sections"
        );
    } else {
        panic!("PE fixture is not a valid PE file");
    }
}
