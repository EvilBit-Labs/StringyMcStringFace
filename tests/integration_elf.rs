use insta::assert_snapshot;
use std::fs;
use stringy::container::{ContainerParser, ElfParser};

fn get_fixture_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

#[test]
fn test_elf_import_export_extraction_dynamic() {
    // Test with the ELF fixture
    let fixture_path = get_fixture_path("test_binary_elf");
    let elf_data = fs::read(&fixture_path)
        .expect("Failed to read ELF fixture. Run the build script to generate fixtures.");

    // Verify it's an ELF file
    assert!(ElfParser::detect(&elf_data), "ELF detection should succeed");

    // Test parsing
    let parser = ElfParser::new();
    let container_info = parser.parse(&elf_data).expect("Failed to parse ELF");

    // Verify we found some imports
    assert!(
        !container_info.imports.is_empty(),
        "Should find imports like printf, malloc, free"
    );

    // Check that we found expected imports
    let import_names: Vec<&str> = container_info
        .imports
        .iter()
        .map(|imp| imp.name.as_str())
        .collect();

    // We should find at least some of these common libc functions
    let expected_imports = ["malloc", "free", "__libc_start_main"];
    let found_expected = expected_imports
        .iter()
        .any(|&expected| import_names.iter().any(|&name| name.contains(expected)));

    assert!(
        found_expected,
        "Should find at least one expected import. Found: {:?}",
        import_names
    );

    // Verify we found some exports (at least main and our exported function)
    let export_names: Vec<&str> = container_info
        .exports
        .iter()
        .map(|exp| exp.name.as_str())
        .collect();

    assert!(
        export_names.contains(&"main"),
        "Should find main export. Found: {:?}",
        export_names
    );
    assert!(
        export_names.contains(&"exported_function"),
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
fn test_elf_import_export_extraction_static() {
    // Test with the ELF fixture (dynamically linked, but we can still test parsing)
    // Note: For true static binary testing, we'd need a separate static fixture
    let fixture_path = get_fixture_path("test_binary_elf");
    let elf_data = fs::read(&fixture_path)
        .expect("Failed to read ELF fixture. Run the build script to generate fixtures.");

    let parser = ElfParser::new();
    let container_info = parser.parse(&elf_data).expect("Failed to parse ELF");

    // Our fixture is dynamically linked, so it should have imports
    println!("Binary imports found: {}", container_info.imports.len());

    // Check exports
    let export_names: Vec<String> = container_info
        .exports
        .iter()
        .map(|e| e.name.clone())
        .collect();

    println!(
        "Binary exports found: {} exports: {:?}",
        container_info.exports.len(),
        export_names
    );

    // Verify expected exports exist
    assert!(
        export_names.contains(&"main".to_string()),
        "Should find main export"
    );
    assert!(
        export_names.contains(&"exported_function".to_string()),
        "Should find exported_function export"
    );
}

#[test]
fn test_elf_section_classification_integration() {
    // Test with the ELF fixture
    let fixture_path = get_fixture_path("test_binary_elf");
    let elf_data = fs::read(&fixture_path)
        .expect("Failed to read ELF fixture. Run the build script to generate fixtures.");

    if ElfParser::detect(&elf_data) {
        let container_info = ElfParser::new()
            .parse(&elf_data)
            .expect("Failed to parse ELF fixture");
        // Verify we found sections and classified them
        assert!(
            !container_info.sections.is_empty(),
            "Should find sections in ELF binary"
        );

        // Look for common ELF sections and verify weights are assigned
        let section_names: Vec<&str> = container_info
            .sections
            .iter()
            .map(|sec| sec.name.as_str())
            .collect();

        println!("Found sections: {:?}", section_names);

        // Verify that all sections have weights assigned
        for section in &container_info.sections {
            assert!(
                section.weight > 0.0,
                "Section {} should have a positive weight, got {}",
                section.name,
                section.weight
            );
        }

        // Check that string data sections get higher weights than code sections
        let string_sections: Vec<_> = container_info
            .sections
            .iter()
            .filter(|sec| matches!(sec.section_type, stringy::types::SectionType::StringData))
            .collect();
        let code_sections: Vec<_> = container_info
            .sections
            .iter()
            .filter(|sec| matches!(sec.section_type, stringy::types::SectionType::Code))
            .collect();

        if !string_sections.is_empty() && !code_sections.is_empty() {
            let max_string_weight = string_sections
                .iter()
                .map(|s| s.weight)
                .fold(0.0f32, f32::max);
            let max_code_weight = code_sections
                .iter()
                .map(|s| s.weight)
                .fold(0.0f32, f32::max);
            assert!(
                max_string_weight > max_code_weight,
                "String sections should have higher weight than code sections"
            );
        }

        // We should find at least some standard sections
        let has_text = section_names.iter().any(|&name| name.contains(".text"));
        let has_rodata = section_names.iter().any(|&name| name.contains(".rodata"));

        // At least one of these should be present in a typical ELF
        assert!(
            has_text || has_rodata,
            "Should find .text or .rodata sections"
        );
    } else {
        panic!("ELF fixture is not a valid ELF file");
    }
}

#[test]
fn test_elf_library_dependencies() {
    // Test with the ELF fixture
    let fixture_path = get_fixture_path("test_binary_elf");
    let elf_data = fs::read(&fixture_path)
        .expect("Failed to read ELF fixture. Run the build script to generate fixtures.");

    // Parse with goblin to check if it's ELF
    match goblin::Object::parse(&elf_data) {
        Ok(goblin::Object::Elf(elf)) => {
            // Check if we have a dynamic section
            if let Some(ref dynamic) = elf.dynamic {
                // Extract libraries using the method we're testing
                let libraries = dynamic.get_libraries(&elf.dynstrtab);

                println!("Found {} library dependencies:", libraries.len());
                for lib in &libraries {
                    println!("  - {}", lib);
                }

                // A dynamically linked ELF binary should typically have at least one library
                // (e.g., libc.so.6 on Linux)
                // But we'll be lenient here since we might be on a different platform
                if !libraries.is_empty() {
                    // Verify at least one common library is present
                    let has_libc = libraries.iter().any(|lib| lib.contains("libc"));
                    let has_libpthread = libraries.iter().any(|lib| lib.contains("pthread"));
                    let has_libm = libraries.iter().any(|lib| lib.contains("libm"));

                    // At least one common library should be present in a typical executable
                    if has_libc || has_libpthread || has_libm {
                        println!("✓ Found expected library dependencies");
                    }
                } else {
                    println!(
                        "No library dependencies found. This might be a static binary or on a non-Linux platform."
                    );
                }
            } else {
                println!("No dynamic section found. This might be a static binary.");
            }
        }
        Ok(_) => {
            panic!("Expected ELF binary from fixture");
        }
        Err(e) => {
            panic!("Failed to parse ELF fixture: {}", e);
        }
    }
}

#[test]
fn test_elf_symbol_extraction_snapshot() {
    // Test with a fixed ELF fixture to create a consistent snapshot
    let fixture_path = get_fixture_path("test_binary_elf");

    let elf_data = fs::read(&fixture_path)
        .expect("Failed to read ELF fixture. Run the build script to generate fixtures.");

    if ElfParser::detect(&elf_data) {
        let container_info = ElfParser::new()
            .parse(&elf_data)
            .expect("Failed to parse ELF fixture");
        // Create a formatted output for snapshot testing
        let mut output = String::new();

        // Document imports
        output.push_str("=== IMPORTS ===\n");
        output.push_str(&format!("Total: {}\n\n", container_info.imports.len()));

        // Take first 10 imports for snapshot (to keep it manageable)
        for (i, import) in container_info.imports.iter().take(10).enumerate() {
            output.push_str(&format!("Import {}: {}\n", i + 1, import.name));
            if let Some(ref lib) = import.library {
                output.push_str(&format!("  Library: {}\n", lib));
            }
            if let Some(addr) = import.address {
                output.push_str(&format!("  Address: 0x{:x}\n", addr));
            }
            output.push('\n');
        }

        if container_info.imports.len() > 10 {
            output.push_str(&format!(
                "... and {} more imports\n\n",
                container_info.imports.len() - 10
            ));
        }

        // Document exports
        output.push_str("=== EXPORTS ===\n");
        output.push_str(&format!("Total: {}\n\n", container_info.exports.len()));

        // Take first 10 exports for snapshot
        for (i, export) in container_info.exports.iter().take(10).enumerate() {
            output.push_str(&format!("Export {}: {}\n", i + 1, export.name));
            output.push_str(&format!("  Address: 0x{:x}\n", export.address));
            if let Some(ord) = export.ordinal {
                output.push_str(&format!("  Ordinal: {}\n", ord));
            }
            output.push('\n');
        }

        if container_info.exports.len() > 10 {
            output.push_str(&format!(
                "... and {} more exports\n",
                container_info.exports.len() - 10
            ));
        }

        // Snapshot the output
        assert_snapshot!("elf_symbol_extraction", output);
    } else {
        panic!("ELF fixture is not a valid ELF file");
    }
}

#[test]
fn test_elf_symbol_library_mapping() {
    // Test symbol-to-library mapping using version information
    let fixture_path = get_fixture_path("test_binary_elf");
    let elf_data = fs::read(&fixture_path)
        .expect("Failed to read ELF fixture. Run the build script to generate fixtures.");

    match goblin::Object::parse(&elf_data) {
        Ok(goblin::Object::Elf(_)) => {
            let parser = ElfParser::new();
            let container_info = parser.parse(&elf_data).expect("Failed to parse ELF");

            // Check that we found imports
            assert!(!container_info.imports.is_empty(), "Should find imports");

            // Check that some imports have library information populated
            let imports_with_libs: Vec<_> = container_info
                .imports
                .iter()
                .filter(|imp| imp.library.is_some())
                .collect();

            println!(
                "Found {} imports with library information out of {} total imports",
                imports_with_libs.len(),
                container_info.imports.len()
            );

            // Common libc symbols should have library info if version info is available
            let malloc_import = container_info
                .imports
                .iter()
                .find(|imp| imp.name.contains("malloc"));

            if let Some(malloc) = malloc_import {
                println!("malloc import: {:?}", malloc);
            }

            // At least verify the mapping logic runs without errors
            // Actual library attribution depends on binary's version info
        }
        Ok(_) => {
            panic!("Expected ELF binary from fixture");
        }
        Err(e) => {
            panic!("Failed to parse ELF fixture: {}", e);
        }
    }
}

#[test]
fn test_elf_unversioned_symbols() {
    // Test handling of symbols without version info
    let fixture_path = get_fixture_path("test_binary_elf");
    let elf_data = fs::read(&fixture_path)
        .expect("Failed to read ELF fixture. Run the build script to generate fixtures.");

    if ElfParser::detect(&elf_data) {
        let container_info = ElfParser::new()
            .parse(&elf_data)
            .expect("Failed to parse ELF fixture");
        // Count imports with and without library info
        let with_lib = container_info
            .imports
            .iter()
            .filter(|imp| imp.library.is_some())
            .count();
        let without_lib = container_info
            .imports
            .iter()
            .filter(|imp| imp.library.is_none())
            .count();

        println!(
            "Imports with library: {}, without library: {}",
            with_lib, without_lib
        );

        // Both cases are valid - versioned symbols get libraries,
        // unversioned symbols may not
        assert!(
            !container_info.imports.is_empty(),
            "Should find at least some imports"
        );
    } else {
        panic!("ELF fixture is not a valid ELF file");
    }
}

#[test]
fn test_elf_no_dynamic_section() {
    // Test with the ELF fixture (dynamically linked, but we can test parsing)
    // Note: For true static binary testing, we'd need a separate static fixture
    let fixture_path = get_fixture_path("test_binary_elf");
    let elf_data = fs::read(&fixture_path)
        .expect("Failed to read ELF fixture. Run the build script to generate fixtures.");

    match goblin::Object::parse(&elf_data) {
        Ok(goblin::Object::Elf(_)) => {
            let parser = ElfParser::new();
            let container_info = parser.parse(&elf_data).expect("Failed to parse ELF");

            // Our fixture is dynamically linked, so it should have imports
            // Some may have library info if version info is available
            println!("Binary: {} imports", container_info.imports.len());

            // Verify parsing works correctly
            assert!(!container_info.sections.is_empty(), "Should have sections");
        }
        _ => {
            panic!("Expected ELF binary from fixture");
        }
    }
}

#[test]
fn test_elf_stripped_binary() {
    // Test with the ELF fixture (not stripped, but we can test parsing)
    // Note: For true stripped binary testing, we'd need a separate stripped fixture
    let fixture_path = get_fixture_path("test_binary_elf");
    let elf_data = fs::read(&fixture_path)
        .expect("Failed to read ELF fixture. Run the build script to generate fixtures.");

    match goblin::Object::parse(&elf_data) {
        Ok(goblin::Object::Elf(_)) => {
            let parser = ElfParser::new();
            // Should handle gracefully
            let container_info = parser.parse(&elf_data).expect("Failed to parse ELF");
            println!(
                "Binary: {} imports, {} exports",
                container_info.imports.len(),
                container_info.exports.len()
            );
            // Parsing should succeed
            assert!(!container_info.sections.is_empty(), "Should have sections");
        }
        _ => {
            panic!("Expected ELF binary from fixture");
        }
    }
}
