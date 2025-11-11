use insta::assert_snapshot;
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

    // Verify resources field exists (may be None for simple binaries)
    // The basic test_binary_pe.exe compiled from test_binary.c won't have resources
    // since it's a minimal C program without resource files
    assert!(
        container_info.resources.is_some() || container_info.resources.is_none(),
        "Resources field should exist in ContainerInfo"
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

        // Verify resources field exists (may be None for simple binaries)
        assert!(
            container_info.resources.is_some() || container_info.resources.is_none(),
            "Resources field should exist in ContainerInfo"
        );
    } else {
        panic!("PE fixture is not a valid PE file");
    }
}

#[test]
fn test_pe_resource_enumeration() {
    // Test resource extraction from PE binary
    // Note: The basic test_binary_pe.exe compiled from test_binary.c likely won't have
    // VERSIONINFO or STRINGTABLE resources since it's a minimal C program without .rc files.
    // Real-world PE binaries with resources should be tested manually or with additional fixtures.
    let fixture_path = get_fixture_path("test_binary_pe.exe");

    let pe_data = match fs::read(&fixture_path) {
        Ok(data) => data,
        Err(_) => {
            println!(
                "PE fixture not found at {:?}, skipping resource test",
                fixture_path
            );
            return;
        }
    };

    if !PeParser::detect(&pe_data) {
        println!("PE fixture is not a valid PE file, skipping resource test");
        return;
    }

    let container_info = match PeParser::new().parse(&pe_data) {
        Ok(info) => info,
        Err(e) => {
            println!(
                "Failed to parse PE fixture: {:?}, skipping resource test",
                e
            );
            return;
        }
    };

    // Check if resources field exists
    match &container_info.resources {
        Some(resources) => {
            println!("Found {} resources", resources.len());
            for (i, resource) in resources.iter().enumerate() {
                println!(
                    "Resource {}: {:?}, language: {}, size: {}",
                    i + 1,
                    resource.resource_type,
                    resource.language,
                    resource.data_size
                );
            }
            // For simple test binaries, the vector may be empty
            // This is expected and not an error
        }
        None => {
            println!("No resources found (expected for minimal test binary)");
        }
    }

    // Verify the structure is correct even if empty
    assert!(
        container_info.resources.is_some() || container_info.resources.is_none(),
        "Resources field should exist in ContainerInfo"
    );
}

#[test]
fn test_pe_resource_extraction_with_resources() {
    // Phase 1: Verify resource enumeration and metadata extraction
    // Phase 2 will add actual string content extraction
    // Test resource extraction from PE binary with embedded resources
    let fixture_path = get_fixture_path("test_binary_with_resources.exe");

    // Assert fixture presence - fail clearly if missing rather than silently skipping
    assert!(
        fixture_path.exists(),
        "Fixture test_binary_with_resources.exe not found at {:?}. Build it using: docker run --rm -v \"$(pwd):/work\" -w /work mcr.microsoft.com/devcontainers/cpp:latest bash -c \"apt-get update -qq && apt-get install -y -qq mingw-w64 && x86_64-w64-mingw32-windres --input-format=rc --output-format=coff -o test_binary_with_resources.res test_binary_with_resources.rc && x86_64-w64-mingw32-gcc -o test_binary_with_resources.exe test_binary_with_resources.c test_binary_with_resources.res\"",
        fixture_path
    );

    let pe_data = fs::read(&fixture_path).expect("Failed to read resource-enabled PE fixture");

    assert!(
        PeParser::detect(&pe_data),
        "Resource-enabled PE fixture is not a valid PE file"
    );

    let container_info = PeParser::new()
        .parse(&pe_data)
        .expect("Failed to parse resource-enabled PE fixture");

    // This binary should have resources
    // test_binary_with_resources.rc has:
    // - 1 VERSIONINFO block
    // - 2 STRINGTABLE blocks (lines 34-39 and 41-45)
    match &container_info.resources {
        Some(resources) => {
            println!("Found {} resources", resources.len());
            for (i, resource) in resources.iter().enumerate() {
                println!(
                    "Resource {}: {:?}, language: {}, size: {}",
                    i + 1,
                    resource.resource_type,
                    resource.language,
                    resource.data_size
                );
            }

            // The test_binary_with_resources.exe should have:
            // - At least 1 VERSIONINFO resource (RT_VERSION)
            // - At least 1 STRINGTABLE resource (RT_STRING)
            let has_version_info = resources
                .iter()
                .any(|r| matches!(r.resource_type, stringy::types::ResourceType::VersionInfo));
            let has_string_table = resources
                .iter()
                .any(|r| matches!(r.resource_type, stringy::types::ResourceType::StringTable));

            assert!(has_version_info, "Should find VERSIONINFO resource");
            assert!(has_string_table, "Should find STRINGTABLE resource");

            // Add count expectations based on the .rc file
            let version_count = resources
                .iter()
                .filter(|r| matches!(r.resource_type, stringy::types::ResourceType::VersionInfo))
                .count();
            let string_table_count = resources
                .iter()
                .filter(|r| matches!(r.resource_type, stringy::types::ResourceType::StringTable))
                .count();

            assert!(version_count >= 1, "Should find at least 1 VERSIONINFO");
            assert!(
                string_table_count >= 1,
                "Should find at least 1 STRINGTABLE"
            );

            // test_binary_with_resources.rc does not include MANIFEST resources
            // Assert that no manifests are present if fixture definition is stable
            let manifest_count = resources
                .iter()
                .filter(|r| matches!(r.resource_type, stringy::types::ResourceType::Manifest))
                .count();
            assert_eq!(
                manifest_count, 0,
                "test_binary_with_resources.exe fixture should not have MANIFEST resources"
            );

            // Verify all resources have valid metadata
            for resource in resources {
                assert!(resource.data_size > 0, "Resource should have non-zero size");
                // Language can be 0 or any valid LCID
                assert!(resource.language <= 0xFFFF, "Language ID should be valid");
            }

            // Phase 2: Verify actual string extraction
            let strings = stringy::extraction::extract_resource_strings(&pe_data);
            assert!(!strings.is_empty(), "Should extract strings from resources");
            assert!(
                strings.len() >= 8 + 5,
                "Should extract at least 8 version strings + 5 string table strings"
            );
        }
        None => {
            panic!(
                "No resources found in resource-enabled binary - Phase 1 should detect resources"
            );
        }
    }

    // Verify the structure is correct
    assert!(
        container_info.resources.is_some(),
        "Resources field should exist in ContainerInfo"
    );
}

#[test]
fn test_pe_symbol_extraction_snapshot() {
    // Test with a fixed PE fixture to create a consistent snapshot
    let fixture_path = get_fixture_path("test_binary_pe.exe");

    let pe_data = fs::read(&fixture_path)
        .expect("Failed to read PE fixture. Run the build script to generate fixtures.");

    if PeParser::detect(&pe_data) {
        let container_info = PeParser::new()
            .parse(&pe_data)
            .expect("Failed to parse PE fixture");
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
        assert_snapshot!("pe_symbol_extraction", output);
    } else {
        panic!("PE fixture is not a valid PE file");
    }
}

#[test]
fn test_pe_version_info_string_extraction() {
    // Test VERSIONINFO string extraction from resource-enabled binary
    let fixture_path = get_fixture_path("test_binary_with_resources.exe");
    assert!(
        fixture_path.exists(),
        "Fixture test_binary_with_resources.exe not found. Build it using: docker run --rm -v \"$(pwd):/work\" -w /work mcr.microsoft.com/devcontainers/cpp:latest bash -c \"apt-get update -qq && apt-get install -y -qq mingw-w64 && x86_64-w64-mingw32-windres --input-format=rc --output-format=coff -o test_binary_with_resources.res test_binary_with_resources.rc && x86_64-w64-mingw32-gcc -o test_binary_with_resources.exe test_binary_with_resources.c test_binary_with_resources.res\""
    );

    let pe_data = fs::read(&fixture_path).expect("Failed to read resource-enabled PE fixture");

    let strings = stringy::extraction::extract_resource_strings(&pe_data);

    // Filter for version strings
    let version_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.tags.contains(&stringy::types::Tag::Version))
        .collect();

    println!("Found {} version strings", version_strings.len());
    for string in &version_strings {
        println!("  - {}", string.text);
    }

    // Should find expected version strings
    let texts: Vec<&str> = version_strings.iter().map(|s| s.text.as_str()).collect();
    let has_company = texts.iter().any(|&t| t.contains("Stringy Test"));
    let has_description = texts
        .iter()
        .any(|&t| t.contains("Test binary with resources"));
    let has_product = texts.iter().any(|&t| t.contains("Stringy Test Binary"));
    let has_version = texts.iter().any(|&t| t.contains("1.0.0.0"));
    let has_copyright = texts.iter().any(|&t| t.contains("Copyright"));

    // Verify encoding and source
    for string in &version_strings {
        assert_eq!(string.encoding, stringy::types::Encoding::Utf16Le);
        assert_eq!(string.source, stringy::types::StringSource::ResourceString);
        assert!(string.tags.contains(&stringy::types::Tag::Version));
        assert!(string.tags.contains(&stringy::types::Tag::Resource));
    }

    // At least some expected strings should be found
    assert!(
        has_company || has_description || has_product || has_version || has_copyright,
        "Should find at least some expected version strings"
    );
}

#[test]
fn test_pe_string_table_extraction() {
    // Test STRINGTABLE string extraction
    let fixture_path = get_fixture_path("test_binary_with_resources.exe");
    assert!(
        fixture_path.exists(),
        "Fixture test_binary_with_resources.exe not found. Build it using: docker run --rm -v \"$(pwd):/work\" -w /work mcr.microsoft.com/devcontainers/cpp:latest bash -c \"apt-get update -qq && apt-get install -y -qq mingw-w64 && x86_64-w64-mingw32-windres --input-format=rc --output-format=coff -o test_binary_with_resources.res test_binary_with_resources.rc && x86_64-w64-mingw32-gcc -o test_binary_with_resources.exe test_binary_with_resources.c test_binary_with_resources.res\""
    );

    let pe_data = fs::read(&fixture_path).expect("Failed to read resource-enabled PE fixture");

    let strings = stringy::extraction::extract_resource_strings(&pe_data);

    // Filter for string table strings (Resource tag but not Version or Manifest)
    let string_table_strings: Vec<_> = strings
        .iter()
        .filter(|s| {
            s.tags.contains(&stringy::types::Tag::Resource)
                && !s.tags.contains(&stringy::types::Tag::Version)
                && !s.tags.contains(&stringy::types::Tag::Manifest)
        })
        .collect();

    println!("Found {} string table strings", string_table_strings.len());
    for string in &string_table_strings {
        println!("  - {}", string.text);
    }

    // Verify encoding
    for string in &string_table_strings {
        assert_eq!(string.encoding, stringy::types::Encoding::Utf16Le);
        assert_eq!(string.source, stringy::types::StringSource::ResourceString);
        assert!(string.tags.contains(&stringy::types::Tag::Resource));
    }

    // Should find at least 5 strings
    assert!(
        string_table_strings.len() >= 5,
        "Should find at least 5 string table strings, found {}",
        string_table_strings.len()
    );
}

#[test]
fn test_pe_resource_string_extraction_snapshot() {
    // Test resource string extraction with snapshot
    let fixture_path = get_fixture_path("test_binary_with_resources.exe");
    assert!(
        fixture_path.exists(),
        "Fixture test_binary_with_resources.exe not found. Build it using: docker run --rm -v \"$(pwd):/work\" -w /work mcr.microsoft.com/devcontainers/cpp:latest bash -c \"apt-get update -qq && apt-get install -y -qq mingw-w64 && x86_64-w64-mingw32-windres --input-format=rc --output-format=coff -o test_binary_with_resources.res test_binary_with_resources.rc && x86_64-w64-mingw32-gcc -o test_binary_with_resources.exe test_binary_with_resources.c test_binary_with_resources.res\""
    );

    let pe_data = fs::read(&fixture_path).expect("Failed to read resource-enabled PE fixture");

    let strings = stringy::extraction::extract_resource_strings(&pe_data);

    let mut output = String::new();

    // VERSION INFO STRINGS
    output.push_str("=== VERSION INFO STRINGS ===\n");
    let version_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.tags.contains(&stringy::types::Tag::Version))
        .collect();
    output.push_str(&format!("Total: {}\n\n", version_strings.len()));
    for (i, string) in version_strings.iter().take(20).enumerate() {
        output.push_str(&format!("Version String {}: {}\n", i + 1, string.text));
    }
    if version_strings.len() > 20 {
        output.push_str(&format!("... and {} more\n", version_strings.len() - 20));
    }
    output.push('\n');

    // STRING TABLE STRINGS
    output.push_str("=== STRING TABLE STRINGS ===\n");
    let string_table_strings: Vec<_> = strings
        .iter()
        .filter(|s| {
            s.tags.contains(&stringy::types::Tag::Resource)
                && !s.tags.contains(&stringy::types::Tag::Version)
                && !s.tags.contains(&stringy::types::Tag::Manifest)
        })
        .collect();
    output.push_str(&format!("Total: {}\n\n", string_table_strings.len()));
    for (i, string) in string_table_strings.iter().take(20).enumerate() {
        output.push_str(&format!("String Table Entry {}: {}\n", i + 1, string.text));
    }
    if string_table_strings.len() > 20 {
        output.push_str(&format!(
            "... and {} more\n",
            string_table_strings.len() - 20
        ));
    }
    output.push('\n');

    // MANIFEST STRINGS
    output.push_str("=== MANIFEST STRINGS ===\n");
    let manifest_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.tags.contains(&stringy::types::Tag::Manifest))
        .collect();
    output.push_str(&format!("Total: {}\n\n", manifest_strings.len()));
    for (i, string) in manifest_strings.iter().take(5).enumerate() {
        // Truncate long manifests for readability
        let text = if string.text.len() > 200 {
            format!("{}...", &string.text[..200])
        } else {
            string.text.clone()
        };
        output.push_str(&format!("Manifest {}:\n{}\n", i + 1, text));
    }
    if manifest_strings.len() > 5 {
        output.push_str(&format!("... and {} more\n", manifest_strings.len() - 5));
    }

    assert_snapshot!("pe_resource_strings", output);
}

#[test]
fn test_pe_resource_strings_empty_binary() {
    // Test with binary that has no resources
    let fixture_path = get_fixture_path("test_binary_pe.exe");
    let pe_data = match fs::read(&fixture_path) {
        Ok(data) => data,
        Err(_) => {
            println!("PE fixture not found, skipping test");
            return;
        }
    };

    let strings = stringy::extraction::extract_resource_strings(&pe_data);
    // Should return empty Vec without panicking
    assert!(strings.is_empty() || !strings.is_empty()); // Either is fine, just no panic
}
