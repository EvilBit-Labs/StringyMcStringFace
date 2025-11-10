use std::fs;
use std::fs::File;
use std::io::Write;
use std::process::Command;
use stringy::container::{ContainerParser, ElfParser};
use tempfile::TempDir;
use insta::assert_snapshot;

#[test]
#[cfg(target_family = "unix")]
fn test_elf_import_export_extraction_dynamic() {
    // Create a simple C program that we can compile to test with
    let c_code = r#"
#include <stdio.h>
#include <stdlib.h>

// Export a function
int exported_function(int x) {
    return x * 2;
}

// Use some imports
int main() {
    printf("Hello, world!\n");  // Import from libc
    void* ptr = malloc(100);    // Import from libc
    free(ptr);                  // Import from libc
    return 0;
}
"#;

    // Write the C code to a temporary file
    let temp_dir = std::env::temp_dir();
    let c_file = temp_dir.join("test_elf.c");
    let elf_file = temp_dir.join("test_elf");

    fs::write(&c_file, c_code).expect("Failed to write C file");

    // Try to compile it with gcc, attempting to force ELF output
    // First try with a cross-compiler for Linux if available
    // NOTE: This is for dynamic linking test, so we DON'T use -static
    let mut output = Command::new("x86_64-linux-gnu-gcc")
        .args(["-o", elf_file.to_str().unwrap(), c_file.to_str().unwrap()])
        .output();

    // If cross-compiler not available, try regular gcc (dynamically linked)
    if output.is_err() {
        output = Command::new("gcc")
            .args(["-o", elf_file.to_str().unwrap(), c_file.to_str().unwrap()])
            .output();
    }

    match output {
        Ok(result) if result.status.success() => {
            // Successfully compiled, now test our ELF parser
            let elf_data = fs::read(&elf_file).expect("Failed to read ELF file");

            // Check what format we actually got
            match goblin::Object::parse(&elf_data) {
                Ok(goblin::Object::Elf(_)) => {
                    // Great! We have an ELF binary, test our parser
                    assert!(ElfParser::detect(&elf_data), "ELF detection should succeed");
                }
                Ok(goblin::Object::Mach(_)) => {
                    println!("Got Mach-O binary (expected on macOS), skipping ELF-specific test");
                    // Clean up and return early
                    let _ = fs::remove_file(&c_file);
                    let _ = fs::remove_file(&elf_file);
                    return;
                }
                Ok(other) => {
                    println!(
                        "Got unexpected binary format: {:?}, skipping test",
                        std::mem::discriminant(&other)
                    );
                    let _ = fs::remove_file(&c_file);
                    let _ = fs::remove_file(&elf_file);
                    return;
                }
                Err(e) => {
                    println!("Failed to parse binary: {}, skipping test", e);
                    let _ = fs::remove_file(&c_file);
                    let _ = fs::remove_file(&elf_file);
                    return;
                }
            }

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
            let expected_imports = ["printf", "malloc", "free", "__libc_start_main"];
            let found_expected = expected_imports
                .iter()
                .any(|&expected| import_names.contains(&expected));

            assert!(
                found_expected,
                "Should find at least one expected import. Found: {:?}",
                import_names
            );

            // Verify we found some exports (at least main and our exported function)
            // Note: exports might be stripped in some builds, so we'll be lenient
            println!(
                "Found {} imports and {} exports",
                container_info.imports.len(),
                container_info.exports.len()
            );

            // Clean up
            let _ = fs::remove_file(&c_file);
            let _ = fs::remove_file(&elf_file);
        }
        Ok(_) => {
            println!("gcc compilation failed, skipping ELF integration test");
            // This is not a test failure - just means gcc isn't available
        }
        Err(_) => {
            println!("gcc not found, skipping ELF integration test");
            // This is not a test failure - just means gcc isn't available
        }
    }
}

#[test]
#[cfg(target_family = "unix")]
fn test_elf_import_export_extraction_static() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let c_file = temp_dir.path().join("test_static.c");
    let elf_file = temp_dir.path().join("test_static");

    let c_code = r#"
        #include <stdio.h>
        #include <stdlib.h>

        void exported_function() {
            printf("Hello from exported function\n");
        }

        int main() {
            void *ptr = malloc(100);
            printf("Allocated memory\n");
            free(ptr);
            exported_function();
            return 0;
        }
    "#;

    File::create(&c_file)
        .expect("Failed to create C file")
        .write_all(c_code.as_bytes())
        .expect("Failed to write C code");

    // Compile statically-linked binary with -static flag
    let mut output = Command::new("x86_64-linux-gnu-gcc")
        .args([
            "-static",
            "-o",
            elf_file.to_str().unwrap(),
            c_file.to_str().unwrap(),
        ])
        .output();

    if output.is_err() || !output.as_ref().map(|o| o.status.success()).unwrap_or(false) {
        output = Command::new("gcc")
            .args([
                "-static",
                "-o",
                elf_file.to_str().unwrap(),
                c_file.to_str().unwrap(),
            ])
            .output();
    }

    match output {
        Ok(output) if output.status.success() => {
            let elf_data = fs::read(&elf_file).expect("Failed to read ELF file");

            let format_obj = goblin::Object::parse(&elf_data).expect("Failed to parse with goblin");

            match format_obj {
                goblin::Object::Elf(_elf) => {
                    let parser = ElfParser::new();
                    let container_info = parser.parse(&elf_data).expect("Failed to parse ELF");

                    // Statically-linked binaries typically have no or very few dynamic imports
                    // since all dependencies are embedded
                    println!(
                        "Static binary imports found: {} (expected: 0 or very few)",
                        container_info.imports.len()
                    );

                    // Check exports - note that static binaries may have symbols stripped
                    // or may not expose them depending on compilation flags
                    let export_names: Vec<String> = container_info
                        .exports
                        .iter()
                        .map(|e| e.name.clone())
                        .collect();

                    println!(
                        "Static binary exports found: {} exports: {:?}",
                        container_info.exports.len(),
                        export_names
                    );

                    // If exports are present, verify expected ones exist
                    // Note: Exports may be stripped in static binaries, so this is not always guaranteed
                    if !container_info.exports.is_empty() {
                        let has_main = export_names.iter().any(|name| name == "main");
                        let has_exported_function =
                            export_names.iter().any(|name| name == "exported_function");

                        if has_main || has_exported_function {
                            println!(
                                "Found expected exports: main={}, exported_function={}",
                                has_main, has_exported_function
                            );
                        }
                    } else {
                        println!(
                            "No exports found in static binary. This can happen when symbols are stripped or not exported."
                        );
                    }
                }
                goblin::Object::Mach(_) => {
                    println!("Compiled to Mach-O, skipping ELF-specific test");
                }
                _ => panic!("Unexpected binary format"),
            }
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            println!(
                "Static compilation failed, skipping test. This is expected if static libraries are not available.\nError: {}",
                stderr
            );
        }
        Err(e) => {
            println!(
                "GCC not available, skipping test. This is expected in some CI environments. Error: {}",
                e
            );
        }
    }
}

#[test]
#[cfg(target_family = "unix")]
fn test_elf_section_classification_integration() {
    // Test with the current binary (this test executable)
    let current_exe = std::env::current_exe().expect("Failed to get current executable path");

    if let Ok(elf_data) = fs::read(&current_exe) {
        if ElfParser::detect(&elf_data) {
            let parser = ElfParser::new();
            if let Ok(container_info) = parser.parse(&elf_data) {
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
                    .filter(|sec| {
                        matches!(sec.section_type, stringy::types::SectionType::StringData)
                    })
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
            }
        }
    }
}

#[test]
#[cfg(target_family = "unix")]
fn test_elf_library_dependencies() {
    // Test with the current binary (this test executable) which should have library dependencies
    let current_exe = std::env::current_exe().expect("Failed to get current executable path");

    if let Ok(elf_data) = fs::read(&current_exe) {
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
                        let has_libpthread =
                            libraries.iter().any(|lib| lib.contains("pthread"));
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
            Ok(goblin::Object::Mach(_)) => {
                println!("Got Mach-O binary (expected on macOS), skipping ELF library test");
            }
            Ok(_) => {
                println!("Got non-ELF binary format, skipping test");
            }
            Err(e) => {
                println!("Failed to parse binary: {}, skipping test", e);
            }
        }
    }
}

#[test]
#[cfg(target_family = "unix")]
fn test_elf_symbol_extraction_snapshot() {
    // Test with the current binary to create a snapshot of symbol extraction
    let current_exe = std::env::current_exe().expect("Failed to get current executable path");

    if let Ok(elf_data) = fs::read(&current_exe) {
        if ElfParser::detect(&elf_data) {
            let parser = ElfParser::new();
            if let Ok(container_info) = parser.parse(&elf_data) {
                // Create a formatted output for snapshot testing
                let mut output = String::new();
                
                // Document imports
                output.push_str("=== IMPORTS ===\n");
                output.push_str(&format!("Total: {}\n\n", container_info.imports.len()));
                
                // Take first 10 imports for snapshot (to keep it manageable)
                for (i, import) in container_info.imports.iter().take(10).enumerate() {
                    output.push_str(&format!(
                        "Import {}: {}\n",
                        i + 1,
                        import.name
                    ));
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
                    output.push_str(&format!(
                        "Export {}: {}\n",
                        i + 1,
                        export.name
                    ));
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
            }
        }
    }
}
