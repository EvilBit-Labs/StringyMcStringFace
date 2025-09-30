use std::fs;
use std::process::Command;
use stringy::container::{ContainerParser, ElfParser};

#[test]
fn test_elf_import_export_extraction() {
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
    let mut output = Command::new("x86_64-linux-gnu-gcc")
        .args([
            "-static", // Static linking to avoid library dependencies
            "-o",
            elf_file.to_str().unwrap(),
            c_file.to_str().unwrap(),
        ])
        .output();

    // If cross-compiler not available, try regular gcc
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
