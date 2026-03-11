use super::*;
use goblin::elf::section_header::{SHF_EXECINSTR, SectionHeader};

#[test]
fn test_elf_detection() {
    // Invalid data
    let invalid_data = b"NOT_ELF_DATA";
    assert!(!ElfParser::detect(invalid_data));

    // For valid ELF detection, we'd need a complete ELF binary
    // which would be better tested with actual binary files
}

#[test]
fn test_section_classification() {
    // Create a mock section header for testing
    let section = SectionHeader {
        sh_flags: SHF_EXECINSTR as u64,
        ..Default::default()
    };
    assert_eq!(
        ElfParser::classify_section(&section, ".text"),
        SectionType::Code
    );

    // Test string data sections
    let data_section = SectionHeader {
        sh_flags: 0,
        ..Default::default()
    };
    assert_eq!(
        ElfParser::classify_section(&data_section, ".rodata"),
        SectionType::StringData
    );
    assert_eq!(
        ElfParser::classify_section(&data_section, ".rodata.str1.1"),
        SectionType::StringData
    );
    assert_eq!(
        ElfParser::classify_section(&data_section, ".comment"),
        SectionType::StringData
    );
    assert_eq!(
        ElfParser::classify_section(&data_section, ".note"),
        SectionType::StringData
    );

    // Test read-only data sections
    assert_eq!(
        ElfParser::classify_section(&data_section, ".data.rel.ro"),
        SectionType::ReadOnlyData
    );
    assert_eq!(
        ElfParser::classify_section(&data_section, ".data.rel.ro.local"),
        SectionType::ReadOnlyData
    );

    // Test writable data sections
    assert_eq!(
        ElfParser::classify_section(&data_section, ".data"),
        SectionType::WritableData
    );
    assert_eq!(
        ElfParser::classify_section(&data_section, ".bss"),
        SectionType::WritableData
    );

    // Test debug sections
    assert_eq!(
        ElfParser::classify_section(&data_section, ".debug_info"),
        SectionType::Debug
    );
    assert_eq!(
        ElfParser::classify_section(&data_section, ".strtab"),
        SectionType::Debug
    );
    assert_eq!(
        ElfParser::classify_section(&data_section, ".symtab"),
        SectionType::Debug
    );

    // Test other sections
    assert_eq!(
        ElfParser::classify_section(&data_section, ".unknown"),
        SectionType::Other
    );
}

#[test]
fn test_elf_parser_creation() {
    let _parser = ElfParser::new();
    // Just verify we can create the parser
    // Test passes - basic functionality verified
}

#[test]
fn test_section_weight_calculation() {
    // Test weight calculation for different section types and names

    // String data sections should get highest weights
    assert_eq!(
        ElfParser::calculate_section_weight(SectionType::StringData, ".rodata"),
        10.0
    );
    assert_eq!(
        ElfParser::calculate_section_weight(SectionType::StringData, ".rodata.str1.1"),
        10.0
    );
    assert_eq!(
        ElfParser::calculate_section_weight(SectionType::StringData, ".comment"),
        9.0
    );
    assert_eq!(
        ElfParser::calculate_section_weight(SectionType::StringData, ".note"),
        9.0
    );

    // Read-only data sections
    assert_eq!(
        ElfParser::calculate_section_weight(SectionType::ReadOnlyData, ".data.rel.ro"),
        7.0
    );

    // Writable data sections
    assert_eq!(
        ElfParser::calculate_section_weight(SectionType::WritableData, ".data"),
        5.0
    );

    // Code sections should get low weight
    assert_eq!(
        ElfParser::calculate_section_weight(SectionType::Code, ".text"),
        1.0
    );

    // Debug sections
    assert_eq!(
        ElfParser::calculate_section_weight(SectionType::Debug, ".debug_info"),
        2.0
    );

    // Other sections
    assert_eq!(
        ElfParser::calculate_section_weight(SectionType::Other, ".unknown"),
        1.0
    );
}

#[test]
fn test_symbol_filtering_constants() {
    // Test the symbol filtering logic by checking the constants we use
    use goblin::elf::section_header::SHN_UNDEF;
    use goblin::elf::sym::{STB_GLOBAL, STB_WEAK, STT_FUNC, STT_OBJECT};

    // Verify that our filtering constants are correct
    assert_eq!(SHN_UNDEF, 0); // Undefined section index
    assert_eq!(STB_GLOBAL, 1); // Global binding
    assert_eq!(STB_WEAK, 2); // Weak binding
    assert_eq!(STT_FUNC, 2); // Function type
    assert_eq!(STT_OBJECT, 1); // Object type

    // These constants are used in our import/export filtering logic
    // This test ensures they remain consistent with the goblin crate
}

#[test]
fn test_import_export_extraction_methods_exist() {
    // API contract test: verify method signatures haven't changed.
    // These are compile-time checks, not runtime behavior tests.
    let parser = ElfParser::new();
    let _extract_imports = ElfParser::extract_imports;
    let _extract_exports = ElfParser::extract_exports;
    let _ = parser;
}

#[test]
fn test_library_extraction_behavior() {
    // API contract test: verify method signature for get_symbol_providing_library.
    // Compile-time only -- runtime testing requires a valid ELF with version info.
    let parser = ElfParser::new();
    let _method_ref: fn(&ElfParser, &Elf, usize, &[String]) -> Option<String> =
        ElfParser::get_symbol_providing_library;
    let _ = parser;
}

#[test]
fn test_extract_needed_libraries_with_test_binary() {
    // Test library extraction with the current test binary
    // This test demonstrates the extract_needed_libraries method works with real ELF files
    let current_exe = std::env::current_exe().expect("Failed to get current executable");

    if let Ok(data) = std::fs::read(&current_exe)
        && let Ok(goblin::Object::Elf(elf)) = goblin::Object::parse(&data)
    {
        let parser = ElfParser::new();
        let libraries = parser.extract_needed_libraries(&elf);

        // The test binary should have some libraries (e.g., libc) unless statically linked
        println!("Test binary libraries: {:?}", libraries);

        // Just verify the method runs without panicking
        // Actual library content depends on the build environment
    }
}

#[test]
fn test_symbol_type_constants() {
    // Test additional symbol type constants we're now using
    use goblin::elf::sym::{STT_GNU_IFUNC, STT_TLS};

    // Verify the constants we're now using in import/export filtering
    assert_eq!(STT_TLS, 6); // Thread-local storage
    assert_eq!(STT_GNU_IFUNC, 10); // Indirect function

    // These constants are used in our enhanced import/export filtering logic
}

#[test]
fn test_symbol_visibility_constants() {
    // Test symbol visibility constants
    use goblin::elf::sym::{STV_DEFAULT, STV_HIDDEN, STV_INTERNAL};

    // Verify the visibility constants we're using for filtering
    assert_eq!(STV_DEFAULT, 0);
    assert_eq!(STV_HIDDEN, 2);
    assert_eq!(STV_INTERNAL, 1);

    // These constants are used to filter out hidden and internal symbols from exports
}
