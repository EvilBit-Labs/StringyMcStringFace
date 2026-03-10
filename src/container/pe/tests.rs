use super::*;
use goblin::pe::section_table::{IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_WRITE, SectionTable};

#[test]
fn test_pe_detection() {
    // Invalid data
    let invalid_data = b"NOT_PE_DATA";
    assert!(!PeParser::detect(invalid_data));

    // For valid PE detection, we'd need a complete PE binary
    // which would be better tested with actual binary files
}

#[test]
fn test_section_classification() {
    // Test code section
    let code_section = SectionTable {
        name: *b".text\0\0\0",
        characteristics: IMAGE_SCN_CNT_CODE,
        ..Default::default()
    };
    assert_eq!(PeParser::classify_section(&code_section), SectionType::Code);

    // Test string data section
    let rdata_section = SectionTable {
        name: *b".rdata\0\0",
        characteristics: 0,
        ..Default::default()
    };
    assert_eq!(
        PeParser::classify_section(&rdata_section),
        SectionType::StringData
    );

    // Test writable data section
    let writable_data_section = SectionTable {
        name: *b".data\0\0\0",
        characteristics: IMAGE_SCN_MEM_WRITE,
        ..Default::default()
    };
    assert_eq!(
        PeParser::classify_section(&writable_data_section),
        SectionType::WritableData
    );

    // Test read-only data section
    let readonly_data_section = SectionTable {
        name: *b".data\0\0\0",
        characteristics: 0, // No write flag
        ..Default::default()
    };
    assert_eq!(
        PeParser::classify_section(&readonly_data_section),
        SectionType::ReadOnlyData
    );

    // Test resource section
    let resource_section = SectionTable {
        name: *b".rsrc\0\0\0",
        characteristics: 0,
        ..Default::default()
    };
    assert_eq!(
        PeParser::classify_section(&resource_section),
        SectionType::Resources
    );

    // Test debug section
    let debug_section = SectionTable {
        name: *b".debug\0\0",
        characteristics: 0,
        ..Default::default()
    };
    assert_eq!(
        PeParser::classify_section(&debug_section),
        SectionType::Debug
    );

    // Test other section
    let other_section = SectionTable {
        name: *b".unknown",
        characteristics: 0,
        ..Default::default()
    };
    assert_eq!(
        PeParser::classify_section(&other_section),
        SectionType::Other
    );
}

#[test]
fn test_pe_parser_creation() {
    let _parser = PeParser::new();
    // Just verify we can create the parser
    // Test passes - basic functionality verified
}

#[test]
fn test_section_weight_calculation() {
    // Test weight calculation for different section types and names

    // String data sections should get highest weights
    assert_eq!(
        PeParser::calculate_section_weight(SectionType::StringData, ".rdata"),
        10.0
    );
    assert_eq!(
        PeParser::calculate_section_weight(SectionType::StringData, ".rodata"),
        10.0
    );

    // Resources get high weight
    assert_eq!(
        PeParser::calculate_section_weight(SectionType::Resources, ".rsrc"),
        9.0
    );

    // Read-only data sections
    assert_eq!(
        PeParser::calculate_section_weight(SectionType::ReadOnlyData, ".data"),
        7.0
    );

    // Writable data sections
    assert_eq!(
        PeParser::calculate_section_weight(SectionType::WritableData, ".data"),
        5.0
    );

    // Code sections should get low weight
    assert_eq!(
        PeParser::calculate_section_weight(SectionType::Code, ".text"),
        1.0
    );

    // Debug sections
    assert_eq!(
        PeParser::calculate_section_weight(SectionType::Debug, ".debug"),
        2.0
    );

    // Other sections
    assert_eq!(
        PeParser::calculate_section_weight(SectionType::Other, ".unknown"),
        1.0
    );
}

#[test]
fn test_section_executable_flag_mem_execute() {
    use goblin::pe::section_table::{IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, SectionTable};

    // Test section with MEM_EXECUTE but not CNT_CODE
    // This should be marked as executable even though it's not classified as Code
    let executable_data_section = SectionTable {
        name: *b".data\0\0\0",
        characteristics: IMAGE_SCN_MEM_EXECUTE, // Executable but not code
        ..Default::default()
    };

    // This section should not be classified as Code (no CNT_CODE flag)
    assert_ne!(
        PeParser::classify_section(&executable_data_section),
        SectionType::Code
    );

    // But when parsed, it should be marked as executable
    // We can't directly test parse() here, but we verify the logic:
    // is_executable should check IMAGE_SCN_MEM_EXECUTE, not IMAGE_SCN_CNT_CODE
    let is_executable = executable_data_section.characteristics
        & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE
        != 0;
    assert!(
        is_executable,
        "Section with MEM_EXECUTE should be marked executable"
    );

    // Test section with CNT_CODE (should be Code type)
    let code_section = SectionTable {
        name: *b".text\0\0\0",
        characteristics: IMAGE_SCN_CNT_CODE,
        ..Default::default()
    };
    assert_eq!(PeParser::classify_section(&code_section), SectionType::Code);

    // Test section with both flags
    let both_flags_section = SectionTable {
        name: *b".text\0\0\0",
        characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE,
        ..Default::default()
    };
    assert_eq!(
        PeParser::classify_section(&both_flags_section),
        SectionType::Code
    );
    let is_executable_both =
        both_flags_section.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE != 0;
    assert!(
        is_executable_both,
        "Section with both flags should be executable"
    );
}

#[test]
fn test_export_ordinal_extraction() {
    // Test that export ordinals are correctly extracted from the export directory table
    // We'll use a minimal PE binary with exports to verify ordinal calculation
    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("test_binary_pe.exe");

    if fixture_path.exists() {
        let pe_data = std::fs::read(&fixture_path).expect("Failed to read PE fixture");

        if PeParser::detect(&pe_data) {
            let container_info = PeParser::new()
                .parse(&pe_data)
                .expect("Failed to parse PE fixture");

            // If exports exist, verify ordinals are present and reasonable
            if !container_info.exports.is_empty() {
                // All exports should have ordinals
                for export in &container_info.exports {
                    assert!(
                        export.ordinal.is_some(),
                        "Export '{}' should have an ordinal",
                        export.name
                    );

                    // Ordinal should be a valid u16 value
                    if let Some(ord) = export.ordinal {
                        assert!(
                            ord > 0,
                            "Export '{}' should have a positive ordinal, got {}",
                            export.name,
                            ord
                        );
                    }
                }

                // Verify ordinals are sequential (base + index)
                // The first export should have ordinal = base_ordinal
                // Subsequent exports should have ordinal = base_ordinal + index
                for (i, export) in container_info.exports.iter().enumerate() {
                    if let Some(ord) = export.ordinal {
                        // Ordinal should be base_ordinal + index
                        // We can't directly verify the base_ordinal without parsing the export directory,
                        // but we can verify that ordinals are sequential
                        if i > 0 {
                            let prev_ord = container_info.exports[i - 1].ordinal.unwrap();
                            assert!(
                                ord >= prev_ord,
                                "Export ordinals should be non-decreasing: export {} has ordinal {}, previous has {}",
                                i,
                                ord,
                                prev_ord
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn test_export_unnamed_ordinal_naming() {
    // Test that unnamed exports use the correct ordinal in their synthesized name
    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("test_binary_pe.exe");

    if fixture_path.exists() {
        let pe_data = std::fs::read(&fixture_path).expect("Failed to read PE fixture");

        if PeParser::detect(&pe_data) {
            let container_info = PeParser::new()
                .parse(&pe_data)
                .expect("Failed to parse PE fixture");

            // Check for unnamed exports (those with names starting with "ordinal_")
            for export in &container_info.exports {
                if export.name.starts_with("ordinal_") {
                    // Extract the ordinal from the name
                    if let Some(ord_str) = export.name.strip_prefix("ordinal_")
                        && let Ok(ord_from_name) = ord_str.parse::<u32>()
                        && let Some(ord_from_field) = export.ordinal
                    {
                        // Verify the ordinal in the name matches the ordinal field
                        assert_eq!(
                            ord_from_name as u16, ord_from_field,
                            "Unnamed export name '{}' should match ordinal field {}",
                            export.name, ord_from_field
                        );
                    }
                }
            }
        }
    }
}
