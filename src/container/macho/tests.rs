use super::*;

#[test]
fn test_macho_detection() {
    // Invalid data
    let invalid_data = b"NOT_MACHO_DATA";
    assert!(!MachoParser::detect(invalid_data));

    // For valid Mach-O detection, we'd need a complete Mach-O binary
    // which would be better tested with actual binary files
}

#[test]
fn test_section_classification() {
    // Test string data sections
    assert_eq!(
        MachoParser::classify_section("__TEXT", "__cstring"),
        SectionType::StringData
    );
    assert_eq!(
        MachoParser::classify_section("__TEXT", "__const"),
        SectionType::StringData
    );
    assert_eq!(
        MachoParser::classify_section("__DATA_CONST", "__cfstring"),
        SectionType::StringData
    );
    assert_eq!(
        MachoParser::classify_section("__TEXT", "__objc_methname"),
        SectionType::StringData
    );
    assert_eq!(
        MachoParser::classify_section("__TEXT", "__objc_classname"),
        SectionType::StringData
    );
    assert_eq!(
        MachoParser::classify_section("__TEXT", "__ustring"),
        SectionType::StringData
    );

    // Test read-only data sections
    assert_eq!(
        MachoParser::classify_section("__DATA_CONST", "__const"),
        SectionType::ReadOnlyData
    );

    // Test writable data sections
    assert_eq!(
        MachoParser::classify_section("__DATA", "__data"),
        SectionType::WritableData
    );

    // Test code sections
    assert_eq!(
        MachoParser::classify_section("__TEXT", "__text"),
        SectionType::Code
    );
    assert_eq!(
        MachoParser::classify_section("__TEXT", "__stubs"),
        SectionType::Code
    );

    // Test debug sections
    assert_eq!(
        MachoParser::classify_section("__DWARF", "__debug_info"),
        SectionType::Debug
    );

    // Test other sections
    assert_eq!(
        MachoParser::classify_section("__UNKNOWN", "__unknown"),
        SectionType::Other
    );
}

#[test]
fn test_macho_parser_creation() {
    let _parser = MachoParser::new();
    let _default_parser = MachoParser;
    // Verify we can create the parser through both methods
}

#[test]
fn test_segment_section_name_formatting() {
    let segment = "__TEXT";
    let section = "__cstring";
    let expected = "__TEXT,__cstring";
    let actual = MachoParser::format_section_name(segment, section);
    assert_eq!(actual, expected);
}

#[test]
fn test_symbol_classification() {
    use goblin::mach::symbols::Nlist;

    // Test undefined symbol (import)
    let undefined_symbol = Nlist {
        n_strx: 0,
        n_type: 0,
        n_sect: 0,
        n_desc: 0,
        n_value: 0,
    };
    assert!(MachoParser::is_undefined_symbol(&undefined_symbol));
    assert!(!MachoParser::is_defined_symbol(&undefined_symbol));

    // Test defined symbol (export)
    let defined_symbol = Nlist {
        n_strx: 0,
        n_type: 0,
        n_sect: 1,
        n_desc: 0,
        n_value: 0x1000,
    };
    assert!(!MachoParser::is_undefined_symbol(&defined_symbol));
    assert!(MachoParser::is_defined_symbol(&defined_symbol));
}

#[test]
fn test_meaningful_symbol_detection() {
    // Meaningful symbols
    assert!(MachoParser::is_meaningful_symbol("main"));
    assert!(MachoParser::is_meaningful_symbol("_start"));
    assert!(MachoParser::is_meaningful_symbol("function_name"));

    // Non-meaningful symbols
    assert!(!MachoParser::is_meaningful_symbol("_"));
}

#[test]
fn test_section_properties() {
    // Test executable section detection
    assert!(MachoParser::is_executable_section("__TEXT", "__text"));
    assert!(!MachoParser::is_executable_section("__DATA", "__data"));
    assert!(!MachoParser::is_executable_section("__TEXT", "__cstring"));

    // Test writable section detection
    assert!(MachoParser::is_writable_section("__DATA"));
    assert!(MachoParser::is_writable_section("__DATA_DIRTY"));
    assert!(!MachoParser::is_writable_section("__TEXT"));
    assert!(!MachoParser::is_writable_section("__DATA_CONST"));
}

#[test]
fn test_section_weight_calculation() {
    // Test weight calculation for different section types and names
    // Uses the same 1.0-10.0 scale as ELF and PE parsers

    // String data sections should get highest weights
    assert_eq!(
        MachoParser::calculate_section_weight(SectionType::StringData, "__TEXT", "__cstring"),
        10.0
    );
    assert_eq!(
        MachoParser::calculate_section_weight(SectionType::StringData, "__TEXT", "__const"),
        7.0
    );
    assert_eq!(
        MachoParser::calculate_section_weight(
            SectionType::StringData,
            "__DATA_CONST",
            "__cfstring"
        ),
        7.0
    );
    assert_eq!(
        MachoParser::calculate_section_weight(SectionType::StringData, "__TEXT", "__objc_methname"),
        10.0
    );
    assert_eq!(
        MachoParser::calculate_section_weight(
            SectionType::StringData,
            "__TEXT",
            "__objc_classname"
        ),
        10.0
    );
    assert_eq!(
        MachoParser::calculate_section_weight(SectionType::StringData, "__TEXT", "__ustring"),
        7.0
    );

    // Read-only data sections
    assert_eq!(
        MachoParser::calculate_section_weight(SectionType::ReadOnlyData, "__DATA_CONST", "__const"),
        4.0
    );

    // Writable data sections
    assert_eq!(
        MachoParser::calculate_section_weight(SectionType::WritableData, "__DATA", "__data"),
        3.0
    );

    // Code sections should get low weight
    assert_eq!(
        MachoParser::calculate_section_weight(SectionType::Code, "__TEXT", "__text"),
        1.0
    );

    // Debug sections
    assert_eq!(
        MachoParser::calculate_section_weight(SectionType::Debug, "__DWARF", "__debug_info"),
        2.0
    );

    // Other sections
    assert_eq!(
        MachoParser::calculate_section_weight(SectionType::Other, "__UNKNOWN", "__unknown"),
        1.0
    );
}
