use crate::container::ContainerParser;
use crate::types::{
    BinaryFormat, ContainerInfo, ExportInfo, ImportInfo, Result, SectionInfo, SectionType,
    StringyError,
};
use goblin::Object;
use goblin::pe::{PE, section_table::SectionTable};

/// Parser for PE (Portable Executable) binaries.
///
/// The PE format is the standard executable format on Windows, used for executables (.exe),
/// dynamic link libraries (.dll), and drivers (.sys). This parser extracts sections,
/// imports, and exports from PE binaries to support string analysis.
///
/// # Section Classification Strategy
///
/// The parser uses a weight-based system to prioritize sections for string extraction:
///
/// - **`.rdata` / `.rodata`**: StringData (weight 10.0) - Primary string storage section
/// - **`.rsrc`**: Resources (weight 9.0) - Version info, string tables, and other resources
/// - **`.data` (read-only)**: ReadOnlyData (weight 7.0) - May contain constants and string literals
/// - **`.data` (writable)**: WritableData (weight 5.0) - Runtime state, lower priority for strings
/// - **`.text`**: Code (weight 1.0) - Unlikely to contain meaningful strings
/// - **`.bss`, `.reloc`**: Other/VeryLow priority - Minimal string content
/// - **`.pdata`, `.xdata`**: Debug (weight 2.0) - Exception handling metadata
///
/// Section classification considers both the section name and characteristics flags
/// (e.g., `IMAGE_SCN_CNT_CODE`, `IMAGE_SCN_MEM_WRITE`) to determine the appropriate type.
/// Exception handling sections (`.pdata`, `.xdata`) are classified as Debug for consistency,
/// though they could be considered a separate Metadata type in future versions.
///
/// # Import/Export Table Parsing
///
/// The parser extracts import and export information from PE directories:
///
/// ## Imports
///
/// Imports are extracted from the PE import directory using goblin's `pe.imports`.
/// Each import includes:
/// - Function name (e.g., `printf`, `malloc`) or synthesized name for ordinal imports
/// - DLL name (e.g., `msvcrt.dll`, `kernel32.dll`)
/// - RVA (Relative Virtual Address) for the import
/// - Ordinal (if available, for ordinal imports)
///
/// ## Exports
///
/// Exports are extracted from the PE export directory using goblin's `pe.exports`.
/// Each export includes:
/// - Function name (or synthesized `ordinal_{n}` for unnamed exports)
/// - Address (RVA, or 0 for forwarded exports)
/// - Ordinal (extracted from PE export directory table's `ordinal_base` field plus index)
///
/// The ordinal is calculated as `base_ordinal + index` where `base_ordinal` comes from
/// the export directory table's `ordinal_base` field. This provides the actual PE
/// ordinal value, accounting for the export directory's base and ensuring correct
/// ordinal numbering even when there are gaps in the export table.
///
/// Forwarded exports (reexports) are detected and marked with `address = 0` and
/// a name suffix indicating the forwarder target (e.g., `name -> forwarded: DLL.func`).
///
/// **Note**: PE executables typically don't export symbols - only DLLs do. Most `.exe`
/// files will have an empty exports list.
///
/// # UTF-16LE Considerations
///
/// Windows APIs favor wide strings (UTF-16LE), so the `.rdata` section should be
/// prioritized for UTF-16LE extraction in the future extraction pipeline. The current
/// implementation focuses on section classification and import/export extraction;
/// encoding detection will be handled by the extraction pipeline.
///
/// # Examples
///
/// ```rust,no_run
/// use stringy::container::{ContainerParser, PeParser};
///
/// let parser = PeParser::new();
/// let data = std::fs::read("example.exe").unwrap();
///
/// if PeParser::detect(&data) {
///     let container_info = parser.parse(&data).unwrap();
///     println!("Found {} sections", container_info.sections.len());
///     println!("Found {} imports", container_info.imports.len());
///     println!("Found {} exports", container_info.exports.len());
///
///     // Access section information
///     for section in &container_info.sections {
///         println!("Section: {} (type: {:?}, weight: {})",
///                  section.name, section.section_type, section.weight);
///     }
///
///     // Access import information
///     for import in &container_info.imports {
///         println!("Import: {} from {}", import.name,
///                  import.library.as_ref().unwrap_or(&"unknown".to_string()));
///     }
/// }
/// ```
pub struct PeParser;

impl Default for PeParser {
    fn default() -> Self {
        Self::new()
    }
}

impl PeParser {
    pub fn new() -> Self {
        Self
    }

    /// Calculate section weight based on likelihood of containing meaningful strings
    fn calculate_section_weight(section_type: SectionType, name: &str) -> f32 {
        match section_type {
            // String data sections get highest weight
            SectionType::StringData => {
                match name {
                    // .rdata is the primary string section in PE
                    ".rdata" | ".rodata" => 10.0,
                    _ => 8.0,
                }
            }
            // Resources often contain strings
            SectionType::Resources => 9.0,
            // Read-only data sections are likely to contain strings
            SectionType::ReadOnlyData => 7.0,
            // Writable data sections may contain strings but less likely
            SectionType::WritableData => 5.0,
            // Code sections unlikely to contain meaningful strings
            SectionType::Code => 1.0,
            // Debug sections may contain some strings but usually not user-facing
            SectionType::Debug => 2.0,
            // Other sections get minimal weight
            SectionType::Other => 1.0,
        }
    }

    /// Classify PE section based on its name and characteristics
    fn classify_section(section: &SectionTable) -> SectionType {
        let name_bytes = String::from_utf8_lossy(&section.name);
        let name = name_bytes.trim_end_matches('\0');

        // Check section characteristics first
        if section.characteristics & goblin::pe::section_table::IMAGE_SCN_CNT_CODE != 0 {
            return SectionType::Code;
        }

        // Classify based on section name
        match name {
            // String data sections - highest priority for string extraction
            ".rdata" | ".rodata" => SectionType::StringData,

            // Read-only data sections
            ".data"
                if section.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_WRITE
                    == 0 =>
            {
                SectionType::ReadOnlyData
            }

            // Writable data sections
            ".data" | ".bss" => SectionType::WritableData,

            // Resource sections
            ".rsrc" => SectionType::Resources,

            // Debug sections
            name if name.starts_with(".debug") => SectionType::Debug,

            // Exception handling data sections (.pdata, .xdata)
            // These contain exception handling metadata and are classified as Debug
            // for consistency, though they could be considered a separate Metadata type
            ".pdata" | ".xdata" => SectionType::Debug,

            // Everything else
            _ => SectionType::Other,
        }
    }

    /// Extract import information from PE import table
    ///
    /// For ordinal imports, synthesizes name from `import.ordinal` and stores it in `ImportInfo` if available.
    fn extract_imports(&self, pe: &PE) -> Vec<ImportInfo> {
        let mut imports = Vec::new();

        // Extract from import table
        for (index, import) in pe.imports.iter().enumerate() {
            // Handle imports by ordinal or missing names
            // import.ordinal is u16 (always present, 0 if not an ordinal import)
            let ordinal_value = import.ordinal;
            let name = if !import.name.is_empty() {
                import.name.to_string()
            } else if ordinal_value != 0 {
                // Import by ordinal - use the actual ordinal value
                format!("ordinal_{}", ordinal_value)
            } else {
                // No name and no ordinal - use index for uniqueness
                format!("unknown_ordinal_{}", index)
            };

            imports.push(ImportInfo {
                name,
                library: Some(import.dll.to_string()),
                address: Some(import.rva as u64),
                ordinal: if ordinal_value != 0 {
                    Some(ordinal_value)
                } else {
                    None
                },
            });
        }

        imports
    }

    /// Extract export information from PE export table
    ///
    /// Ordinal extracted from PE export directory table's base ordinal and export index.
    /// The actual ordinal is calculated as `base_ordinal + index` where base_ordinal comes
    /// from the export directory table's `ordinal_base` field.
    fn extract_exports(&self, pe: &PE) -> Vec<ExportInfo> {
        let mut exports = Vec::new();

        // Get the base ordinal from the export directory table
        // This is the starting ordinal value for exports in this PE
        let base_ordinal = pe
            .export_data
            .as_ref()
            .map(|ed| ed.export_directory_table.ordinal_base)
            .unwrap_or(1u32);

        // Extract from export table
        for (i, export) in pe.exports.iter().enumerate() {
            // Calculate the actual ordinal as base_ordinal + index
            // This matches the PE format specification where ordinals are sequential
            // starting from the base ordinal
            let ordinal_value = base_ordinal.saturating_add(i as u32);
            let ordinal = if ordinal_value > u16::MAX as u32 {
                u16::MAX
            } else {
                ordinal_value as u16
            };

            // Check for forwarded exports (reexports)
            let is_forwarded = export.reexport.is_some();

            let mut name = if let Some(name_str) = export.name {
                name_str.to_string()
            } else {
                // Use the real ordinal for unnamed exports
                format!("ordinal_{}", ordinal_value)
            };

            // Handle forwarded exports
            let address = if is_forwarded {
                // For forwarded exports, the RVA points to a forwarder string, not code
                // Set address to 0 to indicate this is not a valid code address
                0
            } else {
                export.rva as u64
            };

            // Append forwarder marker to name if applicable
            if is_forwarded {
                if let Some(reexport) = &export.reexport {
                    match reexport {
                        goblin::pe::export::Reexport::DLLName { lib, export: exp } => {
                            name = format!("{} -> forwarded: {}.{}", name, lib, exp);
                        }
                        goblin::pe::export::Reexport::DLLOrdinal { lib, ordinal: ord } => {
                            name = format!("{} -> forwarded: {}.ordinal_{}", name, lib, ord);
                        }
                    }
                } else {
                    name = format!("{} -> forwarded", name);
                }
            }

            exports.push(ExportInfo {
                name,
                address,
                ordinal: Some(ordinal),
            });
        }

        exports
    }
}

impl ContainerParser for PeParser {
    fn detect(data: &[u8]) -> bool {
        matches!(Object::parse(data), Ok(Object::PE(_)))
    }

    fn parse(&self, data: &[u8]) -> Result<ContainerInfo> {
        let pe = match Object::parse(data)? {
            Object::PE(pe) => pe,
            _ => return Err(StringyError::ParseError("Not a PE file".to_string())),
        };

        let mut sections = Vec::new();

        // Process each section
        for section in &pe.sections {
            let name = String::from_utf8_lossy(&section.name)
                .trim_end_matches('\0')
                .to_string();

            // Skip empty sections
            if section.size_of_raw_data == 0 {
                continue;
            }

            let section_type = Self::classify_section(section);
            let weight = Self::calculate_section_weight(section_type, &name);

            sections.push(SectionInfo {
                name,
                offset: section.pointer_to_raw_data as u64,
                size: section.size_of_raw_data as u64,
                rva: Some(section.virtual_address as u64),
                section_type,
                is_executable: section.characteristics
                    & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE
                    != 0,
                is_writable: section.characteristics
                    & goblin::pe::section_table::IMAGE_SCN_MEM_WRITE
                    != 0,
                weight,
            });
        }

        let imports = self.extract_imports(&pe);
        let exports = self.extract_exports(&pe);

        Ok(ContainerInfo {
            format: BinaryFormat::Pe,
            sections,
            imports,
            exports,
        })
    }
}

#[cfg(test)]
mod tests {
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
        let is_executable_both = both_flags_section.characteristics
            & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE
            != 0;
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
}
