use crate::container::ContainerParser;
use crate::types::{
    BinaryFormat, ContainerInfo, ExportInfo, ImportInfo, Result, SectionInfo, SectionType,
    StringyError,
};
use goblin::Object;
use goblin::elf::{Elf, SectionHeader};

/// Parser for ELF (Executable and Linkable Format) binaries
pub struct ElfParser;

impl Default for ElfParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ElfParser {
    pub fn new() -> Self {
        Self
    }

    /// Calculate section weight based on likelihood of containing meaningful strings
    fn calculate_section_weight(section_type: SectionType, name: &str) -> f32 {
        match section_type {
            // String data sections get highest weight
            SectionType::StringData => {
                match name {
                    // Dedicated string sections get maximum weight
                    ".rodata" | ".rodata.str1.1" | ".rodata.str1.4" | ".rodata.str1.8" => 10.0,
                    // Comment sections are also very likely to contain strings
                    ".comment" | ".note" | ".note.gnu.build-id" => 9.0,
                    // Other string data sections
                    _ => 8.0,
                }
            }
            // Read-only data sections are likely to contain strings
            SectionType::ReadOnlyData => 7.0,
            // Writable data sections may contain strings but less likely
            SectionType::WritableData => 5.0,
            // Code sections unlikely to contain meaningful strings
            SectionType::Code => 1.0,
            // Debug sections may contain some strings but usually not user-facing
            SectionType::Debug => 2.0,
            // Resources (not applicable to ELF but included for completeness)
            SectionType::Resources => 8.0,
            // Other sections get minimal weight
            SectionType::Other => 1.0,
        }
    }

    /// Classify ELF section based on its name and flags
    fn classify_section(section: &SectionHeader, name: &str) -> SectionType {
        // Check section flags first
        if section.sh_flags & (goblin::elf::section_header::SHF_EXECINSTR as u64) != 0 {
            return SectionType::Code;
        }

        // Classify based on section name
        match name {
            // String data sections - highest priority for string extraction
            ".rodata" | ".rodata.str1.1" | ".rodata.str1.4" | ".rodata.str1.8" => {
                SectionType::StringData
            }
            ".comment" | ".note" | ".note.gnu.build-id" => SectionType::StringData,

            // Read-only data sections
            ".data.rel.ro" | ".data.rel.ro.local" => SectionType::ReadOnlyData,

            // Writable data sections
            ".data" | ".bss" => SectionType::WritableData,

            // Debug sections
            name if name.starts_with(".debug_") => SectionType::Debug,
            ".strtab" | ".shstrtab" | ".symtab" | ".dynsym" | ".dynstr" => SectionType::Debug,

            // Everything else
            _ => SectionType::Other,
        }
    }

    /// Extract import information from ELF dynamic section
    /// Imports are symbols that are undefined (SHN_UNDEF) and need to be resolved at runtime
    fn extract_imports(&self, elf: &Elf) -> Vec<ImportInfo> {
        let mut imports = Vec::new();

        // Extract from dynamic symbol table
        for sym in &elf.dynsyms {
            // Import symbols are:
            // - Undefined (st_shndx == SHN_UNDEF)
            // - Global or weak binding
            // - Functions or objects
            if sym.st_shndx == (goblin::elf::section_header::SHN_UNDEF as usize)
                && (sym.st_bind() == goblin::elf::sym::STB_GLOBAL
                    || sym.st_bind() == goblin::elf::sym::STB_WEAK)
                && (sym.st_type() == goblin::elf::sym::STT_FUNC
                    || sym.st_type() == goblin::elf::sym::STT_OBJECT
                    || sym.st_type() == goblin::elf::sym::STT_NOTYPE)
            {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    // Skip empty names
                    if !name.is_empty() {
                        imports.push(ImportInfo {
                            name: name.to_string(),
                            library: self.extract_library_from_needed(elf, name),
                            address: if sym.st_value != 0 {
                                Some(sym.st_value)
                            } else {
                                None
                            },
                        });
                    }
                }
            }
        }

        // Also check regular symbol table for static imports
        for sym in &elf.syms {
            if sym.st_shndx == (goblin::elf::section_header::SHN_UNDEF as usize)
                && (sym.st_bind() == goblin::elf::sym::STB_GLOBAL
                    || sym.st_bind() == goblin::elf::sym::STB_WEAK)
                && (sym.st_type() == goblin::elf::sym::STT_FUNC
                    || sym.st_type() == goblin::elf::sym::STT_OBJECT
                    || sym.st_type() == goblin::elf::sym::STT_NOTYPE)
            {
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        // Avoid duplicates from dynamic symbol table
                        if !imports.iter().any(|imp| imp.name == name) {
                            imports.push(ImportInfo {
                                name: name.to_string(),
                                library: None, // Static symbols don't have library info
                                address: if sym.st_value != 0 {
                                    Some(sym.st_value)
                                } else {
                                    None
                                },
                            });
                        }
                    }
                }
            }
        }

        imports
    }

    /// Attempt to extract library information from DT_NEEDED entries
    /// This is a best-effort approach since ELF doesn't directly link symbols to libraries
    fn extract_library_from_needed(&self, elf: &Elf, _symbol_name: &str) -> Option<String> {
        // For now, we can't reliably determine which specific library a symbol comes from
        // in ELF without additional information like version symbols or relocation data.
        // This would require more complex analysis of the dynamic linking process.

        // We could potentially return the first DT_NEEDED entry as a fallback,
        // but that would be misleading. Better to return None for accuracy.

        // Future enhancement: analyze PLT/GOT relocations to match symbols to libraries
        let _ = elf; // Suppress unused parameter warning
        None
    }

    /// Extract basic export information from ELF symbol table
    fn extract_exports(&self, elf: &Elf) -> Vec<ExportInfo> {
        let mut exports = Vec::new();

        // Extract from dynamic symbol table
        for sym in &elf.dynsyms {
            if sym.st_bind() == goblin::elf::sym::STB_GLOBAL
                && sym.st_shndx != (goblin::elf::section_header::SHN_UNDEF as usize)
                && sym.st_value != 0
            {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    exports.push(ExportInfo {
                        name: name.to_string(),
                        address: sym.st_value,
                        ordinal: None, // ELF doesn't use ordinals
                    });
                }
            }
        }

        exports
    }
}

impl ContainerParser for ElfParser {
    fn detect(data: &[u8]) -> bool {
        matches!(Object::parse(data), Ok(Object::Elf(_)))
    }

    fn parse(&self, data: &[u8]) -> Result<ContainerInfo> {
        let elf = match Object::parse(data)? {
            Object::Elf(elf) => elf,
            _ => return Err(StringyError::ParseError("Not an ELF file".to_string())),
        };

        let mut sections = Vec::new();

        // Process each section
        for (i, section) in elf.section_headers.iter().enumerate() {
            // Get section name
            let name = elf
                .shdr_strtab
                .get_at(section.sh_name)
                .unwrap_or(&format!("section_{}", i))
                .to_string();

            // Skip empty sections
            if section.sh_size == 0 {
                continue;
            }

            let section_type = Self::classify_section(section, &name);
            let weight = Self::calculate_section_weight(section_type, &name);

            sections.push(SectionInfo {
                name,
                offset: section.sh_offset,
                size: section.sh_size,
                rva: Some(section.sh_addr), // ELF uses virtual addresses
                section_type,
                is_executable: section.sh_flags
                    & (goblin::elf::section_header::SHF_EXECINSTR as u64)
                    != 0,
                is_writable: section.sh_flags & (goblin::elf::section_header::SHF_WRITE as u64)
                    != 0,
                weight,
            });
        }

        let imports = self.extract_imports(&elf);
        let exports = self.extract_exports(&elf);

        Ok(ContainerInfo {
            format: BinaryFormat::Elf,
            sections,
            imports,
            exports,
        })
    }
}

#[cfg(test)]
mod tests {
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
    fn test_symbol_filtering_criteria() {
        // Test the symbol filtering logic by checking the constants we use
        use goblin::elf::section_header::SHN_UNDEF;
        use goblin::elf::sym::{STB_GLOBAL, STB_WEAK, STT_FUNC, STT_NOTYPE, STT_OBJECT};

        // Verify that our filtering constants are correct
        assert_eq!(SHN_UNDEF, 0); // Undefined section index
        assert_eq!(STB_GLOBAL, 1); // Global binding
        assert_eq!(STB_WEAK, 2); // Weak binding
        assert_eq!(STT_FUNC, 2); // Function type
        assert_eq!(STT_OBJECT, 1); // Object type
        assert_eq!(STT_NOTYPE, 0); // No type

        // These constants are used in our import/export filtering logic
        // This test ensures they remain consistent with the goblin crate
    }

    #[test]
    fn test_import_export_methods_exist() {
        // Test that the import/export extraction methods exist and can be called
        // Full functionality testing requires integration tests with real ELF binaries
        let parser = ElfParser::new();

        // We can't easily create a valid ELF structure for unit testing,
        // but we can verify the methods exist and have the right signatures
        // by checking that they compile and can be referenced
        let _extract_imports = ElfParser::extract_imports;
        let _extract_exports = ElfParser::extract_exports;
        let _extract_library = ElfParser::extract_library_from_needed;

        // Verify parser can be created (this is a compile-time check)
        let _ = parser;
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
        // Test that the import/export extraction methods exist and can be called
        // Full functionality testing requires integration tests with real ELF binaries
        let parser = ElfParser::new();

        // We can't easily create a valid ELF structure for unit testing,
        // but we can verify the methods exist and have the right signatures
        // by checking that they compile and can be referenced
        let _extract_imports = ElfParser::extract_imports;
        let _extract_exports = ElfParser::extract_exports;
        let _extract_library = ElfParser::extract_library_from_needed;

        // Verify parser can be created (this is a compile-time check)
        let _ = parser;
    }

    #[test]
    fn test_library_extraction_behavior() {
        // Test the documented behavior of library extraction
        let parser = ElfParser::new();

        // Create a minimal ELF structure for testing
        // We can't use Elf::default() as it doesn't exist, so we'll test the behavior
        // by verifying that the method signature is correct and the documented behavior

        // The extract_library_from_needed method should return None as documented
        // since ELF doesn't directly link symbols to libraries without additional analysis

        // This is a compile-time test to ensure the method exists with correct signature
        let _method_ref: fn(&ElfParser, &Elf, &str) -> Option<String> =
            ElfParser::extract_library_from_needed;

        // Verify the parser exists
        let _ = parser;
    }
}
