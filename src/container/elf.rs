use crate::container::ContainerParser;
use crate::types::{
    BinaryFormat, ContainerInfo, ExportInfo, ImportInfo, Result, SectionInfo, SectionType,
    StringyError,
};
use goblin::Object;
use goblin::elf::{Elf, SectionHeader};
use std::collections::HashSet;

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
    fn extract_imports(&self, elf: &Elf, libraries: &[String]) -> Vec<ImportInfo> {
        let mut imports = Vec::new();
        let mut seen_names = HashSet::new();

        // Extract from dynamic symbol table
        for (sym_index, sym) in elf.dynsyms.iter().enumerate() {
            // Import symbols are:
            // - Undefined (st_shndx == SHN_UNDEF)
            // - Global or weak binding
            // - Functions, objects, TLS variables, or IFuncs
            if sym.st_shndx == (goblin::elf::section_header::SHN_UNDEF as usize)
                && (sym.st_bind() == goblin::elf::sym::STB_GLOBAL
                    || sym.st_bind() == goblin::elf::sym::STB_WEAK)
                && (sym.st_type() == goblin::elf::sym::STT_FUNC
                    || sym.st_type() == goblin::elf::sym::STT_OBJECT
                    || sym.st_type() == goblin::elf::sym::STT_TLS
                    || sym.st_type() == goblin::elf::sym::STT_GNU_IFUNC
                    || sym.st_type() == goblin::elf::sym::STT_NOTYPE)
                && let Some(name) = elf.dynstrtab.get_at(sym.st_name)
                && !name.is_empty()
                && seen_names.insert(name.to_string())
            {
                imports.push(ImportInfo {
                    name: name.to_string(),
                    library: self.get_symbol_providing_library(elf, sym_index, libraries),
                    address: if sym.st_value != 0 {
                        Some(sym.st_value)
                    } else {
                        None
                    },
                    ordinal: None, // ELF doesn't use ordinals
                });
            }
        }

        // Also check regular symbol table for static imports
        for sym in &elf.syms {
            if sym.st_shndx == (goblin::elf::section_header::SHN_UNDEF as usize)
                && (sym.st_bind() == goblin::elf::sym::STB_GLOBAL
                    || sym.st_bind() == goblin::elf::sym::STB_WEAK)
                && (sym.st_type() == goblin::elf::sym::STT_FUNC
                    || sym.st_type() == goblin::elf::sym::STT_OBJECT
                    || sym.st_type() == goblin::elf::sym::STT_TLS
                    || sym.st_type() == goblin::elf::sym::STT_GNU_IFUNC
                    || sym.st_type() == goblin::elf::sym::STT_NOTYPE)
                && let Some(name) = elf.strtab.get_at(sym.st_name)
                && !name.is_empty()
                && seen_names.insert(name.to_string())
            {
                imports.push(ImportInfo {
                    name: name.to_string(),
                    library: None, // Static symbols don't have library info
                    address: if sym.st_value != 0 {
                        Some(sym.st_value)
                    } else {
                        None
                    },
                    ordinal: None, // ELF doesn't use ordinals
                });
            }
        }

        imports
    }

    /// Extract DT_NEEDED entries (library dependencies) from ELF dynamic section
    ///
    /// Returns a list of required shared library names that the binary depends on.
    /// These are used in conjunction with version information to map symbols to their
    /// providing libraries.
    fn extract_needed_libraries(&self, elf: &Elf) -> Vec<String> {
        if let Some(ref dynamic) = elf.dynamic {
            dynamic
                .get_libraries(&elf.dynstrtab)
                .iter()
                .map(|&s| s.to_string())
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get the library that provides a symbol using version information
    /// This is a best-effort approach using versym and verneed tables
    fn get_symbol_providing_library(
        &self,
        elf: &Elf,
        sym_index: usize,
        libraries: &[String],
    ) -> Option<String> {
        // If no libraries are available, return None
        if libraries.is_empty() {
            return None;
        }

        // Try to resolve version information for this symbol
        if let Some(version_index) = self.resolve_versym(elf, sym_index) {
            // Version index 0 (VER_NDX_LOCAL) and 1 (VER_NDX_GLOBAL) are special
            // and don't correspond to specific libraries
            if version_index >= 2
                && let Some((library_name, _version_name)) =
                    self.parse_verneed_entry(elf, version_index)
            {
                // Match the library name from verneed with DT_NEEDED entries
                for lib in libraries {
                    if lib.contains(&library_name) || library_name.contains(lib) {
                        return Some(lib.clone());
                    }
                }
                // If exact match not found, return the library name from verneed
                return Some(library_name);
            }
        }

        // Fallback: For common libc symbols, attribute to first libc library found
        // This is a heuristic and may not always be accurate
        if let Some(libc_lib) = libraries.iter().find(|lib| {
            lib.contains("libc") || lib.contains("libSystem") || lib.contains("libc.so")
        }) {
            return Some(libc_lib.clone());
        }

        // Last resort: return first library (least accurate)
        if libraries.len() == 1 {
            return Some(libraries[0].clone());
        }

        None
    }

    /// Resolve version symbol index from versym table
    fn resolve_versym(&self, elf: &Elf, sym_index: usize) -> Option<u16> {
        // Check if versym table exists and has entry for this symbol
        let versym = elf.versym.as_ref()?;
        if versym.is_empty() || sym_index >= versym.len() {
            return None;
        }

        if let Some(versym_entry) = versym.get_at(sym_index) {
            let version_index = versym_entry.vs_val;
            // VER_NDX_LOCAL (0) and VER_NDX_GLOBAL (1) are special values
            // that don't correspond to versioned symbols
            if version_index >= 2 {
                return Some(version_index);
            }
        }

        None
    }

    /// Parse verneed entry to extract library name and version name
    /// Returns (library_name, version_name) if found
    fn parse_verneed_entry(&self, elf: &Elf, version_index: u16) -> Option<(String, String)> {
        let verneed = elf.verneed.as_ref()?;

        // Iterate through verneed entries to find the one matching version_index
        for verneed_entry in verneed.iter() {
            // Extract library name from verneed entry
            let library_name = elf
                .dynstrtab
                .get_at(verneed_entry.vn_file)
                .unwrap_or("")
                .to_string();

            // Check auxiliary versions in this verneed entry
            for aux in verneed_entry.iter() {
                if aux.vna_other == version_index {
                    // Found matching version, extract version name
                    let version_name = elf.dynstrtab.get_at(aux.vna_name).unwrap_or("").to_string();
                    return Some((library_name, version_name));
                }
            }
        }

        None
    }

    /// Extract basic export information from ELF symbol table
    fn extract_exports(&self, elf: &Elf) -> Vec<ExportInfo> {
        let mut exports = Vec::new();
        let mut seen_names = HashSet::new();

        // Extract from dynamic symbol table
        for sym in &elf.dynsyms {
            // Export symbols must be:
            // - Defined (not SHN_UNDEF)
            // - Global or weak binding
            // - Visible (not hidden or internal)
            // - Have a valid address
            if (sym.st_bind() == goblin::elf::sym::STB_GLOBAL
                || sym.st_bind() == goblin::elf::sym::STB_WEAK)
                && sym.st_shndx != (goblin::elf::section_header::SHN_UNDEF as usize)
                && sym.st_value != 0
                && sym.st_visibility() != goblin::elf::sym::STV_HIDDEN
                && sym.st_visibility() != goblin::elf::sym::STV_INTERNAL
                && let Some(name) = elf.dynstrtab.get_at(sym.st_name)
                && !name.is_empty()
                && seen_names.insert(name.to_string())
            {
                exports.push(ExportInfo {
                    name: name.to_string(),
                    address: sym.st_value,
                    ordinal: None, // ELF doesn't use ordinals
                });
            }
        }

        // Also check regular symbol table for static exports
        for sym in &elf.syms {
            if (sym.st_bind() == goblin::elf::sym::STB_GLOBAL
                || sym.st_bind() == goblin::elf::sym::STB_WEAK)
                && sym.st_shndx != (goblin::elf::section_header::SHN_UNDEF as usize)
                && sym.st_value != 0
                && sym.st_visibility() != goblin::elf::sym::STV_HIDDEN
                && sym.st_visibility() != goblin::elf::sym::STV_INTERNAL
                && (sym.st_type() == goblin::elf::sym::STT_FUNC
                    || sym.st_type() == goblin::elf::sym::STT_OBJECT
                    || sym.st_type() == goblin::elf::sym::STT_TLS
                    || sym.st_type() == goblin::elf::sym::STT_GNU_IFUNC
                    || sym.st_type() == goblin::elf::sym::STT_NOTYPE)
                && let Some(name) = elf.strtab.get_at(sym.st_name)
                && !name.is_empty()
                && seen_names.insert(name.to_string())
            {
                exports.push(ExportInfo {
                    name: name.to_string(),
                    address: sym.st_value,
                    ordinal: None, // ELF doesn't use ordinals
                });
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

        let libraries = self.extract_needed_libraries(&elf);
        let imports = self.extract_imports(&elf, &libraries);
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

        // The get_symbol_providing_library method uses version information to map symbols
        // to libraries, which is a best-effort approach

        // This is a compile-time test to ensure the methods exist with correct signatures
        let _method_ref: fn(&ElfParser, &Elf, usize, &[String]) -> Option<String> =
            ElfParser::get_symbol_providing_library;

        // Verify the parser exists
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
}
