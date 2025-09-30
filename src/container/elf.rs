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

    /// Extract basic import information from ELF dynamic section
    fn extract_imports(&self, elf: &Elf) -> Vec<ImportInfo> {
        let mut imports = Vec::new();

        // Extract from dynamic symbol table
        for sym in &elf.dynsyms {
            if sym.st_bind() == goblin::elf::sym::STB_GLOBAL
                && sym.st_type() == goblin::elf::sym::STT_FUNC
                && sym.st_shndx == (goblin::elf::section_header::SHN_UNDEF as usize)
            {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    imports.push(ImportInfo {
                        name: name.to_string(),
                        library: None, // ELF doesn't directly specify library names in symbols
                        address: Some(sym.st_value),
                    });
                }
            }
        }

        imports
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
        use goblin::elf::section_header::{SHF_EXECINSTR, SectionHeader};

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
            ElfParser::classify_section(&data_section, ".comment"),
            SectionType::StringData
        );

        // Test read-only data sections
        assert_eq!(
            ElfParser::classify_section(&data_section, ".data.rel.ro"),
            SectionType::ReadOnlyData
        );

        // Test writable data sections
        assert_eq!(
            ElfParser::classify_section(&data_section, ".data"),
            SectionType::WritableData
        );

        // Test debug sections
        assert_eq!(
            ElfParser::classify_section(&data_section, ".debug_info"),
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
}
