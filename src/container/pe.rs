use crate::container::ContainerParser;
use crate::types::{
    BinaryFormat, ContainerInfo, ExportInfo, ImportInfo, Result, SectionInfo, SectionType,
    StringyError,
};
use goblin::Object;
use goblin::pe::{PE, section_table::SectionTable};

/// Parser for PE (Portable Executable) binaries
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
            ".debug" | ".pdata" | ".xdata" => SectionType::Debug,
            name if name.starts_with(".debug") => SectionType::Debug,

            // Everything else
            _ => SectionType::Other,
        }
    }

    /// Extract import information from PE import table
    fn extract_imports(&self, pe: &PE) -> Vec<ImportInfo> {
        let mut imports = Vec::new();

        // Extract from import table
        for import in &pe.imports {
            imports.push(ImportInfo {
                name: import.name.to_string(),
                library: Some(import.dll.to_string()),
                address: Some(import.rva as u64),
            });
        }

        imports
    }

    /// Extract export information from PE export table
    fn extract_exports(&self, pe: &PE) -> Vec<ExportInfo> {
        let mut exports = Vec::new();

        // Extract from export table
        for (i, export) in pe.exports.iter().enumerate() {
            exports.push(ExportInfo {
                name: export
                    .name
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("ordinal_{}", i)),
                address: export.rva as u64,
                ordinal: Some(i as u16), // Use index as ordinal since goblin doesn't expose it directly
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

            sections.push(SectionInfo {
                name,
                offset: section.pointer_to_raw_data as u64,
                size: section.size_of_raw_data as u64,
                rva: Some(section.virtual_address as u64),
                section_type,
                is_executable: section.characteristics
                    & goblin::pe::section_table::IMAGE_SCN_CNT_CODE
                    != 0,
                is_writable: section.characteristics
                    & goblin::pe::section_table::IMAGE_SCN_MEM_WRITE
                    != 0,
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
}
