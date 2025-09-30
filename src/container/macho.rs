use crate::container::ContainerParser;
use crate::types::{
    BinaryFormat, ContainerInfo, ExportInfo, ImportInfo, Result, SectionInfo, SectionType,
    StringyError,
};
use goblin::Object;
use goblin::mach::{Mach, MachO};

/// Parser for Mach-O (Mach Object) binaries
pub struct MachoParser;

impl Default for MachoParser {
    fn default() -> Self {
        Self::new()
    }
}

impl MachoParser {
    pub fn new() -> Self {
        Self
    }

    /// Classify Mach-O section based on segment and section names
    fn classify_section(segment_name: &str, section_name: &str) -> SectionType {
        match (segment_name, section_name) {
            // String data sections - highest priority for string extraction
            ("__TEXT", "__cstring") => SectionType::StringData,
            ("__TEXT", "__const") => SectionType::StringData,
            ("__DATA_CONST", _) => SectionType::ReadOnlyData,

            // Writable data sections
            ("__DATA", _) => SectionType::WritableData,

            // Code sections
            ("__TEXT", "__text") => SectionType::Code,
            ("__TEXT", "__stubs") => SectionType::Code,
            ("__TEXT", "__stub_helper") => SectionType::Code,

            // Debug sections
            ("__DWARF", _) => SectionType::Debug,
            (_, name) if name.starts_with("__debug") => SectionType::Debug,

            // Everything else
            _ => SectionType::Other,
        }
    }

    /// Extract import information from Mach-O dynamic symbol table
    fn extract_imports(&self, macho: &MachO) -> Vec<ImportInfo> {
        let mut imports = Vec::new();

        // Extract from dynamic symbol table
        if let Some(symbols) = &macho.symbols {
            for (name, nlist) in symbols.iter().flatten() {
                // Check if it's an undefined symbol (import)
                if nlist.n_sect == 0 && nlist.n_value == 0 {
                    imports.push(ImportInfo {
                        name: name.to_string(),
                        library: None, // Mach-O doesn't directly specify library names in symbols
                        address: Some(nlist.n_value),
                    });
                }
            }
        }

        imports
    }

    /// Extract export information from Mach-O symbol table
    fn extract_exports(&self, macho: &MachO) -> Vec<ExportInfo> {
        let mut exports = Vec::new();

        // Extract from symbol table
        if let Some(symbols) = &macho.symbols {
            for (name, nlist) in symbols.iter().flatten() {
                // Check if it's a defined symbol (export)
                if nlist.n_sect != 0 && nlist.n_value != 0 {
                    // Check if it's externally visible
                    if nlist.n_type & goblin::mach::symbols::N_EXT != 0 {
                        exports.push(ExportInfo {
                            name: name.to_string(),
                            address: nlist.n_value,
                            ordinal: None, // Mach-O doesn't use ordinals
                        });
                    }
                }
            }
        }

        exports
    }

    /// Parse a single Mach-O binary
    fn parse_single_macho(&self, macho: &MachO) -> Result<ContainerInfo> {
        let mut sections = Vec::new();

        // Process each segment and its sections
        for segment in &macho.segments {
            let segment_name = segment.name().unwrap_or("unknown");

            for (section, _data) in segment.into_iter().flatten() {
                let section_name = section.name().unwrap_or("unknown");

                // Skip empty sections
                if section.size == 0 {
                    continue;
                }

                let section_type = Self::classify_section(segment_name, section_name);

                sections.push(SectionInfo {
                    name: format!("{},{}", segment_name, section_name),
                    offset: section.offset as u64,
                    size: section.size,
                    rva: Some(section.addr), // Mach-O uses virtual addresses
                    section_type,
                    is_executable: segment_name == "__TEXT" && section_name == "__text",
                    is_writable: segment_name == "__DATA" || segment_name == "__DATA_DIRTY",
                });
            }
        }

        let imports = self.extract_imports(macho);
        let exports = self.extract_exports(macho);

        Ok(ContainerInfo {
            format: BinaryFormat::MachO,
            sections,
            imports,
            exports,
        })
    }
}

impl ContainerParser for MachoParser {
    fn detect(data: &[u8]) -> bool {
        matches!(Object::parse(data), Ok(Object::Mach(_)))
    }

    fn parse(&self, data: &[u8]) -> Result<ContainerInfo> {
        let mach = match Object::parse(data)? {
            Object::Mach(mach) => mach,
            _ => return Err(StringyError::ParseError("Not a Mach-O file".to_string())),
        };

        match mach {
            Mach::Binary(macho) => self.parse_single_macho(&macho),
            Mach::Fat(fat) => {
                // For fat binaries, parse the first architecture
                // In a more complete implementation, we might want to parse all architectures
                if let Some(Ok(_arch)) = fat.iter_arches().next() {
                    // For now, just return an error as we need the actual binary data
                    // In a full implementation, we'd need to extract the architecture data
                    return Err(StringyError::ParseError(
                        "Fat binary parsing not fully implemented".to_string(),
                    ));
                }
                Err(StringyError::ParseError(
                    "No valid architecture found in fat binary".to_string(),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
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
        // Just verify we can create the parser
        // Test passes - basic functionality verified
    }
}
