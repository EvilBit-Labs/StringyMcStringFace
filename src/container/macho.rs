use crate::container::ContainerParser;
use crate::types::{
    BinaryFormat, ContainerInfo, ExportInfo, ImportInfo, Result, SectionInfo, SectionType,
    StringyError,
};
use goblin::Object;
use goblin::mach::{Mach, MachO};

/// Parser for Mach-O (Mach Object) binaries.
///
/// Supports both single architecture binaries and universal (fat) binaries.
/// Extracts sections, imports, and exports from Mach-O format executables,
/// dynamic libraries, and object files.
///
/// # Examples
///
/// ```rust
/// use stringy::container::{ContainerParser, macho::MachoParser};
///
/// let parser = MachoParser::new();
/// // Example usage (would require actual Mach-O binary data):
/// // let data = std::fs::read("example.dylib")?;
/// // if MachoParser::detect(&data) {
/// //     let container_info = parser.parse(&data)?;
/// //     println!("Found {} sections", container_info.sections.len());
/// // }
/// ```
pub struct MachoParser;

impl Default for MachoParser {
    fn default() -> Self {
        Self::new()
    }
}

impl MachoParser {
    /// Creates a new Mach-O parser instance.
    pub fn new() -> Self {
        Self
    }

    /// Classifies Mach-O section based on its segment and section name.
    ///
    /// Returns the appropriate `SectionType` for string extraction prioritization.
    /// String data sections receive highest priority, followed by read-only data,
    /// then writable data, code, debug info, and finally other sections.
    fn classify_section(segment_name: &str, section_name: &str) -> SectionType {
        use SectionType::*;

        match (segment_name, section_name) {
            // String data sections - highest priority for string extraction
            ("__TEXT", "__cstring") | ("__TEXT", "__const") | ("__DATA_CONST", "__cfstring") => {
                StringData
            }

            // Read-only data sections
            ("__DATA_CONST", _) => ReadOnlyData,

            // Writable data sections
            ("__DATA", _) => WritableData,

            // Executable code sections
            ("__TEXT", "__text") | ("__TEXT", "__stubs") | ("__TEXT", "__stub_helper") => Code,

            // Debug sections
            ("__DWARF", _) => Debug,
            (_, name) if name.starts_with("__debug") => Debug,

            // Everything else
            _ => Other,
        }
    }

    /// Extracts import information from Mach-O dynamic symbol table.
    ///
    /// Identifies undefined symbols (imports) by checking for symbols with
    /// n_sect == 0 and n_value == 0, which indicates external dependencies.
    fn extract_imports(&self, macho: &MachO) -> Vec<ImportInfo> {
        let Some(symbols) = &macho.symbols else {
            return Vec::new();
        };

        symbols
            .iter()
            .flatten()
            .filter_map(|(name, nlist)| {
                // Check if this is an undefined symbol (import)
                if Self::is_undefined_symbol(&nlist) {
                    Some(ImportInfo {
                        name: name.to_string(),
                        library: None, // Mach-O doesn't directly specify library names in symbols
                        address: Some(nlist.n_value),
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    /// Checks if a symbol is undefined (indicating an import).
    fn is_undefined_symbol(nlist: &goblin::mach::symbols::Nlist) -> bool {
        nlist.n_sect == 0 && nlist.n_value == 0
    }

    /// Extracts export information from Mach-O symbol table.
    ///
    /// Identifies defined symbols (exports) and filters out internal symbols
    /// that are unlikely to be meaningful for string analysis.
    fn extract_exports(&self, macho: &MachO) -> Vec<ExportInfo> {
        let Some(symbols) = &macho.symbols else {
            return Vec::new();
        };

        symbols
            .iter()
            .flatten()
            .filter_map(|(name, nlist)| {
                if Self::is_defined_symbol(&nlist) && Self::is_meaningful_symbol(name) {
                    Some(ExportInfo {
                        name: name.to_string(),
                        address: nlist.n_value,
                        ordinal: None, // Mach-O doesn't use ordinals
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    /// Checks if a symbol is defined (indicating an export).
    fn is_defined_symbol(nlist: &goblin::mach::symbols::Nlist) -> bool {
        nlist.n_sect != 0 && nlist.n_value != 0
    }

    /// Determines if a symbol name is meaningful for analysis.
    /// Filters out single-character underscore symbols which are typically internal.
    fn is_meaningful_symbol(name: &str) -> bool {
        !name.starts_with('_') || name.len() > 1
    }

    /// Parses a single Mach-O binary and extracts container information.
    ///
    /// Processes all segments and their sections, extracting metadata needed
    /// for string analysis including section types, addresses, and permissions.
    fn parse_single_macho(&self, macho: &MachO) -> Result<ContainerInfo> {
        let sections = self.extract_sections(macho)?;
        let imports = self.extract_imports(macho);
        let exports = self.extract_exports(macho);

        Ok(ContainerInfo {
            format: BinaryFormat::MachO,
            sections,
            imports,
            exports,
        })
    }

    /// Extracts section information from all segments in the Mach-O binary.
    fn extract_sections(&self, macho: &MachO) -> Result<Vec<SectionInfo>> {
        let mut sections = Vec::new();

        for segment in &macho.segments {
            let segment_name = segment.name().unwrap_or("unknown");

            for (section, _data) in segment.sections()? {
                if let Some(section_info) = self.process_section(segment_name, &section) {
                    sections.push(section_info);
                }
            }
        }

        Ok(sections)
    }

    /// Processes a single section and returns section info if the section is non-empty.
    fn process_section(
        &self,
        segment_name: &str,
        section: &goblin::mach::segment::Section,
    ) -> Option<SectionInfo> {
        // Skip empty sections
        if section.size == 0 {
            return None;
        }

        let section_name = section.name().unwrap_or("unknown");
        let section_type = Self::classify_section(segment_name, section_name);
        let full_name = Self::format_section_name(segment_name, section_name);

        Some(SectionInfo {
            name: full_name,
            offset: section.offset as u64,
            size: section.size,
            rva: Some(section.addr), // Mach-O uses virtual addresses
            section_type,
            is_executable: Self::is_executable_section(segment_name, section_name),
            is_writable: Self::is_writable_section(segment_name),
        })
    }

    /// Formats the full section name as "segment,section".
    fn format_section_name(segment_name: &str, section_name: &str) -> String {
        format!("{},{}", segment_name, section_name)
    }

    /// Determines if a section is executable based on segment and section names.
    fn is_executable_section(segment_name: &str, section_name: &str) -> bool {
        segment_name == "__TEXT" && section_name == "__text"
    }

    /// Determines if a section is writable based on segment name.
    fn is_writable_section(segment_name: &str) -> bool {
        matches!(segment_name, "__DATA" | "__DATA_DIRTY")
    }
}

impl ContainerParser for MachoParser {
    /// Detects if the provided data is a Mach-O binary format.
    ///
    /// Returns `true` if the data can be parsed as either a single Mach-O binary
    /// or a universal (fat) binary containing Mach-O architectures.
    fn detect(data: &[u8]) -> bool {
        matches!(Object::parse(data), Ok(Object::Mach(_)))
    }

    /// Parses Mach-O binary data and extracts container information.
    ///
    /// Supports both single architecture binaries and universal (fat) binaries.
    /// For fat binaries, parses the first available architecture.
    ///
    /// # Errors
    ///
    /// Returns `StringyError::ParseError` if:
    /// - The data is not a valid Mach-O format
    /// - Fat binary parsing fails
    /// - Section parsing encounters errors
    fn parse(&self, data: &[u8]) -> Result<ContainerInfo> {
        let mach = self.parse_mach_object(data)?;

        match mach {
            Mach::Binary(macho) => self.parse_single_macho(&macho),
            Mach::Fat(fat) => self.parse_fat_binary(&fat, data),
        }
    }
}

impl MachoParser {
    /// Parses the raw data into a Mach object.
    fn parse_mach_object<'a>(&self, data: &'a [u8]) -> Result<Mach<'a>> {
        match Object::parse(data)? {
            Object::Mach(mach) => Ok(mach),
            _ => Err(StringyError::ParseError("Not a Mach-O file".to_string())),
        }
    }

    /// Parses a fat (universal) binary by extracting the first architecture.
    ///
    /// TODO: Consider parsing all architectures instead of just the first one
    /// for more comprehensive analysis in future versions.
    fn parse_fat_binary(
        &self,
        fat: &goblin::mach::MultiArch,
        data: &[u8],
    ) -> Result<ContainerInfo> {
        let arch = fat.iter_arches().next().ok_or_else(|| {
            StringyError::ParseError("No architectures found in fat binary".to_string())
        })?;

        let arch = arch?;
        let arch_data = self.extract_architecture_data(&arch, data)?;

        match Object::parse(arch_data)? {
            Object::Mach(Mach::Binary(macho)) => self.parse_single_macho(&macho),
            _ => Err(StringyError::ParseError(
                "Invalid architecture data in fat binary".to_string(),
            )),
        }
    }

    /// Extracts architecture-specific data from a fat binary.
    fn extract_architecture_data<'a>(
        &self,
        arch: &goblin::mach::fat::FatArch,
        data: &'a [u8],
    ) -> Result<&'a [u8]> {
        let offset = arch.offset as usize;
        let size = arch.size as usize;

        if offset + size <= data.len() {
            Ok(&data[offset..offset + size])
        } else {
            Err(StringyError::ParseError(
                "Architecture data extends beyond file bounds".to_string(),
            ))
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
        assert_eq!(
            MachoParser::classify_section("__DATA_CONST", "__cfstring"),
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
}
