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
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Calculate section weight based on likelihood of containing meaningful strings
    ///
    /// Uses the same 1.0-10.0 scale as ELF and PE parsers for consistent ranking
    /// across formats.
    fn calculate_section_weight(
        section_type: SectionType,
        segment_name: &str,
        section_name: &str,
    ) -> f32 {
        match section_type {
            // String data sections get highest weight
            SectionType::StringData => {
                match (segment_name, section_name) {
                    // __cstring is the primary string section in Mach-O
                    ("__TEXT", "__cstring") => 10.0,
                    // Objective-C method names - high priority identifiers
                    ("__TEXT", "__objc_methname") => 10.0,
                    // Objective-C class names - high priority identifiers
                    ("__TEXT", "__objc_classname") => 10.0,
                    // __const may contain string constants
                    ("__TEXT", "__const") => 7.0,
                    // Unicode string literals
                    ("__TEXT", "__ustring") => 7.0,
                    // Core Foundation strings
                    ("__DATA_CONST", "__cfstring") => 7.0,
                    _ => 7.0,
                }
            }
            // Read-only data sections are likely to contain strings
            SectionType::ReadOnlyData => 4.0,
            // Writable data sections may contain strings but less likely
            SectionType::WritableData => 3.0,
            // Code sections unlikely to contain meaningful strings
            SectionType::Code => 1.0,
            // Debug sections may contain some strings but usually not user-facing
            SectionType::Debug => 2.0,
            // Resources (not applicable to Mach-O but included for completeness)
            SectionType::Resources => 7.0,
            // Other sections get minimal weight
            SectionType::Other => 1.0,
        }
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
            ("__TEXT", "__cstring")
            | ("__TEXT", "__const")
            | ("__DATA_CONST", "__cfstring")
            | ("__TEXT", "__objc_methname")
            | ("__TEXT", "__objc_classname")
            | ("__TEXT", "__ustring") => StringData,

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
                    Some(ImportInfo::new(name.to_string()).with_address(nlist.n_value))
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
                    Some(ExportInfo::new(name.to_string(), nlist.n_value))
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
        // TODO: Load command strings will be integrated into the main extraction pipeline
        // once it's built. Use `stringy::extraction::extract_load_command_strings()` when ready.

        Ok(ContainerInfo::new(
            BinaryFormat::MachO,
            sections,
            imports,
            exports,
            None,
        ))
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
        let weight = Self::calculate_section_weight(section_type, segment_name, section_name);
        let full_name = Self::format_section_name(segment_name, section_name);

        Some(
            SectionInfo::new(
                full_name,
                section.offset as u64,
                section.size,
                section_type,
                weight,
            )
            .with_rva(section.addr)
            .with_executable(Self::is_executable_section(segment_name, section_name))
            .with_writable(Self::is_writable_section(segment_name)),
        )
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
mod tests;
