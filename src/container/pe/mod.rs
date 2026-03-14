use crate::container::ContainerParser;
use crate::extraction::pe_resources;
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
    /// Creates a new PE parser instance.
    #[must_use]
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

            let mut import_info = ImportInfo::new(name)
                .with_library(import.dll.to_string())
                .with_address(import.rva as u64);
            if ordinal_value != 0 {
                import_info = import_info.with_ordinal(ordinal_value);
            }
            imports.push(import_info);
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

            exports.push(ExportInfo::new(name, address).with_ordinal(ordinal));
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
        self.parse_from(&pe, data)
    }
}

impl PeParser {
    /// Parse from an already-parsed goblin PE object (avoids double-parse).
    pub fn parse_from(&self, pe: &PE, data: &[u8]) -> Result<ContainerInfo> {
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

            sections.push(
                SectionInfo::new(
                    name,
                    section.pointer_to_raw_data as u64,
                    section.size_of_raw_data as u64,
                    section_type,
                    weight,
                )
                .with_rva(section.virtual_address as u64)
                .with_executable(
                    section.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE != 0,
                )
                .with_writable(
                    section.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_WRITE != 0,
                ),
            );
        }

        let imports = self.extract_imports(pe);
        let exports = self.extract_exports(pe);

        // Use pelite for resource extraction while goblin handles sections/imports/exports
        let resources = {
            let resource_metadata = pe_resources::extract_resources(data);
            if !resource_metadata.is_empty() {
                Some(resource_metadata)
            } else {
                None // Empty vector - no resources found
            }
        };

        Ok(ContainerInfo::new(
            BinaryFormat::Pe,
            sections,
            imports,
            exports,
            resources,
        ))
    }
}

#[cfg(test)]
mod tests;
