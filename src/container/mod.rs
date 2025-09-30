// Container format detection and parsing

use crate::types::{BinaryFormat, ContainerInfo, Result, StringyError};
use goblin::Object;

pub mod elf;
pub mod macho;
pub mod pe;

// Re-export parsers for easier access
pub use elf::ElfParser;
pub use macho::MachoParser;
pub use pe::PeParser;

/// Trait for parsing different container formats
pub trait ContainerParser {
    /// Detect if this parser can handle the given data
    fn detect(data: &[u8]) -> bool
    where
        Self: Sized;

    /// Parse the container and extract metadata
    fn parse(&self, data: &[u8]) -> Result<ContainerInfo>;
}

/// Detect the binary format of the given data
pub fn detect_format(data: &[u8]) -> BinaryFormat {
    match Object::parse(data) {
        Ok(Object::Elf(_)) => BinaryFormat::Elf,
        Ok(Object::PE(_)) => BinaryFormat::Pe,
        Ok(Object::Mach(_)) => BinaryFormat::MachO,
        _ => BinaryFormat::Unknown,
    }
}

/// Create appropriate parser for the detected format
pub fn create_parser(format: BinaryFormat) -> Result<Box<dyn ContainerParser>> {
    match format {
        BinaryFormat::Elf => Ok(Box::new(elf::ElfParser::new())),
        BinaryFormat::Pe => Ok(Box::new(pe::PeParser::new())),
        BinaryFormat::MachO => Ok(Box::new(macho::MachoParser::new())),
        BinaryFormat::Unknown => Err(StringyError::UnsupportedFormat),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_detection() {
        // Test with minimal but valid headers that goblin can recognize

        // Unknown format
        let unknown_data = b"UNKNOWN_FORMAT_DATA";
        assert_eq!(detect_format(unknown_data), BinaryFormat::Unknown);

        // For now, we'll just test that the function doesn't panic
        // Real binary format detection would require actual binary files
        // which would be better tested in integration tests
    }

    #[test]
    fn test_parser_creation() {
        // Test successful parser creation
        assert!(create_parser(BinaryFormat::Elf).is_ok());
        assert!(create_parser(BinaryFormat::Pe).is_ok());
        assert!(create_parser(BinaryFormat::MachO).is_ok());

        // Test error for unknown format
        assert!(create_parser(BinaryFormat::Unknown).is_err());
    }
}
