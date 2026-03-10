//! Constructors and builder methods for container-related types

use super::{
    ContainerInfo, ExportInfo, ImportInfo, ResourceMetadata, ResourceStringEntry,
    ResourceStringTable, ResourceType, SectionInfo, SectionType,
};

impl ContainerInfo {
    /// Create a new `ContainerInfo` instance
    ///
    /// This constructor should be used instead of struct literals to ensure
    /// all fields are properly initialized, especially when new fields are added.
    pub fn new(
        format: super::BinaryFormat,
        sections: Vec<SectionInfo>,
        imports: Vec<ImportInfo>,
        exports: Vec<ExportInfo>,
        resources: Option<Vec<ResourceMetadata>>,
    ) -> Self {
        Self {
            format,
            sections,
            imports,
            exports,
            resources,
        }
    }
}

impl SectionInfo {
    /// Create a new `SectionInfo` instance
    #[must_use]
    pub fn new(
        name: String,
        offset: u64,
        size: u64,
        section_type: SectionType,
        weight: f32,
    ) -> Self {
        Self {
            name,
            offset,
            size,
            rva: None,
            section_type,
            is_executable: false,
            is_writable: false,
            weight,
        }
    }

    /// Sets the Relative Virtual Address
    #[must_use]
    pub fn with_rva(mut self, rva: u64) -> Self {
        self.rva = Some(rva);
        self
    }

    /// Sets the executable flag
    #[must_use]
    pub fn with_executable(mut self, is_executable: bool) -> Self {
        self.is_executable = is_executable;
        self
    }

    /// Sets the writable flag
    #[must_use]
    pub fn with_writable(mut self, is_writable: bool) -> Self {
        self.is_writable = is_writable;
        self
    }
}

impl ImportInfo {
    /// Create a new `ImportInfo` instance
    #[must_use]
    pub fn new(name: String) -> Self {
        Self {
            name,
            library: None,
            address: None,
            ordinal: None,
        }
    }

    /// Sets the library name
    #[must_use]
    pub fn with_library(mut self, library: String) -> Self {
        self.library = Some(library);
        self
    }

    /// Sets the address
    #[must_use]
    pub fn with_address(mut self, address: u64) -> Self {
        self.address = Some(address);
        self
    }

    /// Sets the ordinal
    #[must_use]
    pub fn with_ordinal(mut self, ordinal: u16) -> Self {
        self.ordinal = Some(ordinal);
        self
    }
}

impl ExportInfo {
    /// Create a new `ExportInfo` instance
    #[must_use]
    pub fn new(name: String, address: u64) -> Self {
        Self {
            name,
            address,
            ordinal: None,
        }
    }

    /// Sets the ordinal
    #[must_use]
    pub fn with_ordinal(mut self, ordinal: u16) -> Self {
        self.ordinal = Some(ordinal);
        self
    }
}

impl ResourceMetadata {
    /// Create a new `ResourceMetadata` instance
    #[must_use]
    pub fn new(resource_type: ResourceType, language: u32, data_size: usize) -> Self {
        Self {
            resource_type,
            language,
            data_size,
            offset: None,
        }
    }

    /// Sets the file offset
    #[must_use]
    pub fn with_offset(mut self, offset: u64) -> Self {
        self.offset = Some(offset);
        self
    }
}

impl ResourceStringTable {
    /// Create a new `ResourceStringTable` instance
    #[must_use]
    pub fn new(language: u32, entries: Vec<ResourceStringEntry>) -> Self {
        Self { language, entries }
    }
}

impl ResourceStringEntry {
    /// Create a new `ResourceStringEntry` instance
    #[must_use]
    pub fn new(id: u32, value: String) -> Self {
        Self { id, value }
    }
}
