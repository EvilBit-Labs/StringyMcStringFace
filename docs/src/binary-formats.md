# Binary Format Support

Stringy supports the three major executable formats across different platforms. Each format has unique characteristics that influence string extraction strategies.

## ELF (Executable and Linkable Format)

Used primarily on Linux and other Unix-like systems.

### Key Sections for String Extraction

| Section          | Priority | Description                                    |
| ---------------- | -------- | ---------------------------------------------- |
| `.rodata`        | High     | Read-only data, often contains string literals |
| `.rodata.str1.1` | High     | Aligned string literals                        |
| `.data.rel.ro`   | Medium   | Read-only after relocation                     |
| `.comment`       | Medium   | Compiler and build information                 |
| `.note.*`        | Low      | Various metadata notes                         |

### ELF-Specific Features

- **Symbol Tables**: Extract import/export names from `.dynsym` and `.symtab`
- **Dynamic Strings**: Process `.dynstr` for library names and symbols
- **Section Flags**: Use `SHF_EXECINSTR` and `SHF_WRITE` for classification
- **Virtual Addresses**: Map file offsets to runtime addresses
- **Dynamic Linking**: Parse `DT_NEEDED` entries to extract library dependencies
- **Symbol Types**: Support for functions (STT_FUNC), objects (STT_OBJECT), TLS variables (STT_TLS), and indirect functions (STT_GNU_IFUNC)
- **Symbol Visibility**: Filter hidden and internal symbols from exports (STV_HIDDEN, STV_INTERNAL)

### Enhanced Symbol Extraction

The ELF parser now provides comprehensive symbol extraction with:

1. **Import Detection**: Identifies all undefined symbols (SHN_UNDEF) that need runtime resolution

   - Supports multiple symbol types: functions, objects, TLS variables, and indirect functions
   - Handles both global and weak bindings
   - Maps symbols to their providing libraries using version information

2. **Export Detection**: Extracts all globally visible defined symbols

   - Filters out hidden (STV_HIDDEN) and internal (STV_INTERNAL) symbols
   - Includes both strong and weak symbols
   - Supports all relevant symbol types

3. **Library Dependencies**: Extracts DT_NEEDED entries from the dynamic section

   - Provides list of required shared libraries
   - Used in conjunction with version information for symbol-to-library mapping

4. **Symbol-to-Library Mapping**: Maps imported symbols to their providing libraries

   - Uses ELF version tables (versym and verneed) for best-effort attribution
   - Process: versym index → verneed entry → library filename
   - Falls back to heuristics for unversioned symbols (e.g., common libc symbols)
   - Returns `None` when version information is unavailable or ambiguous

### Implementation Details

```rust
impl ElfParser {
    fn classify_section(section: &SectionHeader, name: &str) -> SectionType {
        // Check executable flag first
        if section.sh_flags & SHF_EXECINSTR != 0 {
            return SectionType::Code;
        }

        // Classify by name patterns
        match name {
            ".rodata" | ".rodata.str1.1" => SectionType::StringData,
            ".data.rel.ro" => SectionType::ReadOnlyData,
            // ... more classifications
        }
    }

    fn extract_imports(&self, elf: &Elf, libraries: &[String]) -> Vec<ImportInfo> {
        // Extract undefined symbols from dynamic symbol table
        // Supports STT_FUNC, STT_OBJECT, STT_TLS, STT_GNU_IFUNC, STT_NOTYPE
        // Handles both STB_GLOBAL and STB_WEAK bindings
        // Maps symbols to libraries using version information
    }

    fn extract_exports(&self, elf: &Elf) -> Vec<ExportInfo> {
        // Extract defined symbols with global/weak binding
        // Filters out STV_HIDDEN and STV_INTERNAL symbols
        // Includes all relevant symbol types
    }

    fn extract_needed_libraries(&self, elf: &Elf) -> Vec<String> {
        // Parse DT_NEEDED entries from dynamic section
        // Returns list of required shared library names
    }

    fn get_symbol_providing_library(
        &self,
        elf: &Elf,
        sym_index: usize,
        libraries: &[String],
    ) -> Option<String> {
        // 1. Get version index from versym table for this symbol
        // 2. Look up version in verneed to find library name
        // 3. Match with DT_NEEDED entries
        // 4. Fallback to heuristics for unversioned symbols
    }
}
```

### Library Dependency Mapping

The ELF parser implements symbol-to-library mapping using ELF version information:

1. **Version Symbol Table (versym)**: Maps each dynamic symbol to a version index

   - Index 0 (VER_NDX_LOCAL): Local symbol, not available externally
   - Index 1 (VER_NDX_GLOBAL): Global symbol, no specific version
   - Index ≥ 2: Versioned symbol, references verneed entry

2. **Version Needed Table (verneed)**: Lists library dependencies with version requirements

   - Each entry contains a library filename (from DT_NEEDED)
   - Auxiliary entries specify version names and indices
   - Links version indices to specific libraries

3. **Mapping Process**:

   ```
   Symbol → versym[sym_index] → version_index → verneed lookup → library_name
   ```

4. **Fallback Strategies**:

   - For unversioned symbols: Attempt to match common symbols (e.g., `printf`, `malloc`) to libc
   - If only one library is needed: Attribute to that library (least accurate)
   - Otherwise: Return `None` to avoid false positives

### Limitations

ELF's indirect linking model means symbol-to-library mapping is best-effort:

- **Accuracy**: Version-based mapping is accurate when version information is present, but many binaries lack version info
- **Unversioned Symbols**: Symbols without version information cannot be definitively mapped without relocation analysis
- **Relocation Tables**: PLT/GOT relocations would provide definitive mapping but require complex analysis
- **Static Linking**: Statically linked binaries have no dynamic section, so all imports have `library: None`
- **Stripped Binaries**: Stripped binaries may lack symbol tables entirely

The current implementation is sufficient for most string classification use cases where approximate library attribution is acceptable.

## PE (Portable Executable)

Used on Windows for executables, DLLs, and drivers.

### Key Sections for String Extraction

| Section  | Priority | Description                             |
| -------- | -------- | --------------------------------------- |
| `.rdata` | High     | Read-only data section                  |
| `.rsrc`  | High     | Resources (version info, strings, etc.) |
| `.data`  | Medium   | Initialized data (check write flag)     |
| `.text`  | Low      | Code section (imports/exports only)     |

### PE-Specific Features

- **Resources**: Extract from `VERSIONINFO`, `STRINGTABLE`, and manifest resources
- **Import/Export Tables**: Process IAT and EAT for symbol names
- **UTF-16 Prevalence**: Windows APIs favor wide strings
- **Section Characteristics**: Use `IMAGE_SCN_*` flags for classification

### Enhanced Import/Export Extraction

The PE parser provides comprehensive import/export extraction:

1. **Import Extraction**: Extracts from PE import directory using goblin's `pe.imports`

   - Each import includes: function name, DLL name, and RVA
   - Example: `printf` from `msvcrt.dll`
   - Iterates through `pe.imports` to create `ImportInfo` with name, library (DLL), and address (RVA)

2. **Export Extraction**: Extracts from PE export directory using goblin's `pe.exports`

   - Each export includes: function name, address, and ordinal
   - Note: PE executables typically don't export symbols (only DLLs do)
   - Ordinal is derived from index since goblin doesn't expose it directly
   - Handles unnamed exports with "ordinal\_{i}" naming

### Resource Extraction

PE resources are particularly rich sources of strings:

- **VERSIONINFO**: Product names, descriptions, copyright
- **STRINGTABLE**: Localized UI strings
- **RT_MANIFEST**: Application manifests with metadata
- **RT_VERSION**: Version information blocks

### Implementation Details

```rust
impl PeParser {
    fn classify_section(section: &SectionTable) -> SectionType {
        let name = String::from_utf8_lossy(&section.name);

        // Check characteristics
        if section.characteristics & IMAGE_SCN_CNT_CODE != 0 {
            return SectionType::Code;
        }

        match name.trim_end_matches('\0') {
            ".rdata" => SectionType::StringData,
            ".rsrc" => SectionType::Resources,
            // ... more classifications
        }
    }

    fn extract_imports(&self, pe: &PE) -> Vec<ImportInfo> {
        // Iterates through pe.imports
        // Creates ImportInfo with name, library (DLL), and address (RVA)
    }

    fn extract_exports(&self, pe: &PE) -> Vec<ExportInfo> {
        // Iterates through pe.exports
        // Creates ExportInfo with name, address, and ordinal
        // Handles unnamed exports with "ordinal_{i}" naming
    }

    fn calculate_section_weight(section_type: SectionType, name: &str) -> f32 {
        // Returns weight values based on section type and name
        // Higher weights indicate higher string likelihood
    }
}
```

### Section Weight Calculation

The PE parser uses a weight-based system to prioritize sections for string extraction:

| Section Type         | Weight | Rationale                     |
| -------------------- | ------ | ----------------------------- |
| StringData (.rdata)  | 10.0   | Primary string storage        |
| Resources (.rsrc)    | 9.0    | Version info, string tables   |
| ReadOnlyData         | 7.0    | May contain constants         |
| WritableData (.data) | 5.0    | Runtime state, lower priority |
| Code (.text)         | 1.0    | Unlikely to contain strings   |
| Debug                | 2.0    | Internal metadata             |
| Other                | 1.0    | Minimal priority              |

### Limitations

The current PE parser implementation focuses on import/export tables and section classification:

- **Resource Extraction**: Resource extraction (VERSIONINFO, STRINGTABLE) is planned but not yet implemented
- **Future Enhancements**: PE resource parsing will be added in future versions to extract strings from version blocks, string tables, and manifest resources

## Mach-O (Mach Object)

Used on macOS and iOS for executables, frameworks, and libraries.

### Key Sections for String Extraction

| Segment        | Section     | Priority | Description            |
| -------------- | ----------- | -------- | ---------------------- |
| `__TEXT`       | `__cstring` | High     | C string literals      |
| `__TEXT`       | `__const`   | High     | Constant data          |
| `__DATA_CONST` | `*`         | Medium   | Read-only after fixups |
| `__DATA`       | `*`         | Low      | Writable data          |

### Mach-O-Specific Features

- **Load Commands**: Extract strings from `LC_*` commands
- **Segment/Section Model**: Two-level naming scheme
- **Fat Binaries**: Multi-architecture support
- **String Pools**: Centralized string storage in `__cstring`

### Load Command Processing

Mach-O load commands contain valuable strings:

- `LC_LOAD_DYLIB`: Library paths and names
- `LC_RPATH`: Runtime search paths
- `LC_ID_DYLIB`: Library identification
- `LC_BUILD_VERSION`: Build tool information

### Implementation Details

```rust
impl MachoParser {
    fn classify_section(segment_name: &str, section_name: &str) -> SectionType {
        match (segment_name, section_name) {
            ("__TEXT", "__cstring") => SectionType::StringData,
            ("__DATA_CONST", _) => SectionType::ReadOnlyData,
            ("__DATA", _) => SectionType::WritableData,
            // ... more classifications
        }
    }
}
```

## Cross-Platform Considerations

### Encoding Differences

| Platform   | Primary Encoding | Notes                            |
| ---------- | ---------------- | -------------------------------- |
| Linux/Unix | UTF-8            | ASCII-compatible, variable width |
| Windows    | UTF-16LE         | Wide strings common in APIs      |
| macOS      | UTF-8            | Similar to Linux, some UTF-16    |

### String Storage Patterns

- **ELF**: Strings often in `.rodata` with null terminators
- **PE**: Mix of ANSI and Unicode APIs, resources use UTF-16
- **Mach-O**: Centralized in `__cstring`, mostly UTF-8

### Section Weight Calculation

Different formats require different weighting strategies:

```rust
fn calculate_section_weight(format: BinaryFormat, section_type: SectionType) -> i32 {
    match (format, section_type) {
        (BinaryFormat::Elf, SectionType::StringData) => 10, // .rodata
        (BinaryFormat::Pe, SectionType::Resources) => 9,    // .rsrc
        (BinaryFormat::MachO, SectionType::StringData) => 10, // __cstring
                                                             // ... more weights
    }
}
```

## Format Detection

Stringy uses `goblin` for robust format detection:

```rust
pub fn detect_format(data: &[u8]) -> BinaryFormat {
    match Object::parse(data) {
        Ok(Object::Elf(_)) => BinaryFormat::Elf,
        Ok(Object::PE(_)) => BinaryFormat::Pe,
        Ok(Object::Mach(_)) => BinaryFormat::MachO,
        _ => BinaryFormat::Unknown,
    }
}
```

## Future Enhancements

### Planned Format Extensions

- **WebAssembly (WASM)**: Growing importance in web and edge computing
- **Java Class Files**: JVM bytecode analysis
- **Android APK/DEX**: Mobile application analysis

### Enhanced Resource Support

- **PE**: Dialog resources, icon strings, version blocks
- **Mach-O**: Plist resources, framework bundles
- **ELF**: Note sections, build IDs, GNU attributes

### Architecture-Specific Features

- **ARM64**: Pointer authentication, tagged pointers
- **x86-64**: RIP-relative addressing hints
- **RISC-V**: Emerging architecture support

This comprehensive format support ensures Stringy can effectively analyze binaries across all major platforms while respecting the unique characteristics of each format.
