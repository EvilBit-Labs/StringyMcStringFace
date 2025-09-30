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
}
```

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
}
```

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
