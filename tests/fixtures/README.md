# Test Fixtures

This directory contains pre-compiled binary test fixtures used for snapshot testing.

## Fixtures

- `test_binary_elf` - x86-64 ELF binary
- `test_binary_macho` - ARM64 Mach-O binary with standard load commands:
  - LC_LOAD_DYLIB for system library dependencies (e.g., libSystem.B.dylib)
  - May include LC_RPATH commands
  - May include framework dependencies
- `test_binary_pe.exe` - x86-64 PE binary
- `test_binary_with_resources.exe` - x86-64 PE binary with VERSIONINFO and STRINGTABLE resources

## Source

All fixtures are compiled from `test_binary.c`, a simple C program with:

- Exported functions: `exported_function`, `helper_function`
- Imports from libc: `printf`, `malloc`, `free`
- A `main` function

## Rebuilding Fixtures

If you need to rebuild the fixtures:

### ELF (x86-64)

```bash
docker run --rm -v "$(pwd):/work" -w /work --platform linux/amd64 gcc:latest gcc -o test_binary_elf test_binary.c
```

### Mach-O (ARM64)

```bash
clang -o test_binary_macho test_binary.c
```

The resulting binary will have standard system library dependencies. To add rpaths for testing, use:

```bash
clang -o test_binary_macho test_binary.c -Wl,-rpath,@executable_path/../Frameworks
```

To link frameworks for testing, use:

```bash
clang -o test_binary_macho test_binary.c -framework Foundation
```

Note: The current fixture is sufficient for basic testing, but enhanced fixtures with rpaths and frameworks can be added later if needed.

### PE (x86-64)

```bash
docker run --rm -v "$(pwd):/work" -w /work mcr.microsoft.com/devcontainers/cpp:latest bash -c "apt-get update -qq && apt-get install -y -qq mingw-w64 && x86_64-w64-mingw32-gcc -o test_binary_pe.exe test_binary.c"
```

Note: The current mingw-w64 build doesn't include resources, which is expected for Phase 1 testing.

### Mach-O Load Commands

Mach-O load command string extraction tests work cross-platform because they operate on binary data. The `test_binary_macho` fixture is an ARM64 binary but can be parsed on any platform using goblin.

**Load commands tested:**

- **LC_LOAD_DYLIB**: Library dependency paths (e.g., `/usr/lib/libSystem.B.dylib`)
- **LC_LOAD_WEAK_DYLIB**: Weak library dependencies
- **LC_REEXPORT_DYLIB**: Re-exported libraries
- **LC_RPATH**: Runtime search paths (may contain @-variables like `@rpath`, `@executable_path`, `@loader_path`)

The fixture should contain at least `libSystem.B.dylib` as a dependency (standard for all Mach-O executables). Framework paths and rpath variables are tested using the classification logic, even if the specific fixture doesn't contain them.

## Resource Testing

### Why We Need a Resource-Enabled Test Binary

The basic `test_binary_pe.exe` compiled from `test_binary.c` won't have VERSIONINFO or STRINGTABLE resources. These are typically added via `.rc` resource files during compilation. However, to properly test PE resource extraction functionality (implemented in Phase 1), we need a binary that actually contains these resources.

**What we're testing:**

- Detection and enumeration of PE resources using the `pelite` library
- Identification of VERSIONINFO resources (RT_VERSION, type 16)
- Identification of STRINGTABLE resources (RT_STRING, type 6)
- Proper metadata extraction (resource type, language, size)
- Integration with the PE parser's dual-parser strategy (goblin for structure, pelite for resources)

**Why this matters:** PE resources are a common source of meaningful strings in Windows binaries. Version information often contains company names, product descriptions, copyright notices, and version strings. String tables contain localized UI strings. Being able to extract and classify these resources is essential for comprehensive string analysis of PE binaries.

The `test_binary_with_resources.exe` fixture provides a controlled test case with known resources, allowing us to verify that our resource extraction framework correctly identifies and processes them.

### Building a Test Binary with Resources

The `test_binary_with_resources.exe` fixture is pre-built and included in the repository. To rebuild it:

```bash
# Using mingw-w64 with windres (resource compiler)
cd tests/fixtures
docker run --rm -v "$(pwd):/work" -w /work mcr.microsoft.com/devcontainers/cpp:latest bash -c \
  "apt-get update -qq && apt-get install -y -qq mingw-w64 >/dev/null 2>&1 && \
   x86_64-w64-mingw32-windres --input-format=rc --output-format=coff -o test_binary_with_resources.res test_binary_with_resources.rc && \
   x86_64-w64-mingw32-gcc -o test_binary_with_resources.exe test_binary_with_resources.c test_binary_with_resources.res"
```

This creates a PE binary with:

- **VERSIONINFO resource** (RT_VERSION, type 16): Contains file and product version information, company name, copyright, and other metadata. This is the most common resource type in Windows executables.
- **STRINGTABLE resources** (RT_STRING, type 6): Contains localized string entries organized by language and block ID. These are commonly used for UI strings in Windows applications.

**What the test verifies:** The `test_pe_resource_extraction_with_resources` integration test verifies that:

1. The PE parser successfully detects the binary as a PE file
2. Resource extraction doesn't break the parsing process (graceful degradation)
3. Resources are correctly identified and enumerated
4. Resource metadata (type, language, size) is properly extracted
5. The `ContainerInfo.resources` field is populated with `Some(Vec<ResourceMetadata>)` when resources are found

**Phase 1 vs Phase 2:**

- **Phase 1 (Current)**: Resource enumeration and metadata extraction - we detect that resources exist and extract basic metadata
- **Phase 2 (Future)**: Actual string extraction - we'll parse VERSIONINFO structures and STRINGTABLE entries to extract the actual string content

The current implementation focuses on Phase 1, so the test verifies resource detection rather than full string extraction.

### Alternative: Using Open Source Binaries

For testing with real-world binaries, consider these Apache-2.0/MIT licensed options:

1. **Rust CLI tools** (MIT/Apache-2.0): Many Rust projects compile to Windows PE with version info:

   - `ripgrep` (MIT/Unlicense): https://github.com/BurntSushi/ripgrep/releases
   - `fd` (MIT/Apache-2.0): https://github.com/sharkdp/fd/releases
   - `bat` (MIT/Apache-2.0): https://github.com/sharkdp/bat/releases

2. **Other open source tools**:

   - Check GitHub releases for Windows executables from MIT/Apache-2.0 licensed projects
   - Ensure the project's license permits binary analysis and redistribution in test fixtures

**Note**: Always verify the license of any binary before including it in the repository.

## Notes

- These fixtures are checked into git to ensure consistent test results
- The fixtures should not be modified unless the test requirements change
- If you modify `test_binary.c`, rebuild all fixtures and update snapshots
