# Test Fixtures

This directory contains pre-compiled binary test fixtures used for snapshot testing.

## Fixtures

| Fixture                          | Description                                                                            | How to build                                |
| -------------------------------- | -------------------------------------------------------------------------------------- | ------------------------------------------- |
| `test_binary_elf`                | x86-64 ELF with `main`, `exported_function`, `helper_function`, and a URL in `.rodata` | `just gen-fixtures` (Zig cross-compilation) |
| `test_binary_pe.exe`             | x86-64 PE with libc imports                                                            | `just gen-fixtures` (Zig cross-compilation) |
| `test_binary_macho`              | x86-64 Mach-O with `libSystem.B.dylib` dependency                                      | `just gen-fixtures` (Zig cross-compilation) |
| `test_binary_with_resources.exe` | x86-64 PE with VERSIONINFO and STRINGTABLE resources                                   | `just gen-fixtures` (Zig cross-compilation) |
| `test_unknown.bin`               | Non-ELF/PE/Mach-O blob with taggable URL string                                        | `just gen-fixtures` (committed to git)      |
| `test_empty.bin`                 | Zero-byte file                                                                         | `just gen-fixtures` (committed to git)      |

All compiled binary fixtures (ELF, PE, Mach-O) are gitignored and must be generated locally before running `just test`. The `test_empty.bin` and `test_unknown.bin` files are committed to git since they are platform-independent and deterministic.

## Source

All compiled fixtures are built from `test_binary.c`, a simple C program with:

- Exported functions: `exported_function`, `helper_function`
- Imports from libc: `printf`, `malloc`, `free`
- A URL string in `.rodata` (`https://github.com/EvilBit-Labs/Stringy`)
- A `main` function

## Rebuilding Fixtures

The preferred way to rebuild all fixtures is:

```bash
just gen-fixtures
```

This uses Zig (managed by mise) to cross-compile all targets from any host platform. No Docker or platform-specific compilers are needed. If you need to rebuild individual fixtures manually:

### ELF (x86-64)

```bash
mise exec -- zig cc -target x86_64-linux-gnu -o tests/fixtures/test_binary_elf tests/fixtures/test_binary.c
```

### PE (x86-64)

```bash
mise exec -- zig cc -target x86_64-windows-gnu -o tests/fixtures/test_binary_pe.exe tests/fixtures/test_binary.c
```

### PE with Resources (x86-64)

```bash
mise exec -- zig rc /fo tests/fixtures/test_binary_with_resources.res -- tests/fixtures/test_binary_with_resources.rc
mise exec -- zig cc -target x86_64-windows-gnu -o tests/fixtures/test_binary_with_resources.exe tests/fixtures/test_binary_with_resources.c tests/fixtures/test_binary_with_resources.res
rm -f tests/fixtures/test_binary_with_resources.res
```

### Mach-O (x86-64)

```bash
mise exec -- zig cc -target x86_64-macos -o tests/fixtures/test_binary_macho tests/fixtures/test_binary.c
```

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

The `test_binary_with_resources.exe` fixture is built by `just gen-fixtures` using Zig's resource compiler (`zig rc`) and linker. See the "PE with Resources" section above for manual build commands.

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

## Bumping the Zig Version

The Zig version is pinned in `mise.toml`. Changing it may alter compiled binary layouts, which breaks `insta` snapshot assertions (e.g. `integration_flows_1_5__flow1_top3_json.snap`).

To intentionally upgrade:

1. Update the Zig version in `mise.toml`.

2. Rebuild fixtures and regenerate snapshots:

   ```bash
   just gen-fixtures
   INSTA_UPDATE=always cargo nextest run
   cargo insta accept
   ```

3. Review the updated snapshots, commit `mise.toml` and the changed `.snap` files together.

## Notes

- Compiled binary fixtures (ELF, PE, Mach-O) are gitignored and must be regenerated after any change to `test_binary.c`
- All fixtures are cross-compiled via Zig (managed by mise) -- no Docker or platform-specific compilers needed
- `test_empty.bin` and `test_unknown.bin` are committed to git (platform-independent)
- If you modify `test_binary.c`, rebuild all fixtures with `just gen-fixtures` and update snapshots
