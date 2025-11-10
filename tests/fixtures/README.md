# Test Fixtures

This directory contains pre-compiled binary test fixtures used for snapshot testing.

## Fixtures

- `test_binary_elf` - x86-64 ELF binary
- `test_binary_macho` - ARM64 Mach-O binary
- `test_binary_pe.exe` - x86-64 PE binary

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

### PE (x86-64)

```bash
docker run --rm -v "$(pwd):/work" -w /work mcr.microsoft.com/devcontainers/cpp:latest bash -c "apt-get update -qq && apt-get install -y -qq mingw-w64 && x86_64-w64-mingw32-gcc -o test_binary_pe.exe test_binary.c"
```

## Notes

- These fixtures are checked into git to ensure consistent test results
- The fixtures should not be modified unless the test requirements change
- If you modify `test_binary.c`, rebuild all fixtures and update snapshots
