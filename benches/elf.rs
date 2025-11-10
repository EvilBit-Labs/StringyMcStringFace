use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use stringy::container::{ContainerParser, ElfParser};

fn bench_elf_full_parse(c: &mut Criterion) {
    // Use the current test binary as a sample ELF file
    let current_exe = std::env::current_exe().expect("Failed to get current executable");
    let data = std::fs::read(&current_exe).expect("Failed to read test binary");

    // Only benchmark if it's actually an ELF file
    if !stringy::container::ElfParser::detect(&data) {
        return;
    }

    let parser = ElfParser::new();
    c.bench_function("elf_full_parse", |b| {
        b.iter(|| {
            let _ = parser.parse(black_box(&data));
        });
    });
}

fn bench_elf_parse_with_imports(c: &mut Criterion) {
    let current_exe = std::env::current_exe().expect("Failed to get current executable");
    let data = std::fs::read(&current_exe).expect("Failed to read test binary");

    if !stringy::container::ElfParser::detect(&data) {
        return;
    }

    let parser = ElfParser::new();
    c.bench_function("elf_parse_with_imports", |b| {
        b.iter(|| {
            if let Ok(container_info) = parser.parse(black_box(&data)) {
                // Access imports to ensure mapping is performed
                let _import_count = container_info.imports.len();
                let _imports_with_libs = container_info
                    .imports
                    .iter()
                    .filter(|imp| imp.library.is_some())
                    .count();
            }
        });
    });
}

fn bench_elf_parse_with_exports(c: &mut Criterion) {
    let current_exe = std::env::current_exe().expect("Failed to get current executable");
    let data = std::fs::read(&current_exe).expect("Failed to read test binary");

    if !stringy::container::ElfParser::detect(&data) {
        return;
    }

    let parser = ElfParser::new();
    c.bench_function("elf_parse_with_exports", |b| {
        b.iter(|| {
            if let Ok(container_info) = parser.parse(black_box(&data)) {
                // Access exports to ensure filtering is performed
                let _export_count = container_info.exports.len();
            }
        });
    });
}

criterion_group!(
    elf_benches,
    bench_elf_full_parse,
    bench_elf_parse_with_imports,
    bench_elf_parse_with_exports
);
criterion_main!(elf_benches);
