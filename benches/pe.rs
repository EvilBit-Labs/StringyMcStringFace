use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use stringy::container::{ContainerParser, PeParser};

fn bench_pe_full_parse(c: &mut Criterion) {
    // Use the PE test fixture
    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("test_binary_pe.exe");

    let data = match std::fs::read(&fixture_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to read PE fixture: {}", e);
            return;
        }
    };

    // Only benchmark if it's actually a PE file
    if !stringy::container::PeParser::detect(&data) {
        println!("PE fixture is not a valid PE file, skipping benchmark");
        return;
    }

    let parser = PeParser::new();
    c.bench_function("pe_full_parse", |b| {
        b.iter(|| {
            let _ = parser.parse(black_box(&data));
        });
    });
}

fn bench_pe_parse_with_imports(c: &mut Criterion) {
    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("test_binary_pe.exe");

    let data = match std::fs::read(&fixture_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to read PE fixture: {}", e);
            return;
        }
    };

    if !stringy::container::PeParser::detect(&data) {
        println!("PE fixture is not a valid PE file, skipping benchmark");
        return;
    }

    let parser = PeParser::new();
    c.bench_function("pe_parse_with_imports", |b| {
        b.iter(|| {
            if let Ok(container_info) = parser.parse(black_box(&data)) {
                // Access imports to ensure extraction is performed
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

fn bench_pe_parse_with_exports(c: &mut Criterion) {
    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("test_binary_pe.exe");

    let data = match std::fs::read(&fixture_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to read PE fixture: {}", e);
            return;
        }
    };

    if !stringy::container::PeParser::detect(&data) {
        println!("PE fixture is not a valid PE file, skipping benchmark");
        return;
    }

    let parser = PeParser::new();
    c.bench_function("pe_parse_with_exports", |b| {
        b.iter(|| {
            if let Ok(container_info) = parser.parse(black_box(&data)) {
                // Access exports to ensure extraction is performed
                let _export_count = container_info.exports.len();
            }
        });
    });
}

criterion_group!(
    pe_benches,
    bench_pe_full_parse,
    bench_pe_parse_with_imports,
    bench_pe_parse_with_exports
);
criterion_main!(pe_benches);
