//! Symbol classification tests for the import/export pipeline.
//!
//! Provenance assertions (section, source, rva) run against hand-built
//! `ContainerInfo` values so no byte-scan occurrence is in play -- per the
//! plan's KTD1, a symbol's source/section/rva are only deterministic when the
//! classifier is the sole emitter.

use std::fs;

use stringy::classification::{ImportClassifier, SymbolDemangler, extract_symbol_strings};
use stringy::container::{ContainerParser, ElfParser, MachoParser, PeParser};
use stringy::types::{
    BinaryFormat, ExportInfo, FoundString, ImportInfo, SectionInfo, SectionType, StringSource, Tag,
};

fn get_fixture_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn find<'a>(strings: &'a [FoundString], text: &str) -> &'a FoundString {
    strings
        .iter()
        .find(|s| s.text == text)
        .unwrap_or_else(|| panic!("expected a string with text {text:?}"))
}

// --- Imports (R1, R2, R3, R4; AE1, AE3) --------------------------------------

#[test]
fn every_import_carries_import_tag_source_and_full_confidence() {
    let classifier = ImportClassifier::new();
    let imports = vec![
        ImportInfo::new("printf".to_string()),
        ImportInfo::new("connect".to_string()),
        ImportInfo::new("CreateFileW".to_string()),
    ];

    let strings = classifier.process_imports(&imports, BinaryFormat::Pe);

    assert_eq!(strings.len(), 3);
    for s in &strings {
        assert!(
            s.tags.contains(&Tag::Import),
            "import must carry Tag::Import"
        );
        assert_eq!(s.source, StringSource::ImportName);
        assert_eq!(s.confidence, 1.0);
    }
}

#[test]
fn imports_gain_matching_semantic_tags() {
    let classifier = ImportClassifier::new();
    let imports = vec![
        ImportInfo::new("CreateFileW".to_string()),
        ImportInfo::new("connect".to_string()),
        ImportInfo::new("EVP_EncryptInit".to_string()),
        ImportInfo::new("printf".to_string()),
    ];

    let strings = classifier.process_imports(&imports, BinaryFormat::Pe);

    let create_file = find(&strings, "CreateFileW");
    assert!(create_file.tags.contains(&Tag::Import));
    assert!(create_file.tags.contains(&Tag::FileIO));

    let connect = find(&strings, "connect");
    assert!(connect.tags.contains(&Tag::Import));
    assert!(connect.tags.contains(&Tag::Network));

    let crypto = find(&strings, "EVP_EncryptInit");
    assert!(crypto.tags.contains(&Tag::Import));
    assert!(crypto.tags.contains(&Tag::Crypto));

    // printf matches no semantic set: Import only.
    let printf = find(&strings, "printf");
    assert_eq!(printf.tags, vec![Tag::Import]);
}

#[test]
fn import_section_uses_library_then_format_default() {
    let classifier = ImportClassifier::new();

    // Library present: section is the library name.
    let with_lib = classifier.process_imports(
        &[ImportInfo::new("CreateFileW".to_string()).with_library("kernel32.dll".to_string())],
        BinaryFormat::Pe,
    );
    assert_eq!(with_lib[0].section.as_deref(), Some("kernel32.dll"));

    // No library: format-appropriate default.
    let pe = classifier.process_imports(&[ImportInfo::new("f".to_string())], BinaryFormat::Pe);
    assert_eq!(pe[0].section.as_deref(), Some(".idata"));

    let elf = classifier.process_imports(&[ImportInfo::new("f".to_string())], BinaryFormat::Elf);
    assert_eq!(elf[0].section.as_deref(), Some(".dynsym"));

    // Mach-O imports are always library-less.
    let macho =
        classifier.process_imports(&[ImportInfo::new("f".to_string())], BinaryFormat::MachO);
    assert_eq!(macho[0].section.as_deref(), Some("__LINKEDIT"));
}

#[test]
fn import_rva_populates_only_when_address_present() {
    let classifier = ImportClassifier::new();
    let imports = vec![
        ImportInfo::new("with_addr".to_string()).with_address(0x4010),
        ImportInfo::new("no_addr".to_string()),
    ];

    let strings = classifier.process_imports(&imports, BinaryFormat::Elf);

    assert_eq!(find(&strings, "with_addr").rva, Some(0x4010));
    assert_eq!(find(&strings, "no_addr").rva, None);
}

// --- Exports (R5, R6, R7; AE2) -----------------------------------------------

#[test]
fn every_export_carries_export_tag_source_and_rva() {
    let classifier = ImportClassifier::new();
    let exports = vec![
        ExportInfo::new("alpha".to_string(), 0x1000),
        ExportInfo::new("beta".to_string(), 0x2000),
    ];

    let strings = classifier.process_exports(&exports);

    assert_eq!(strings.len(), 2);
    for s in &strings {
        assert!(s.tags.contains(&Tag::Export));
        assert_eq!(s.source, StringSource::ExportName);
        assert_eq!(s.confidence, 1.0);
    }
    assert_eq!(find(&strings, "alpha").rva, Some(0x1000));
    assert_eq!(find(&strings, "beta").rva, Some(0x2000));
}

#[test]
fn mangled_export_emitted_raw_for_pipeline_demangling() {
    // The classifier tags exports but does NOT demangle. Demangling is the
    // pipeline's job (classify_strings: under catch_unwind, skipped in raw
    // mode), so a third-party demangler panic never aborts extraction and raw
    // mode shows the untouched symbol name.
    let classifier = ImportClassifier::new();
    let exports = vec![ExportInfo::new("_ZN3foo3barEv".to_string(), 0x3000)];

    let strings = classifier.process_exports(&exports);
    let export = &strings[0];

    assert!(export.tags.contains(&Tag::Export));
    assert!(!export.tags.contains(&Tag::DemangledSymbol));
    assert_eq!(export.text, "_ZN3foo3barEv");
    assert_eq!(export.original_text, None);

    // The emitted string is in a demangleable state: the pipeline's
    // SymbolDemangler produces Export + DemangledSymbol + demangled text (AE2).
    let mut downstream = strings[0].clone();
    SymbolDemangler::new().demangle(&mut downstream);
    assert!(downstream.tags.contains(&Tag::Export));
    assert!(downstream.tags.contains(&Tag::DemangledSymbol));
    assert!(downstream.text.contains("foo") && downstream.text.contains("bar"));
}

#[test]
fn entry_point_exports_gain_entry_point_tag() {
    let classifier = ImportClassifier::new();
    let exports = vec![
        ExportInfo::new("main".to_string(), 0x1000),
        ExportInfo::new("DllMain".to_string(), 0x2000),
        ExportInfo::new("_start".to_string(), 0x3000),
        ExportInfo::new("WinMain".to_string(), 0x4000),
        ExportInfo::new("wWinMain".to_string(), 0x5000),
        ExportInfo::new("ordinary_export".to_string(), 0x6000),
    ];

    let strings = classifier.process_exports(&exports);

    for name in ["main", "DllMain", "_start", "WinMain", "wWinMain"] {
        let s = find(&strings, name);
        assert!(
            s.tags.contains(&Tag::EntryPoint),
            "{name} must be an entry point"
        );
    }

    let ordinary = find(&strings, "ordinary_export");
    assert!(!ordinary.tags.contains(&Tag::EntryPoint));
    assert!(!ordinary.tags.contains(&Tag::DemangledSymbol));
    assert_eq!(ordinary.tags, vec![Tag::Export]);
}

// --- Section names (R8) ------------------------------------------------------

#[test]
fn section_names_emit_as_section_name_source() {
    let classifier = ImportClassifier::new();
    let sections = vec![
        SectionInfo::new(".text".to_string(), 0, 100, SectionType::Code, 1.0),
        SectionInfo::new(
            ".rodata".to_string(),
            100,
            100,
            SectionType::StringData,
            1.0,
        ),
        // Empty-named section (e.g. PE all-null name) must be skipped.
        SectionInfo::new(String::new(), 200, 10, SectionType::Other, 1.0),
    ];

    let strings = classifier.process_section_names(&sections);

    assert_eq!(strings.len(), 2);
    for s in &strings {
        assert_eq!(s.source, StringSource::SectionName);
        assert_eq!(s.confidence, 1.0);
        assert!(!s.text.is_empty());
    }
    assert!(strings.iter().any(|s| s.text == ".text"));
    assert!(strings.iter().any(|s| s.text == ".rodata"));
}

#[test]
fn unknown_format_skips_section_name_rows() {
    // The unknown/raw fallback uses a synthetic "raw-bytes" section; its name
    // carries no analytic value and must not be emitted as a standalone row.
    let info = stringy::types::ContainerInfo::new(
        BinaryFormat::Unknown,
        vec![SectionInfo::new(
            "raw-bytes".to_string(),
            0,
            10,
            SectionType::Other,
            1.0,
        )],
        vec![],
        vec![],
        None,
    );

    let strings = extract_symbol_strings(&info);
    assert!(
        !strings
            .iter()
            .any(|s| s.source == StringSource::SectionName),
        "Unknown format must not emit section-name rows"
    );
}

// --- End-to-end against fixtures (R13) ---------------------------------------

fn assert_symbol_contract(strings: &[FoundString]) {
    // Section names are always present (every binary has sections).
    assert!(
        strings
            .iter()
            .any(|s| s.source == StringSource::SectionName),
        "extract_symbol_strings must emit section-name rows"
    );
    // Any import/export row carries the matching always-on tag.
    for s in strings {
        match s.source {
            StringSource::ImportName => assert!(s.tags.contains(&Tag::Import)),
            StringSource::ExportName => assert!(s.tags.contains(&Tag::Export)),
            _ => {}
        }
    }
}

#[test]
fn extract_symbol_strings_on_elf_fixture() {
    let data = fs::read(get_fixture_path("test_binary_elf"))
        .expect("read ELF fixture (run `just gen-fixtures`)");
    assert!(ElfParser::detect(&data));
    let info = ElfParser::new().parse(&data).expect("parse ELF");
    let strings = extract_symbol_strings(&info);
    assert_symbol_contract(&strings);
}

#[test]
fn extract_symbol_strings_on_pe_fixture() {
    let data = fs::read(get_fixture_path("test_binary_pe.exe"))
        .expect("read PE fixture (run `just gen-fixtures`)");
    assert!(PeParser::detect(&data));
    let info = PeParser::new().parse(&data).expect("parse PE");
    let strings = extract_symbol_strings(&info);
    assert_symbol_contract(&strings);
}

#[test]
fn extract_symbol_strings_on_macho_fixture() {
    let data = fs::read(get_fixture_path("test_binary_macho"))
        .expect("read Mach-O fixture (run `just gen-fixtures`)");
    assert!(MachoParser::detect(&data));
    let info = MachoParser::new().parse(&data).expect("parse Mach-O");
    let strings = extract_symbol_strings(&info);
    assert_symbol_contract(&strings);
}
