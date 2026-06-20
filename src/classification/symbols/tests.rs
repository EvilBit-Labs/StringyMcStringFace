use super::*;
use crate::types::{Encoding, StringSource};

fn create_test_string(text: &str) -> FoundString {
    FoundString {
        text: text.to_string(),
        original_text: None,
        encoding: Encoding::Ascii,
        offset: 0,
        rva: None,
        section: None,
        length: text.len() as u32,
        tags: Vec::new(),
        score: 0,
        section_weight: None,
        semantic_boost: None,
        noise_penalty: None,
        display_score: None,
        source: StringSource::ImportName,
        confidence: 1.0,
    }
}

#[test]
fn test_is_mangled_rust_legacy() {
    let demangler = SymbolDemangler::new();

    // Legacy Rust mangling (_ZN prefix)
    assert!(demangler.is_mangled("_ZN4core3fmt5Write9write_str17h1234567890abcdefE"));
    assert!(demangler.is_mangled("_ZN3std2io5stdio6_print17h1234567890abcdefE"));
}

#[test]
fn test_is_mangled_rust_v0() {
    let demangler = SymbolDemangler::new();

    // Rust v0 mangling (_R prefix)
    assert!(demangler.is_mangled("_RNvNtCs123_4core3fmt5write"));
    assert!(demangler.is_mangled("_RNvCs123_5hello4main"));
}

#[test]
fn test_is_mangled_not_mangled() {
    let demangler = SymbolDemangler::new();

    // Regular symbols should not be detected as mangled
    assert!(!demangler.is_mangled("printf"));
    assert!(!demangler.is_mangled("malloc"));
    assert!(!demangler.is_mangled("main"));
    assert!(!demangler.is_mangled("CreateFileW"));
    assert!(!demangler.is_mangled(""));
}

#[test]
fn test_demangle_rust_symbol() {
    let demangler = SymbolDemangler::new();
    let mut found_string = create_test_string("_ZN4core3fmt5Write9write_str17h1234567890abcdefE");

    demangler.demangle(&mut found_string);

    // Should have been demangled
    assert!(found_string.original_text.is_some());
    assert_eq!(
        found_string.original_text.as_ref().unwrap(),
        "_ZN4core3fmt5Write9write_str17h1234567890abcdefE"
    );
    assert!(found_string.tags.contains(&Tag::DemangledSymbol));
    // Demangled text should be different from original
    assert_ne!(
        found_string.text,
        "_ZN4core3fmt5Write9write_str17h1234567890abcdefE"
    );
}

#[test]
fn test_demangle_non_mangled() {
    let demangler = SymbolDemangler::new();
    let mut found_string = create_test_string("printf");

    demangler.demangle(&mut found_string);

    // Should not have been modified
    assert_eq!(found_string.text, "printf");
    assert!(found_string.original_text.is_none());
    assert!(!found_string.tags.contains(&Tag::DemangledSymbol));
}

#[test]
fn test_try_demangle_success() {
    let demangler = SymbolDemangler::new();
    let result = demangler.try_demangle("_ZN4core3fmt5Write9write_str17h1234567890abcdefE");

    assert!(result.is_some());
    let demangled = result.unwrap();
    assert!(!demangled.is_empty());
    assert_ne!(
        demangled,
        "_ZN4core3fmt5Write9write_str17h1234567890abcdefE"
    );
}

#[test]
fn test_try_demangle_failure() {
    let demangler = SymbolDemangler::new();

    assert!(demangler.try_demangle("printf").is_none());
    assert!(demangler.try_demangle("").is_none());
    assert!(demangler.try_demangle("main").is_none());
}

#[test]
fn test_demangle_preserves_existing_tags() {
    let demangler = SymbolDemangler::new();
    let mut found_string = create_test_string("_ZN4core3fmt5Write9write_str17h1234567890abcdefE");
    found_string.tags.push(Tag::Import);

    demangler.demangle(&mut found_string);

    // Should have both the original tag and the new demangled tag
    assert!(found_string.tags.contains(&Tag::Import));
    assert!(found_string.tags.contains(&Tag::DemangledSymbol));
}

#[test]
fn test_demangle_idempotent() {
    let demangler = SymbolDemangler::new();
    let mut found_string = create_test_string("_ZN4core3fmt5Write9write_str17h1234567890abcdefE");

    demangler.demangle(&mut found_string);
    let first_text = found_string.text.clone();
    let first_original = found_string.original_text.clone();

    // Calling demangle again should not change anything
    demangler.demangle(&mut found_string);

    assert_eq!(found_string.text, first_text);
    assert_eq!(found_string.original_text, first_original);
    // Should only have one DemangledSymbol tag
    assert_eq!(
        found_string
            .tags
            .iter()
            .filter(|t| matches!(t, Tag::DemangledSymbol))
            .count(),
        1
    );
}

// C++ demangling tests

#[test]
fn test_is_mangled_cpp_symbols() {
    let demangler = SymbolDemangler::new();

    // C++ Itanium ABI mangled symbols
    assert!(demangler.is_mangled("_ZN3foo3barEv")); // foo::bar()
    assert!(demangler.is_mangled("_Z3foov")); // foo()
    assert!(demangler.is_mangled("_ZN9__gnu_cxx13new_allocatorIcE10deallocateEPcm"));
    assert!(demangler.is_mangled("_ZNSt6vectorIiSaIiEE9push_backERKi"));
    assert!(demangler.is_mangled("_ZTV5MyClass")); // vtable for MyClass
    assert!(demangler.is_mangled("_ZTI5MyClass")); // typeinfo for MyClass
}

#[test]
fn test_demangle_cpp_symbol() {
    let demangler = SymbolDemangler::new();
    let mut found_string = create_test_string("_ZN3foo3barEv");

    demangler.demangle(&mut found_string);

    // Should have been demangled
    assert!(found_string.original_text.is_some());
    assert_eq!(
        found_string.original_text.as_ref().unwrap(),
        "_ZN3foo3barEv"
    );
    assert!(found_string.tags.contains(&Tag::DemangledSymbol));
    // Demangled text should contain "foo" and "bar"
    assert!(found_string.text.contains("foo"));
    assert!(found_string.text.contains("bar"));
}

#[test]
fn test_try_demangle_cpp_success() {
    let demangler = SymbolDemangler::new();

    // Simple C++ function
    let result = demangler.try_demangle("_Z3foov");
    assert!(result.is_some());
    let demangled = result.unwrap();
    assert!(demangled.contains("foo"));

    // Namespaced C++ function
    let result = demangler.try_demangle("_ZN3foo3barEv");
    assert!(result.is_some());
    let demangled = result.unwrap();
    assert!(demangled.contains("foo"));
    assert!(demangled.contains("bar"));
}

#[test]
fn test_demangle_cpp_with_parameters() {
    let demangler = SymbolDemangler::new();

    // C++ function with int parameter: void foo(int)
    let result = demangler.try_demangle("_Z3fooi");
    assert!(result.is_some());
    let demangled = result.unwrap();
    assert!(demangled.contains("foo"));
    assert!(demangled.contains("int"));
}

#[test]
fn test_demangle_cpp_template() {
    let demangler = SymbolDemangler::new();

    // C++ template: std::vector<int>
    let result = demangler.try_demangle("_ZNSt6vectorIiSaIiEEC1Ev");
    assert!(result.is_some());
    let demangled = result.unwrap();
    assert!(demangled.contains("vector"));
}

#[test]
fn test_cpp_symbol_in_found_string() {
    let demangler = SymbolDemangler::new();
    let mut found_string = create_test_string("_Z3fooi");
    found_string.tags.push(Tag::Export);

    demangler.demangle(&mut found_string);

    // Should have been demangled and preserved existing tags
    assert!(found_string.original_text.is_some());
    assert!(found_string.tags.contains(&Tag::Export));
    assert!(found_string.tags.contains(&Tag::DemangledSymbol));
    assert!(found_string.text.contains("foo"));
}

// MSVC demangling tests

#[test]
fn test_is_mangled_msvc_symbols() {
    let demangler = SymbolDemangler::new();

    // MSVC-mangled symbols (?-prefixed)
    assert!(demangler.is_mangled("?printf@@YAHPEBDZZ")); // int __cdecl printf(...)
    assert!(demangler.is_mangled("??0MyClass@@QEAA@XZ")); // MyClass::MyClass(void)
    assert!(demangler.is_mangled("??HMyClass@@QEAAHH@Z")); // MyClass::operator+(int)
}

#[test]
fn test_is_mangled_msvc_not_triggered_for_plain() {
    let demangler = SymbolDemangler::new();

    // Plain Windows API names and empty input must not be treated as MSVC mangled
    assert!(!demangler.is_mangled("printf"));
    assert!(!demangler.is_mangled("CreateFileW"));
    assert!(!demangler.is_mangled(""));
}

#[test]
fn test_demangle_msvc_plain_function() {
    let demangler = SymbolDemangler::new();
    let mut found_string = create_test_string("?printf@@YAHPEBDZZ");

    demangler.demangle(&mut found_string);

    // Should have been demangled with original preserved and tag applied
    assert_eq!(
        found_string.original_text.as_ref().unwrap(),
        "?printf@@YAHPEBDZZ"
    );
    assert!(found_string.tags.contains(&Tag::DemangledSymbol));
    assert!(found_string.text.contains("printf"));
    assert_ne!(found_string.text, "?printf@@YAHPEBDZZ");
}

#[test]
fn test_demangle_msvc_constructor() {
    let demangler = SymbolDemangler::new();
    let mut found_string = create_test_string("??0MyClass@@QEAA@XZ");

    demangler.demangle(&mut found_string);

    // Constructor symbol should demangle and reference the class name
    assert!(found_string.original_text.is_some());
    assert!(found_string.tags.contains(&Tag::DemangledSymbol));
    assert!(found_string.text.contains("MyClass"));
}

#[test]
fn test_demangle_msvc_operator() {
    let demangler = SymbolDemangler::new();
    let mut found_string = create_test_string("??HMyClass@@QEAAHH@Z");

    demangler.demangle(&mut found_string);

    // Operator-overload symbol should demangle to a readable operator form
    assert!(found_string.original_text.is_some());
    assert!(found_string.tags.contains(&Tag::DemangledSymbol));
    assert!(found_string.text.contains("operator+"));
}

#[test]
fn test_demangle_msvc_invalid_fallback() {
    let demangler = SymbolDemangler::new();
    let mut found_string = create_test_string("?notvalid");

    demangler.demangle(&mut found_string);

    // Invalid MSVC input should leave the FoundString unchanged
    assert_eq!(found_string.text, "?notvalid");
    assert!(found_string.original_text.is_none());
    assert!(!found_string.tags.contains(&Tag::DemangledSymbol));
}

#[test]
fn test_try_demangle_msvc_success() {
    let demangler = SymbolDemangler::new();

    let result = demangler.try_demangle("?printf@@YAHPEBDZZ");
    assert!(result.is_some());
    assert!(result.unwrap().contains("printf"));
}

#[test]
fn test_try_demangle_msvc_failure() {
    let demangler = SymbolDemangler::new();

    // A bare "?" is detected as mangled but cannot be demangled
    assert!(demangler.try_demangle("?").is_none());
}

#[test]
fn test_demangle_msvc_idempotent() {
    let demangler = SymbolDemangler::new();
    let mut found_string = create_test_string("?printf@@YAHPEBDZZ");

    demangler.demangle(&mut found_string);
    let first_text = found_string.text.clone();
    let first_original = found_string.original_text.clone();

    // Re-running demangle on an already-demangled MSVC symbol is a no-op: the
    // demangled form no longer starts with `?`, so is_mangled() short-circuits.
    demangler.demangle(&mut found_string);

    assert_eq!(found_string.text, first_text);
    assert_eq!(found_string.original_text, first_original);
    // Should only have one DemangledSymbol tag
    assert_eq!(
        found_string
            .tags
            .iter()
            .filter(|t| matches!(t, Tag::DemangledSymbol))
            .count(),
        1
    );
}

#[test]
fn test_demangle_msvc_oversized_symbol_rejected() {
    let demangler = SymbolDemangler::new();
    // A crafted ?-symbol with deeply nested pointer modifiers would overflow
    // the demangler's recursive parser; the length guard must reject it
    // before parsing, leaving the FoundString untouched.
    let oversized = format!("?x@@3{}HA", "PEA".repeat(20_000));
    assert!(oversized.len() > MSVC_MAX_SYMBOL_LEN);
    let mut found_string = create_test_string(&oversized);

    demangler.demangle(&mut found_string);

    assert_eq!(found_string.text, oversized);
    assert!(found_string.original_text.is_none());
    assert!(!found_string.tags.contains(&Tag::DemangledSymbol));
    // try_demangle must also short-circuit without invoking the parser
    assert!(demangler.try_demangle(&oversized).is_none());
}

#[test]
fn test_msvc_symbol_preserves_existing_tags() {
    let demangler = SymbolDemangler::new();
    let mut found_string = create_test_string("?printf@@YAHPEBDZZ");
    found_string.tags.push(Tag::Import);

    demangler.demangle(&mut found_string);

    // Existing tags should survive alongside the new demangled tag
    assert!(found_string.tags.contains(&Tag::Import));
    assert!(found_string.tags.contains(&Tag::DemangledSymbol));
}
