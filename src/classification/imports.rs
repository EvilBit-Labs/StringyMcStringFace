//! Import/export symbol classification.
//!
//! Converts parsed [`ContainerInfo`] imports, exports, and section names into
//! tagged, scored [`FoundString`]s. This is the single emission point for
//! symbol strings in the extraction path: every import carries [`Tag::Import`]
//! (plus a semantic tag when its name matches a known crypto, network, or
//! file-I/O API), every export carries [`Tag::Export`] (plus [`Tag::EntryPoint`]
//! for known entry points), and each section name is emitted as a standalone
//! row with [`StringSource::SectionName`].
//!
//! Demangling is deliberately left to the pipeline's `classify_strings` (which
//! runs under `catch_unwind` and is skipped in raw mode); the classifier only
//! tags. Exports that are mangled symbols receive [`Tag::DemangledSymbol`] and
//! their demangled text there when demangling succeeds; names that fail to
//! demangle are left unchanged.
//!
//! Symbol strings are emitted with [`Encoding::Utf8`] so that a byte-scanned
//! occurrence of the same name (e.g. from a PE `.idata` section) shares the
//! `(text, encoding)` deduplication key and merges into the single tagged row.

use std::collections::HashSet;
use std::sync::LazyLock;

use crate::types::{
    BinaryFormat, ContainerInfo, Encoding, ExportInfo, FoundString, ImportInfo, SectionInfo,
    StringSource, Tag,
};

/// Crypto-related API names. Matching imports gain [`Tag::Crypto`].
static CRYPTO_APIS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        "EVP_EncryptInit",
        "EVP_DecryptInit",
        "EVP_DigestInit",
        "CryptEncrypt",
        "CryptDecrypt",
        "CryptAcquireContextW",
        "CryptGenKey",
        "BCryptEncrypt",
        "BCryptDecrypt",
        "AES_encrypt",
        "AES_decrypt",
        "SHA256_Init",
        "MD5_Init",
    ])
});

/// Network-related API names. Matching imports gain [`Tag::Network`].
static NETWORK_APIS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        "connect",
        "send",
        "recv",
        "socket",
        "bind",
        "listen",
        "accept",
        "getaddrinfo",
        "gethostbyname",
        "WSAStartup",
        "WSASocketW",
        "InternetOpenW",
        "InternetConnectW",
        "HttpSendRequestW",
    ])
});

/// File-I/O-related API names. Matching imports gain [`Tag::FileIO`].
static FILEIO_APIS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        "CreateFileW",
        "CreateFileA",
        "ReadFile",
        "WriteFile",
        "DeleteFileW",
        "MoveFileW",
        "CopyFileW",
        "fopen",
        "fread",
        "fwrite",
        "open",
        "read",
        "write",
    ])
});

/// Known program entry-point symbol names. Matching exports gain
/// [`Tag::EntryPoint`].
static ENTRY_POINTS: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| HashSet::from(["main", "_start", "DllMain", "WinMain", "wWinMain"]));

/// Classifies import/export symbols and section names into tagged strings.
///
/// Stateless: tagging is the classifier's job. Demangling is performed once by
/// the pipeline's `classify_strings` (under `catch_unwind`, and skipped in raw
/// mode), so it is intentionally not done here.
#[derive(Debug, Default, Clone)]
pub struct ImportClassifier;

impl ImportClassifier {
    /// Create a new `ImportClassifier`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Convert import symbols into tagged `FoundString`s.
    ///
    /// Each import carries [`Tag::Import`] plus a semantic tag when its name
    /// matches a known API set. The `section` field is populated from the
    /// import's originating library when present, otherwise from a
    /// format-appropriate default (see [`default_import_section`]). The RVA is
    /// populated from `ImportInfo::address` when available.
    #[must_use]
    pub fn process_imports(
        &self,
        imports: &[ImportInfo],
        format: BinaryFormat,
    ) -> Vec<FoundString> {
        imports
            .iter()
            .map(|import| {
                let mut tags = vec![Tag::Import];
                if let Some(semantic) = semantic_tag(&import.name) {
                    tags.push(semantic);
                }

                let section = import
                    .library
                    .clone()
                    .unwrap_or_else(|| default_import_section(format).to_string());

                let length = import.name.len() as u32;
                let mut found = FoundString::new(
                    import.name.clone(),
                    Encoding::Utf8,
                    0,
                    length,
                    StringSource::ImportName,
                )
                .with_tags(tags)
                .with_section(section);

                if let Some(address) = import.address {
                    found = found.with_rva(address);
                }

                found
            })
            .collect()
    }

    /// Convert export symbols into tagged `FoundString`s.
    ///
    /// Each export carries [`Tag::Export`] and an RVA from the always-present
    /// `ExportInfo::address`, plus [`Tag::EntryPoint`] when the name is a known
    /// entry point. Demangling (and the resulting [`Tag::DemangledSymbol`]) is
    /// performed downstream by the pipeline's `classify_strings`, which runs
    /// under `catch_unwind` and is skipped in raw mode -- so a panic in a
    /// third-party demangler never aborts extraction, and raw mode shows the
    /// untouched symbol name. Entry-point names are never mangled, so the check
    /// runs correctly on the raw export name.
    #[must_use]
    pub fn process_exports(&self, exports: &[ExportInfo]) -> Vec<FoundString> {
        exports
            .iter()
            .map(|export| {
                let length = export.name.len() as u32;
                let mut found = FoundString::new(
                    export.name.clone(),
                    Encoding::Utf8,
                    0,
                    length,
                    StringSource::ExportName,
                )
                .with_tags(vec![Tag::Export])
                .with_rva(export.address);

                if ENTRY_POINTS.contains(found.text.as_str()) {
                    found.tags.push(Tag::EntryPoint);
                }

                found
            })
            .collect()
    }

    /// Convert section names into standalone `FoundString`s.
    ///
    /// Each section name is emitted with [`StringSource::SectionName`] so it is
    /// distinguishable from byte-scanned section content downstream. Empty
    /// section names (e.g. PE sections with an all-null name field) are skipped
    /// so no zero-length row reaches output.
    #[must_use]
    pub fn process_section_names(&self, sections: &[SectionInfo]) -> Vec<FoundString> {
        sections
            .iter()
            .filter(|section| !section.name.is_empty())
            .map(|section| {
                let length = section.name.len() as u32;
                FoundString::new(
                    section.name.clone(),
                    Encoding::Utf8,
                    0,
                    length,
                    StringSource::SectionName,
                )
            })
            .collect()
    }
}

/// Return the semantic tag for an import name, if it matches a known API set.
///
/// The crypto, network, and file-I/O sets are disjoint, so an import matches
/// at most one category.
fn semantic_tag(name: &str) -> Option<Tag> {
    if CRYPTO_APIS.contains(name) {
        Some(Tag::Crypto)
    } else if NETWORK_APIS.contains(name) {
        Some(Tag::Network)
    } else if FILEIO_APIS.contains(name) {
        Some(Tag::FileIO)
    } else {
        None
    }
}

/// Format-appropriate default `section` for an import with no library name.
///
/// Mach-O imports never carry a library (the parser leaves it `None`), so
/// Mach-O always uses this default.
fn default_import_section(format: BinaryFormat) -> &'static str {
    match format {
        BinaryFormat::Pe => ".idata",
        BinaryFormat::Elf => ".dynsym",
        BinaryFormat::MachO => "__LINKEDIT",
        // Unknown formats fall back to raw scanning and carry no imports;
        // use the ELF default as a neutral placeholder.
        BinaryFormat::Unknown => ".dynsym",
    }
}

/// Convert all symbols and section names in a [`ContainerInfo`] into tagged
/// `FoundString`s.
///
/// This is the single symbol emission point routed into the extraction path.
#[must_use]
pub fn extract_symbol_strings(container_info: &ContainerInfo) -> Vec<FoundString> {
    let classifier = ImportClassifier::new();
    let mut strings = classifier.process_imports(&container_info.imports, container_info.format);
    strings.extend(classifier.process_exports(&container_info.exports));
    // Section names are only meaningful for recognized container formats. The
    // unknown/raw fallback uses a synthetic "raw-bytes" section that carries no
    // analytic value (and would pollute empty-file output), so skip
    // section-name rows for Unknown format.
    if container_info.format != BinaryFormat::Unknown {
        strings.extend(classifier.process_section_names(&container_info.sections));
    }
    strings
}
