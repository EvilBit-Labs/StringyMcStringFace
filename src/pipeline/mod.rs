//! Pipeline orchestrator for Stringy.
//!
//! Wires together all processing stages (parsing, extraction, classification,
//! ranking, normalization, filtering, output) into a single `Pipeline::run`
//! entry point.

pub mod config;
pub mod filter;
pub mod normalizer;

pub use config::{EncodingFilter, FilterConfig, PipelineConfig};
pub use filter::FilterEngine;
pub use normalizer::ScoreNormalizer;

use std::path::Path;
use std::time::Instant;

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};

use crate::classification::{RankingEngine, SemanticClassifier, SymbolDemangler};
use crate::container::elf::ElfParser;
use crate::container::macho::MachoParser;
use crate::container::pe::PeParser;
use crate::extraction::{BasicExtractor, StringExtractor};
use crate::output::{OutputMetadata, format_output};
use crate::types::{
    BinaryFormat, ContainerInfo, FoundString, SectionInfo, SectionType, StringContext, StringyError,
};
use goblin::Object;

/// Top-level pipeline orchestrator.
#[derive(Debug)]
pub struct Pipeline {
    config: PipelineConfig,
}

impl Pipeline {
    /// Create a new `Pipeline` with the given configuration.
    #[must_use]
    pub fn new(config: PipelineConfig) -> Self {
        Self { config }
    }

    /// Run the full Stringy pipeline: load, parse, extract, classify, rank,
    /// normalize, filter, and output.
    ///
    /// # Errors
    ///
    /// Returns `StringyError` on I/O failure, parse failure, extraction
    /// failure, or output formatting failure.
    pub fn run(&self, file_path: &Path) -> crate::types::Result<()> {
        let start_time = Instant::now();
        let data = load_file(file_path)?;

        let pb = create_spinner();

        // -- Parsing --
        set_stage(&pb, "Parsing...");
        let container_info = parse_container(&data);

        // -- Extracting --
        set_stage(&pb, "Extracting...");
        let mut strings = extract_strings(&data, &container_info, &self.config)?;

        // -- Raw-mode early exit --
        // Raw mode bypasses classification, ranking, and normalization.
        // Reset dedup-assigned scores/tags and restore extraction offset order.
        if self.config.raw_mode {
            for s in &mut strings {
                s.score = 0;
                s.display_score = Some(0);
                s.tags = Vec::new();
            }
            strings.sort_by_key(|s| s.offset);
            pb.finish_and_clear();
            let elapsed = start_time.elapsed();
            return emit_output(
                &strings,
                &self.config,
                &container_info,
                strings.len(),
                elapsed,
            );
        }

        // -- Classifying --
        set_stage(&pb, "Classifying...");
        let (demangle_failures, classification_failures) =
            classify_strings(&mut strings, &container_info);

        // -- Ranking --
        set_stage(&pb, "Ranking...");
        rank_strings(&mut strings, &container_info, self.config.debug_mode);

        // -- Score normalization --
        // Map raw internal scores to a bounded 0-100 display range for all
        // non-raw executions so that output always shows normalized values.
        ScoreNormalizer::new().normalize(&mut strings);

        // -- Filtering --
        let total_count = strings.len();
        let filtered = FilterEngine::new().apply(strings, &self.config.filter_config);

        // -- Finish spinner, emit warnings --
        pb.finish_and_clear();
        emit_processing_warnings(demangle_failures, classification_failures);

        // -- Informational diagnostic when filters match nothing --
        if filtered.is_empty() && total_count > 0 {
            eprintln!(
                "Info: No strings matched the current filters ({total_count} extracted, 0 shown)"
            );
        }

        // -- Output --
        let elapsed = start_time.elapsed();
        emit_output(
            &filtered,
            &self.config,
            &container_info,
            total_count,
            elapsed,
        )
    }
}

// ---------------------------------------------------------------------------
// Private helpers -- each keeps `Pipeline::run` readable and `mod.rs` under
// the 500-line file limit.
// ---------------------------------------------------------------------------

/// Load file contents via memory-mapped I/O.
///
/// Uses [`mmap_guard::map_file()`] for zero-copy read-only access with
/// advisory locking and pre-flight validation. Empty files are
/// short-circuited to an empty buffer (there are no strings to extract).
fn load_file(file_path: &Path) -> crate::types::Result<mmap_guard::FileData> {
    match mmap_guard::map_file(file_path) {
        Ok(data) => Ok(data),
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
            // mmap_guard rejects empty files (zero bytes cannot be mapped).
            // Return an empty buffer so the pipeline can proceed gracefully.
            Ok(mmap_guard::FileData::Loaded(Vec::new()))
        }
        Err(e) => Err(StringyError::IoError(std::io::Error::new(
            e.kind(),
            format!("{}: {}", file_path.display(), e),
        ))),
    }
}

/// Create an `indicatif` spinner targeting stderr.
///
/// Returns a hidden (no-op) spinner when `NO_COLOR` is set or stderr is not a
/// terminal, respecting the <https://no-color.org> convention.
fn create_spinner() -> ProgressBar {
    if std::env::var_os("NO_COLOR").is_some()
        || !std::io::IsTerminal::is_terminal(&std::io::stderr())
    {
        return ProgressBar::hidden();
    }

    let pb = ProgressBar::with_draw_target(None, ProgressDrawTarget::stderr());
    if let Ok(style) = ProgressStyle::default_spinner().template("{spinner} {msg}") {
        pb.set_style(style);
    }
    pb.enable_steady_tick(std::time::Duration::from_millis(120));
    pb
}

/// Update the spinner message.
fn set_stage(pb: &ProgressBar, msg: &str) {
    pb.set_message(msg.to_string());
}

/// Parse container with a single `Object::parse()` call, avoiding the
/// double-parse that occurred when `detect_format()` and `parser.parse()`
/// each parsed independently.
fn parse_container(data: &[u8]) -> ContainerInfo {
    let parsed = match Object::parse(data) {
        Ok(obj) => obj,
        Err(e) => {
            eprintln!(
                "Info: Source identified as unknown data ({e}); \
                 proceeding with unstructured byte scan"
            );
            return build_unknown_container(data);
        }
    };

    let result = match parsed {
        Object::Elf(elf) => ElfParser::new().parse_from(&elf),
        Object::PE(pe) => PeParser::new().parse_from(&pe, data),
        Object::Mach(mach) => MachoParser::new().parse_from(&mach, data),
        _ => {
            eprintln!(
                "Info: Unsupported container format; \
                 proceeding with unstructured byte scan"
            );
            return build_unknown_container(data);
        }
    };

    match result {
        Ok(info) => info,
        Err(e) => {
            eprintln!(
                "Info: Container parse failed ({e}); \
                 proceeding with unstructured byte scan"
            );
            build_unknown_container(data)
        }
    }
}

/// Build a synthetic `ContainerInfo` for unknown/unparseable data.
fn build_unknown_container(data: &[u8]) -> ContainerInfo {
    let section = SectionInfo::new(
        "raw-bytes".to_string(),
        0,
        data.len() as u64,
        SectionType::Other,
        1.0,
    );
    ContainerInfo::new(BinaryFormat::Unknown, vec![section], vec![], vec![], None)
}

/// Run the extraction stage.
fn extract_strings(
    data: &[u8],
    container_info: &ContainerInfo,
    config: &PipelineConfig,
) -> crate::types::Result<Vec<FoundString>> {
    let extractor = BasicExtractor::new();
    extractor.extract(data, container_info, &config.extraction_config)
}

/// Classify and demangle all strings. Returns (demangle_failures, classification_failures).
///
/// In debug builds, the environment variables `STRINGY_TEST_INJECT_DEMANGLE_FAILURES`
/// and `STRINGY_TEST_INJECT_CLASSIFY_FAILURES` can inject additional failure counts
/// for integration testing of the warning emission path.
fn classify_strings(strings: &mut [FoundString], container_info: &ContainerInfo) -> (usize, usize) {
    let classifier = SemanticClassifier::new();
    let demangler = SymbolDemangler::new();

    let mut demangle_failures: usize = 0;
    let mut classification_failures: usize = 0;

    // Debug-only failure injection for integration testing of warning paths.
    #[cfg(debug_assertions)]
    {
        if let Ok(val) = std::env::var("STRINGY_TEST_INJECT_DEMANGLE_FAILURES")
            && let Ok(n) = val.parse::<usize>()
        {
            demangle_failures += n;
        }
        if let Ok(val) = std::env::var("STRINGY_TEST_INJECT_CLASSIFY_FAILURES")
            && let Ok(n) = val.parse::<usize>()
        {
            classification_failures += n;
        }
    }

    // Build section lookup map once for O(1) per-string access
    let section_map: std::collections::HashMap<&str, SectionType> = container_info
        .sections
        .iter()
        .map(|sec| (sec.name.as_str(), sec.section_type))
        .collect();

    // Suppress panic output from catch_unwind -- the default hook prints to stderr
    // before we can catch the panic, which pollutes user output.
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    for s in strings.iter_mut() {
        // Demangle (wrapping in catch_unwind for safety against third-party crate panics).
        // Only clone text for strings that look like mangled symbols to avoid
        // unconditional allocation overhead.
        let looks_mangled =
            s.text.starts_with("_Z") || s.text.starts_with("_R") || s.text.starts_with('?');
        let text_backup = if looks_mangled {
            Some(s.text.clone())
        } else {
            None
        };
        if looks_mangled {
            let demangle_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                demangler.demangle(s);
            }));
            if demangle_result.is_err() {
                demangle_failures += 1;
                if let Some(backup) = text_backup {
                    s.text = backup;
                }
            }
        }

        // Classify (catch panics from classifier as actual failures)
        let section_type = s
            .section
            .as_deref()
            .and_then(|name| section_map.get(name).copied())
            .unwrap_or(SectionType::Other);

        let context = StringContext::new(section_type, container_info.format, s.encoding, s.source);
        let context = match &s.section {
            Some(name) => context.with_section_name(name.clone()),
            None => context,
        };

        let text_ref = s.text.as_str();
        let classify_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            classifier.classify(text_ref, &context)
        }));

        match classify_result {
            Ok(tags) => {
                for tag in tags {
                    if !s.tags.contains(&tag) {
                        s.tags.push(tag);
                    }
                }
            }
            Err(_) => {
                classification_failures += 1;
            }
        }
    }

    // Restore the previous panic hook
    std::panic::set_hook(prev_hook);

    (demangle_failures, classification_failures)
}

/// Score every string using the ranking engine.
fn rank_strings(strings: &mut [FoundString], container_info: &ContainerInfo, debug_mode: bool) {
    let ranking_engine = RankingEngine::new(debug_mode);

    // Build section lookup map once for O(1) per-string access
    let section_map: std::collections::HashMap<&str, &SectionInfo> = container_info
        .sections
        .iter()
        .map(|sec| (sec.name.as_str(), sec))
        .collect();

    for s in strings.iter_mut() {
        let section_info = s
            .section
            .as_deref()
            .and_then(|name| section_map.get(name).copied());
        ranking_engine.calculate_score(s, section_info);
    }
}

/// Format a processing-warning message when counters are non-zero.
///
/// Returns `Some(message)` when at least one counter is positive, `None`
/// otherwise. The returned message always starts with "Warning:" and only
/// includes non-zero counters.
#[must_use]
fn format_processing_warnings(
    demangle_failures: usize,
    classification_failures: usize,
) -> Option<String> {
    if demangle_failures == 0 && classification_failures == 0 {
        return None;
    }
    let mut parts = Vec::new();
    if demangle_failures > 0 {
        parts.push(format!(
            "{demangle_failures} symbol(s) could not be demangled (invalid mangled names)"
        ));
    }
    if classification_failures > 0 {
        parts.push(format!(
            "{classification_failures} string(s) failed semantic classification (unexpected content)"
        ));
    }
    Some(format!(
        "Warning: {}. Results may be incomplete for affected strings.",
        parts.join("; ")
    ))
}

/// Emit processing warnings to stderr when counters are non-zero.
fn emit_processing_warnings(demangle_failures: usize, classification_failures: usize) {
    if let Some(msg) = format_processing_warnings(demangle_failures, classification_failures) {
        eprintln!("{msg}");
    }
}

/// Format and print the final output.
fn emit_output(
    strings: &[FoundString],
    config: &PipelineConfig,
    container_info: &ContainerInfo,
    total_count: usize,
    elapsed: std::time::Duration,
) -> crate::types::Result<()> {
    let filtered_count = strings.len();

    let mut metadata = OutputMetadata::new(
        config.binary_name.clone(),
        config.output_format,
        total_count,
        filtered_count,
    )
    .with_show_summary(config.show_summary)
    .with_binary_format(container_info.format)
    .with_analysis_duration(elapsed);

    if config.show_summary {
        let top_tags = OutputMetadata::compute_top_tags(strings, 5);
        metadata = metadata.with_top_tags(top_tags);
    }

    let output = format_output(strings, &metadata)?;
    if !output.is_empty() {
        print!("{output}");
        if !output.ends_with('\n') {
            println!();
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warning_format_both_zero_returns_none() {
        assert!(format_processing_warnings(0, 0).is_none());
    }

    #[test]
    fn warning_format_demangle_only() {
        let msg = format_processing_warnings(3, 0).expect("must produce warning");
        assert!(msg.starts_with("Warning:"));
        assert!(msg.contains("3 symbol(s) could not be demangled"));
        assert!(!msg.contains("classification"));
    }

    #[test]
    fn warning_format_classify_only() {
        let msg = format_processing_warnings(0, 7).expect("must produce warning");
        assert!(msg.starts_with("Warning:"));
        assert!(msg.contains("7 string(s) failed semantic classification"));
        assert!(!msg.contains("demangled"));
    }

    #[test]
    fn warning_format_both_nonzero() {
        let msg = format_processing_warnings(2, 5).expect("must produce warning");
        assert!(msg.starts_with("Warning:"));
        assert!(msg.contains("2 symbol(s) could not be demangled"));
        assert!(msg.contains("5 string(s) failed semantic classification"));
    }

    #[test]
    fn load_file_happy_path() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().expect("create temp file");
        tmp.write_all(b"hello world").expect("write bytes");
        tmp.flush().expect("flush");

        let data = load_file(tmp.path()).expect("load_file must succeed");
        let bytes: &[u8] = &data;
        assert!(!bytes.is_empty(), "loaded data must be non-empty");
        assert_eq!(bytes, b"hello world");
    }

    #[test]
    fn load_file_empty_file_returns_empty_buffer() {
        let tmp = tempfile::NamedTempFile::new().expect("create temp file");
        // File exists but has zero bytes written

        let data = load_file(tmp.path()).expect("load_file must succeed for empty file");
        let bytes: &[u8] = &data;
        assert!(bytes.is_empty(), "empty file must produce empty buffer");
    }

    #[test]
    fn load_file_missing_file_returns_io_error() {
        let tmp = tempfile::NamedTempFile::new().expect("create temp file");
        let path = tmp.path().to_path_buf();
        drop(tmp); // delete the file

        let result = load_file(&path);
        assert!(result.is_err(), "missing file must return an error");
        let err = result.unwrap_err();
        assert!(
            matches!(err, StringyError::IoError(_)),
            "error must be IoError, got: {err:?}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn load_file_permission_denied_returns_io_error() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let mut tmp = tempfile::NamedTempFile::new().expect("create temp file");
        tmp.write_all(b"secret content").expect("write bytes");
        tmp.flush().expect("flush");

        let path = tmp.path().to_path_buf();

        // Remove all permissions to trigger a permission-denied error.
        let no_perms = std::fs::Permissions::from_mode(0o000);
        std::fs::set_permissions(&path, no_perms).expect("set permissions");

        let result = load_file(&path);

        // Restore permissions before assertions so cleanup always succeeds.
        let restored = std::fs::Permissions::from_mode(0o644);
        std::fs::set_permissions(&path, restored).expect("restore permissions");

        assert!(result.is_err(), "permission-denied must return an error");
        let err = result.unwrap_err();
        assert!(
            matches!(err, StringyError::IoError(_)),
            "error must be IoError, got: {err:?}"
        );
    }
}
