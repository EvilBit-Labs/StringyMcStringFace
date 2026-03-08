#![forbid(unsafe_code)]

use std::io::IsTerminal;
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;

use clap::{ArgAction, Parser, ValueEnum};
use patharg::InputArg;
use tempfile::NamedTempFile;

use stringy::extraction::ExtractionConfig;
use stringy::output::OutputFormat;
use stringy::types::{StringyError, Tag};
use stringy::{Encoding, EncodingFilter, FilterConfig, Pipeline, PipelineConfig};

/// Encoding filter for string extraction
#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliEncoding {
    Ascii,
    Utf8,
    Utf16,
    #[value(name = "utf16le")]
    Utf16Le,
    #[value(name = "utf16be")]
    Utf16Be,
}

/// Parse a positive usize (>= 1) from a CLI argument.
fn parse_positive_usize(s: &str) -> Result<usize, String> {
    let value: usize = s.parse().map_err(|e| format!("invalid value '{s}': {e}"))?;
    if value == 0 {
        return Err("value must be >= 1".to_string());
    }
    Ok(value)
}

/// Map CLI encoding variant to pipeline `EncodingFilter`.
fn cli_encoding_to_filter(enc: CliEncoding) -> EncodingFilter {
    match enc {
        CliEncoding::Ascii => EncodingFilter::Exact(Encoding::Ascii),
        CliEncoding::Utf8 => EncodingFilter::Exact(Encoding::Utf8),
        CliEncoding::Utf16 => EncodingFilter::Utf16Any,
        CliEncoding::Utf16Le => EncodingFilter::Exact(Encoding::Utf16Le),
        CliEncoding::Utf16Be => EncodingFilter::Exact(Encoding::Utf16Be),
    }
}

/// A smarter alternative to the strings command that leverages format-specific knowledge
#[derive(Parser)]
#[command(name = "stringy", author, version)]
#[command(about = "Extract meaningful strings from binary files")]
#[command(
    long_about = "A smarter alternative to the strings command that leverages \
    format-specific knowledge.\n\n\
    Stringy is section-aware, encoding-aware, and semantically intelligent. \
    It extracts strings from ELF, PE, and Mach-O binaries, classifies them \
    (URLs, file paths, IPs, GUIDs, etc.), and ranks results by relevance."
)]
#[command(after_help = "EXAMPLES:\n  \
    stringy binary.exe\n  \
    stringy --json binary.elf\n  \
    stringy --yara malware.dll\n  \
    stringy --min-len 8 --only-tags url,domain binary.exe\n  \
    stringy --top 50 --json binary.elf\n\n\
    More info: https://github.com/EvilBit-Labs/Stringy")]
struct Cli {
    /// Input binary file to analyze (use "-" for stdin)
    #[arg(value_name = "FILE")]
    input: InputArg,

    /// Emit JSONL output (one JSON object per line)
    #[arg(long, conflicts_with = "yara")]
    json: bool,

    /// Emit YARA rule template output
    #[arg(long, conflicts_with = "json")]
    yara: bool,

    /// Only include strings with these tags (repeatable)
    #[arg(long = "only-tags", action = ArgAction::Append, value_parser = Tag::from_str)]
    only_tags: Vec<Tag>,

    /// Exclude strings with these tags (repeatable)
    #[arg(long = "notags", action = ArgAction::Append, value_parser = Tag::from_str)]
    notags: Vec<Tag>,

    /// Minimum string length in bytes (must be >= 1)
    #[arg(long = "min-len", value_parser = parse_positive_usize)]
    min_len: Option<usize>,

    /// Show only the top N strings by score
    #[arg(long, value_parser = parse_positive_usize)]
    top: Option<usize>,

    /// Filter by encoding
    #[arg(long, value_enum)]
    enc: Option<CliEncoding>,

    /// Raw output: no tags, no scores, no headers
    #[arg(long, conflicts_with_all = ["only_tags", "notags", "top", "debug", "yara"])]
    raw: bool,

    /// Print a summary banner after output
    #[arg(long, conflicts_with_all = ["json", "yara"])]
    summary: bool,

    /// Include debug metadata in output
    #[arg(long, conflicts_with = "raw")]
    debug: bool,
}

fn run(cli: &Cli) -> Result<(), StringyError> {
    // Runtime validation: tag overlap between --only-tags and --notags
    let overlap: Vec<&Tag> = cli
        .only_tags
        .iter()
        .filter(|t| cli.notags.contains(t))
        .collect();
    if !overlap.is_empty() {
        return Err(StringyError::ValidationError(format!(
            "tag(s) {overlap:?} appear in both --only-tags and --notags"
        )));
    }

    // Runtime validation: --summary requires a TTY
    if cli.summary && !std::io::stdout().is_terminal() {
        return Err(StringyError::ValidationError(
            "--summary requires a TTY; redirect output or omit --summary".to_string(),
        ));
    }

    // Resolve input to a file path (Pipeline::run requires &Path)
    let (file_path, _temp_guard) = resolve_input_path(cli)?;

    let binary_name = match &cli.input {
        InputArg::Stdin => "<stdin>".to_string(),
        InputArg::Path(p) => p
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| p.display().to_string()),
    };

    // -- Extraction config --
    let min_length = cli.min_len.unwrap_or(4);
    let extraction_config = ExtractionConfig {
        min_length,
        min_ascii_length: min_length,
        min_wide_length: min_length,
        ..ExtractionConfig::default()
    };
    extraction_config.validate()?;

    // -- Filter config --
    let mut filter_config = FilterConfig::new().with_min_length(min_length);
    if let Some(enc) = cli.enc {
        filter_config = filter_config.with_encoding(cli_encoding_to_filter(enc));
    }
    if !cli.only_tags.is_empty() {
        filter_config = filter_config.with_include_tags(cli.only_tags.clone());
    }
    if !cli.notags.is_empty() {
        filter_config = filter_config.with_exclude_tags(cli.notags.clone());
    }
    if let Some(n) = cli.top {
        filter_config = filter_config.with_top_n(n);
    }

    // -- Output format --
    let output_format = if cli.json {
        OutputFormat::Json
    } else if cli.yara {
        OutputFormat::Yara
    } else {
        OutputFormat::Table
    };

    // -- Pipeline config --
    let config = PipelineConfig::new(binary_name)
        .with_extraction_config(extraction_config)
        .with_filter_config(filter_config)
        .with_debug_mode(cli.debug)
        .with_raw_mode(cli.raw)
        .with_show_summary(cli.summary)
        .with_output_format(output_format);

    Pipeline::new(config).run(&file_path)?;

    Ok(())
}

/// Resolve `InputArg` to a filesystem path. For stdin, writes the data to a
/// unique temporary file and returns the path along with a guard that cleans
/// it up when dropped.
fn resolve_input_path(cli: &Cli) -> Result<(PathBuf, Option<NamedTempFile>), StringyError> {
    match &cli.input {
        InputArg::Path(p) => Ok((p.clone(), None)),
        InputArg::Stdin => {
            let data = cli.input.read().map_err(|e| {
                StringyError::IoError(std::io::Error::new(
                    e.kind(),
                    format!("{}: {}", cli.input, e),
                ))
            })?;
            let mut temp_file = NamedTempFile::with_prefix("stringy-stdin-").map_err(|e| {
                StringyError::IoError(std::io::Error::new(
                    e.kind(),
                    format!("failed to create temp file: {e}"),
                ))
            })?;
            temp_file.write_all(&data).map_err(|e| {
                StringyError::IoError(std::io::Error::new(
                    e.kind(),
                    format!("failed to write temp file: {e}"),
                ))
            })?;
            let path = temp_file.path().to_path_buf();
            Ok((path, Some(temp_file)))
        }
    }
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(&cli) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
