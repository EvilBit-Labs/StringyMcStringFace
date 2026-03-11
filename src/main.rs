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
    /// ASCII-encoded strings only
    Ascii,
    /// UTF-8 encoded strings only
    Utf8,
    /// UTF-16 in either byte order (LE or BE)
    Utf16,
    /// UTF-16 Little Endian only
    #[value(name = "utf16le")]
    Utf16Le,
    /// UTF-16 Big Endian only
    #[value(name = "utf16be")]
    Utf16Be,
}

/// Parse a positive usize (>= 1) from a CLI argument.
fn parse_positive_usize(s: &str) -> Result<usize, String> {
    let value: usize = s
        .parse()
        .map_err(|_| format!("'{s}' is not a valid positive integer"))?;
    if value == 0 {
        return Err("value must be at least 1".to_string());
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
    stringy -j binary.elf\n  \
    stringy --yara malware.dll\n  \
    cat binary.exe | stringy -\n  \
    stringy -m 8 --only-tags url --only-tags domain binary.exe\n  \
    stringy -t 50 -j binary.elf\n\n\
    More info: https://github.com/EvilBit-Labs/Stringy")]
struct Cli {
    /// Input binary file to analyze (use "-" for stdin)
    #[arg(value_name = "FILE")]
    input: InputArg,

    /// Emit JSONL output (one JSON object per line)
    #[arg(short = 'j', long, conflicts_with = "yara")]
    json: bool,

    /// Emit YARA rule template output
    #[arg(long, conflicts_with = "json")]
    yara: bool,

    /// Only include strings with these tags (repeatable)
    #[arg(
        long = "only-tags",
        action = ArgAction::Append,
        value_parser = Tag::from_str,
        value_name = "TAG",
        long_help = "Include only strings with this tag. Repeat the flag for multiple tags (OR logic).\n\
            Valid tags: url, domain, ipv4, ipv6, filepath, regpath, guid, email, b64, fmt,\n\
            user-agent-ish, demangled, import, export, version, manifest, resource,\n\
            dylib-path, rpath, rpath-var, framework-path"
    )]
    only_tags: Vec<Tag>,

    /// Exclude strings with these tags (repeatable)
    #[arg(
        long = "no-tags",
        action = ArgAction::Append,
        value_parser = Tag::from_str,
        value_name = "TAG",
        long_help = "Exclude strings with this tag. Repeat the flag for multiple tags (OR logic).\n\
            Valid tags: url, domain, ipv4, ipv6, filepath, regpath, guid, email, b64, fmt,\n\
            user-agent-ish, demangled, import, export, version, manifest, resource,\n\
            dylib-path, rpath, rpath-var, framework-path"
    )]
    no_tags: Vec<Tag>,

    /// Minimum string length in bytes (must be >= 1)
    #[arg(short = 'm', long = "min-len", value_name = "N", value_parser = parse_positive_usize)]
    min_len: Option<usize>,

    /// Show only the top N strings by score
    #[arg(short = 't', long, value_name = "N", value_parser = parse_positive_usize)]
    top: Option<usize>,

    /// Filter by encoding [possible values: ascii, utf8, utf16, utf16le, utf16be]
    #[arg(short = 'e', long, value_enum, value_name = "ENCODING")]
    enc: Option<CliEncoding>,

    /// Raw output: no tags, no scores, no headers
    #[arg(long, conflicts_with_all = ["only_tags", "no_tags", "top", "debug", "yara"])]
    raw: bool,

    /// Print a summary banner after output
    #[arg(long, conflicts_with_all = ["json", "yara"])]
    summary: bool,

    /// Include debug metadata in output (extraction source, section info, weights)
    #[arg(long, conflicts_with = "raw")]
    debug: bool,
}

fn run(cli: &Cli) -> Result<(), StringyError> {
    // Runtime validation: tag overlap between --only-tags and --no-tags
    let overlap: Vec<&Tag> = cli
        .only_tags
        .iter()
        .filter(|t| cli.no_tags.contains(t))
        .collect();
    if !overlap.is_empty() {
        let tag_names: Vec<String> = overlap.iter().map(|t| format!("{t:?}")).collect();
        return Err(StringyError::ValidationError(format!(
            "conflicting tag filters: {} appear in both --only-tags and --no-tags\n\
             Remove these tags from one of the filter lists to continue.",
            tag_names.join(", ")
        )));
    }

    // Runtime validation: --summary requires a TTY
    if cli.summary && !std::io::stdout().is_terminal() {
        return Err(StringyError::ValidationError(
            "--summary requires terminal output (not supported for piped/redirected output)\n\
             Try removing --summary or run without output redirection."
                .to_string(),
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
    let extraction_config = if let Some(n) = cli.min_len {
        let config = ExtractionConfig::default().with_min_length(n);
        config.validate()?;
        config
    } else {
        let config = ExtractionConfig::default();
        config.validate()?;
        config
    };

    // -- Filter config --
    let mut filter_config = FilterConfig::new();
    if let Some(n) = cli.min_len {
        filter_config = filter_config.with_min_length(n);
    }
    if let Some(enc) = cli.enc {
        filter_config = filter_config.with_encoding(cli_encoding_to_filter(enc));
    }
    if !cli.only_tags.is_empty() {
        filter_config = filter_config.with_include_tags(cli.only_tags.clone());
    }
    if !cli.no_tags.is_empty() {
        filter_config = filter_config.with_exclude_tags(cli.no_tags.clone());
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
            if std::io::stderr().is_terminal() {
                eprint!("Reading from stdin... ");
            }
            let data = cli.input.read().map_err(|e| {
                StringyError::IoError(std::io::Error::new(
                    e.kind(),
                    format!("{}: {}", cli.input, e),
                ))
            })?;
            if std::io::stderr().is_terminal() {
                eprintln!("{} bytes", data.len());
            }
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
        std::process::exit(e.exit_code());
    }
}
