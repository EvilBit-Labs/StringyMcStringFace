#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::{Parser, ValueEnum};

use stringy::container::{create_parser, detect_format};
use stringy::extraction::{BasicExtractor, ExtractionConfig, StringExtractor};
use stringy::output::{OutputFormat, OutputMetadata, format_output};

/// Output format selection for the CLI.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliOutputFormat {
    /// Human-readable table output
    Table,
    /// JSONL output (one JSON object per line)
    Json,
    /// YARA rule template output
    Yara,
}

impl CliOutputFormat {
    /// Convert the CLI format selection to the library OutputFormat.
    fn to_output_format(self) -> OutputFormat {
        match self {
            Self::Table => OutputFormat::Table,
            Self::Json => OutputFormat::Json,
            Self::Yara => OutputFormat::Yara,
        }
    }
}

/// A smarter alternative to the strings command that leverages format-specific knowledge
#[derive(Parser)]
#[command(name = "stringy")]
#[command(about = "Extract meaningful strings from binary files")]
#[command(version)]
struct Cli {
    /// Input binary file to analyze
    #[arg(value_name = "FILE")]
    input: PathBuf,

    /// Output format
    #[arg(long, short = 'f', value_enum, default_value_t = CliOutputFormat::Table)]
    format: CliOutputFormat,

    /// Minimum string length in bytes (must be >= 1)
    #[arg(long, short = 'l', default_value_t = 4)]
    min_length: usize,
}

fn run(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let data = std::fs::read(&cli.input)?;

    let binary_format = detect_format(&data);
    let parser = create_parser(binary_format)?;
    let container_info = parser.parse(&data)?;

    let config = ExtractionConfig {
        min_length: cli.min_length,
        min_ascii_length: cli.min_length,
        min_wide_length: cli.min_length,
        ..ExtractionConfig::default()
    };
    config.validate()?;

    let extractor = BasicExtractor::new();
    let strings = extractor.extract(&data, &container_info, &config)?;

    let binary_name = cli
        .input
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| cli.input.display().to_string());

    let output_format = cli.format.to_output_format();
    // No post-extraction filtering yet, so total == filtered
    let metadata = OutputMetadata::new(binary_name, output_format, strings.len(), strings.len());

    let output = format_output(&strings, &metadata)?;
    print!("{output}");
    // Ensure output ends with newline for proper shell behavior
    if !output.ends_with('\n') {
        println!();
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    run(&cli)
}
