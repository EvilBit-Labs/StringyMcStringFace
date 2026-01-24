//! Demonstrate different output formats (JSON, Table, YARA).
//!
//! This example shows how to format extracted strings in different output
//! formats suitable for various use cases.
//!
//! Usage: cargo run --example output_formats <binary_file> [format]
//!
//! Formats: table (default), json, yara

use std::env;
use std::fs;
use stringy::container::{create_parser, detect_format};
use stringy::extraction::{BasicExtractor, ExtractionConfig, StringExtractor};
use stringy::output::{OutputFormat, OutputMetadata, format_output};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <binary_file> [format]", args[0]);
        eprintln!("Formats: table (default), json, yara");
        std::process::exit(1);
    }

    let path = &args[1];
    let format_arg = args.get(2).map(|s| s.as_str()).unwrap_or("table");

    let output_format = match format_arg.to_lowercase().as_str() {
        "table" => OutputFormat::Table,
        "json" => OutputFormat::Json,
        "yara" => OutputFormat::Yara,
        _ => {
            eprintln!("Unknown format: {}. Use table, json, or yara.", format_arg);
            std::process::exit(1);
        }
    };

    // Read and parse the binary
    let data = fs::read(path)?;
    let format = detect_format(&data);
    let parser = create_parser(format)?;
    let container_info = parser.parse(&data)?;

    // Extract strings
    let extractor = BasicExtractor::new();
    let config = ExtractionConfig::default();
    let strings = extractor.extract(&data, &container_info, &config)?;

    // Limit to top 50 strings for demonstration
    let mut sorted_strings = strings;
    sorted_strings.sort_by(|a, b| b.score.cmp(&a.score));
    let top_strings: Vec<_> = sorted_strings.into_iter().take(50).collect();

    // Create output metadata
    let binary_name = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    let metadata = OutputMetadata::new(
        binary_name,
        output_format,
        top_strings.len(),
        top_strings.len(),
    );

    // Format and print output
    let output = format_output(&top_strings, &metadata)?;
    println!("{}", output);

    Ok(())
}
