//! Basic string extraction from a binary file.
//!
//! This example demonstrates the fundamental workflow for extracting strings
//! from a binary file using Stringy.
//!
//! Usage: cargo run --example basic_extraction <binary_file>

use std::env;
use std::fs;
use stringy::container::{create_parser, detect_format};
use stringy::extraction::{BasicExtractor, ExtractionConfig, StringExtractor};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <binary_file>", args[0]);
        std::process::exit(1);
    }

    let path = &args[1];
    println!("Analyzing: {}", path);

    // Read the binary file
    let data = fs::read(path)?;
    println!("File size: {} bytes", data.len());

    // Detect the binary format
    let format = detect_format(&data);
    println!("Detected format: {:?}", format);

    // Create a parser for the detected format
    let parser = create_parser(format)?;
    let container_info = parser.parse(&data)?;

    println!(
        "Found {} sections, {} imports, {} exports",
        container_info.sections.len(),
        container_info.imports.len(),
        container_info.exports.len()
    );

    // Extract strings using the basic extractor
    let extractor = BasicExtractor::new();
    let config = ExtractionConfig::default();
    let strings = extractor.extract(&data, &container_info, &config)?;

    println!("\nExtracted {} strings\n", strings.len());

    // Display the top 20 strings by score
    let mut sorted_strings = strings.clone();
    sorted_strings.sort_by(|a, b| b.score.cmp(&a.score));

    println!("Top strings by score:");
    println!("{:-<60}", "");
    for string in sorted_strings.iter().take(20) {
        let tags: Vec<_> = string.tags.iter().map(|t| format!("{:?}", t)).collect();
        let tags_str = if tags.is_empty() {
            String::new()
        } else {
            format!(" [{}]", tags.join(", "))
        };
        println!(
            "{:4} | {:50}{}",
            string.score,
            if string.text.len() > 50 {
                format!("{}...", &string.text[..47])
            } else {
                string.text.clone()
            },
            tags_str
        );
    }

    Ok(())
}
