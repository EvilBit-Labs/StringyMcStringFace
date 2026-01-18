//! Extract network indicators (URLs, IPs, domains) from a binary.
//!
//! This example demonstrates how to extract and filter strings that contain
//! network-related indicators useful for threat intelligence.
//!
//! Usage: cargo run --example network_indicators <binary_file>

use std::env;
use std::fs;
use stringy::container::{create_parser, detect_format};
use stringy::extraction::{BasicExtractor, ExtractionConfig, StringExtractor};
use stringy::types::Tag;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <binary_file>", args[0]);
        std::process::exit(1);
    }

    let path = &args[1];
    println!("Extracting network indicators from: {}\n", path);

    // Read and parse the binary
    let data = fs::read(path)?;
    let format = detect_format(&data);
    let parser = create_parser(format)?;
    let container_info = parser.parse(&data)?;

    // Extract strings with default configuration
    let extractor = BasicExtractor::new();
    let config = ExtractionConfig::default();
    let strings = extractor.extract(&data, &container_info, &config)?;

    // Filter for network-related tags
    let network_tags = [Tag::Url, Tag::Domain, Tag::IPv4, Tag::IPv6];

    let network_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.tags.iter().any(|t| network_tags.contains(t)))
        .collect();

    if network_strings.is_empty() {
        println!("No network indicators found.");
        return Ok(());
    }

    println!("Found {} network indicators:\n", network_strings.len());

    // Group by tag type
    println!("=== URLs ===");
    for s in network_strings
        .iter()
        .filter(|s| s.tags.contains(&Tag::Url))
    {
        println!("  {}", s.text);
    }

    println!("\n=== Domains ===");
    for s in network_strings
        .iter()
        .filter(|s| s.tags.contains(&Tag::Domain))
    {
        println!("  {}", s.text);
    }

    println!("\n=== IPv4 Addresses ===");
    for s in network_strings
        .iter()
        .filter(|s| s.tags.contains(&Tag::IPv4))
    {
        println!("  {}", s.text);
    }

    println!("\n=== IPv6 Addresses ===");
    for s in network_strings
        .iter()
        .filter(|s| s.tags.contains(&Tag::IPv6))
    {
        println!("  {}", s.text);
    }

    Ok(())
}
