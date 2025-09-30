use clap::Parser;
use std::path::PathBuf;

/// A smarter alternative to the strings command that leverages format-specific knowledge
#[derive(Parser)]
#[command(name = "stringy")]
#[command(about = "Extract meaningful strings from binary files")]
#[command(version)]
struct Cli {
    /// Input binary file to analyze
    #[arg(value_name = "FILE")]
    input: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _cli = Cli::parse();

    // TODO: Implement main extraction pipeline
    println!("Stringy - Binary string extraction tool");
    println!("Implementation coming soon...");

    Ok(())
}
