//! CLI for dcap-qvl
//! Usage:
//! dcap-qvl decode-quote [--hex] <quote_file>

use std::path::PathBuf;

use anyhow::{Context as _, Result};
use clap::{Args, Parser, Subcommand};
use dcap_qvl::quote::Quote;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Decode a quote file
    DecodeQuote(DecodeQuoteArgs),
}

#[derive(Args)]
struct DecodeQuoteArgs {
    /// Indicate the quote file is in hex format
    #[arg(long)]
    hex: bool,
    /// The quote file
    quote_file: PathBuf,
}

fn decode_quote(args: DecodeQuoteArgs) -> Result<Quote> {
    let quote = std::fs::read(args.quote_file).context("Failed to read quote file")?;
    let quote = if args.hex {
        let quote = quote.strip_prefix(b"0x").unwrap_or(&quote);
        hex::decode(quote).context("Failed to decode quote file")?
    } else {
        quote
    };
    let quote = Quote::parse(&quote).context("Failed to parse quote")?;
    Ok(quote)
}

fn command_decode_quote(args: DecodeQuoteArgs) -> Result<()> {
    let quote = decode_quote(args).context("Failed to decode quote")?;
    let json = serde_json::to_string(&quote).context("Failed to serialize quote")?;
    println!("{}", json);
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::DecodeQuote(args) => command_decode_quote(args).context("Failed to decode quote"),
    }
}
