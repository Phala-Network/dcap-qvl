//! CLI for dcap-qvl
//! Usage:
//! dcap-qvl decode-quote [--hex] <quote_file>

use std::path::PathBuf;

use anyhow::{Context as _, Result};
use clap::{Args, Parser, Subcommand};
use dcap_qvl::collateral::{get_collateral, get_collateral_from_pcs};
use dcap_qvl::quote::Quote;
use dcap_qvl::verify::verify;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Decode a quote file
    Decode(DecodeQuoteArgs),
    /// Verify a quote file
    Verify(VerifyQuoteArgs),
}

#[derive(Args)]
struct DecodeQuoteArgs {
    /// Indicate the quote file is in hex format
    #[arg(long)]
    hex: bool,
    /// The quote file
    quote_file: PathBuf,
    /// Print fmspc
    #[arg(long)]
    fmspc: bool,
}

#[derive(Args)]
struct VerifyQuoteArgs {
    /// Indicate the quote file is in hex format
    #[arg(long)]
    hex: bool,
    /// The quote file
    quote_file: PathBuf,
}

fn hex_decode(input: &[u8], is_hex: bool) -> Result<Vec<u8>> {
    if is_hex {
        let input = input.strip_prefix(b"0x").unwrap_or(input);
        let input = input.strip_suffix(b"\n").unwrap_or(input);
        hex::decode(input).context("Failed to decode quote file")
    } else {
        Ok(input.to_vec())
    }
}

fn command_decode_quote(args: DecodeQuoteArgs) -> Result<()> {
    let quote = std::fs::read(args.quote_file).context("Failed to read quote file")?;
    let quote = hex_decode(&quote, args.hex)?;
    let decoded_quote = Quote::parse(&quote).context("Failed to parse quote")?;
    if args.fmspc {
        println!("fmspc={}", hex::encode(decoded_quote.fmspc().unwrap()).to_uppercase());
    } else {
        let json = serde_json::to_string(&decoded_quote).context("Failed to serialize quote")?;
        println!("{}", json);
    }
    Ok(())
}

async fn command_verify_quote(args: VerifyQuoteArgs) -> Result<()> {
    let quote = std::fs::read(args.quote_file).context("Failed to read quote file")?;
    let quote = hex_decode(&quote, args.hex)?;
    let pccs_url = std::env::var("PCCS_URL").unwrap_or_default();
    let collateral = if pccs_url.is_empty() {
        eprintln!("Getting collateral from PCS...");
        get_collateral_from_pcs(&quote, std::time::Duration::from_secs(60)).await?
    } else {
        eprintln!("Getting collateral from {pccs_url}");
        get_collateral(&pccs_url, &quote, std::time::Duration::from_secs(60)).await?
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let report = verify(&quote, &collateral, now)
        .ok()
        .context("Failed to verify quote")?;
    println!("{}", serde_json::to_string(&report).unwrap());
    eprintln!("Quote verified");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Decode(args) => command_decode_quote(args).context("Failed to decode quote"),
        Commands::Verify(args) => command_verify_quote(args)
            .await
            .context("Failed to verify quote"),
    }
}
