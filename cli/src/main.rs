//! CLI for dcap-qvl
//! Usage:
//! dcap-qvl decode-quote [--hex] <quote_file>

use std::{fs, path::PathBuf};

use anyhow::{anyhow, Context as _, Result};
use clap::{Args, Parser, Subcommand};
use dcap_qvl::collateral::{get_collateral, get_collateral_from_pcs};
use dcap_qvl::intel;
use dcap_qvl::quote::Quote;
use dcap_qvl::verify::verify;
use der::Decode;
use x509_cert::Certificate;

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
    /// Extract Intel-specific identifiers from the PCK certificate
    #[command(name = "pckinfo")]
    PckInfo(PckInfoArgs),
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

#[derive(Args)]
struct PckInfoArgs {
    /// Indicate the quote file is in hex format
    #[arg(long)]
    hex: bool,
    /// The quote file
    quote_file: PathBuf,
}

fn hex_decode(input: &[u8], is_hex: bool) -> Result<Vec<u8>> {
    if is_hex {
        let input = input.strip_prefix(b"0x").unwrap_or(input);
        let compact = input
            .iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .collect::<Vec<u8>>();
        hex::decode(compact).context("Failed to decode quote file")
    } else {
        Ok(input.to_vec())
    }
}

fn command_decode_quote(args: DecodeQuoteArgs) -> Result<()> {
    let quote = std::fs::read(args.quote_file).context("Failed to read quote file")?;
    let quote = hex_decode(&quote, args.hex)?;
    let decoded_quote = Quote::parse(&quote).context("Failed to parse quote")?;
    if args.fmspc {
        println!(
            "fmspc={}",
            hex::encode(decoded_quote.fmspc().unwrap()).to_uppercase()
        );
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
        get_collateral_from_pcs(&quote).await?
    } else {
        eprintln!("Getting collateral from {pccs_url}");
        get_collateral(&pccs_url, &quote).await?
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

fn command_pck_info(args: PckInfoArgs) -> Result<()> {
    let raw = fs::read(&args.quote_file).context("Failed to read quote file")?;
    let quote_bytes = hex_decode(&raw, args.hex)?;
    let quote = Quote::parse(&quote_bytes).context("Failed to parse quote")?;

    emit_header_summary(&quote);

    let certs = intel::extract_cert_chain(&quote)?;
    println!("Certificate chain contains {} entries:", certs.len());
    for (idx, cert) in certs.iter().enumerate() {
        let parsed = Certificate::from_der(cert.as_slice())
            .map_err(|e| anyhow!("Failed to decode certificate #{idx}: {e}"))?;
        let subject = parsed.tbs_certificate.subject.to_string();
        let issuer = parsed.tbs_certificate.issuer.to_string();
        let role = match idx {
            0 => "Leaf PCK",
            1 => "PCK CA",
            _ => "Issuer",
        };
        println!("  [{idx}] {role}: subject=\"{subject}\", issuer=\"{issuer}\"");
    }

    let leaf = certs
        .first()
        .ok_or_else(|| anyhow!("Certificate chain is empty"))?;
    let extension = intel::parse_pck_extension(leaf)?;

    println!("\nIntel extension values (from leaf PCK certificate):");
    println!("  PPID               : {}", hex_string(&extension.ppid));
    println!("  CPU SVN            : {}", hex_string(&extension.cpu_svn));
    println!("  PCE SVN            : {}", extension.pce_svn);
    println!("  PCE ID             : {}", hex_string(&extension.pce_id));
    println!("  FMSPC              : {}", hex_string(&extension.fmspc));
    println!(
        "  SGX Type           : {} ({})",
        extension.sgx_type,
        match extension.sgx_type {
            0 => "SGX",
            1 => "TDX",
            _ => "Unknown",
        }
    );
    let platform_instance_display = extension
        .platform_instance_id
        .as_ref()
        .map(|bytes| hex_string(bytes))
        .unwrap_or_else(|| "<missing>".to_string());
    println!("  Platform InstanceID: {}", platform_instance_display);

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
        Commands::PckInfo(args) => command_pck_info(args).context("Failed to extract PCK info"),
    }
}

fn emit_header_summary(quote: &Quote) {
    let tee_type = match quote.header.tee_type {
        TEE_TYPE_SGX => "SGX",
        TEE_TYPE_TDX => "TDX",
        other => {
            println!("Quote uses unknown TEE type: 0x{other:08x}");
            "Unknown"
        }
    };
    println!("Quote version {} ({tee_type})", quote.header.version);
    println!(
        "  QE SVN: {} | PCE SVN: {} | User data: {}",
        quote.header.qe_svn,
        quote.header.pce_svn,
        hex_string(&quote.header.user_data)
    );
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}

const TEE_TYPE_SGX: u32 = 0x0000_0000;
const TEE_TYPE_TDX: u32 = 0x0000_0081;
