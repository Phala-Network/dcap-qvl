use anyhow::Context;
use clap::{Parser, Subcommand};
use dcap_qvl::{collateral::get_collateral, verify::QuoteVerifier, QuoteCollateralV3};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "test-case")]
#[command(about = "DCAP Quote Verification test case runner", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Verify a quote with collateral
    Verify {
        /// Path to quote file
        quote_file: PathBuf,
        /// Path to collateral JSON file
        collateral_file: PathBuf,
        /// Optional path to custom root CA DER file
        root_ca_file: Option<PathBuf>,
    },
    /// Fetch collateral from PCCS
    GetCollateral {
        /// PCCS URL
        #[arg(
            long,
            default_value = "https://pccs.phala.network/tdx/certification/v4"
        )]
        pccs_url: String,
        /// Path to quote file
        quote_file: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    let exit_code = match cli.command {
        Commands::Verify {
            quote_file,
            collateral_file,
            root_ca_file,
        } => run_verify(quote_file, collateral_file, root_ca_file),
        Commands::GetCollateral {
            pccs_url,
            quote_file,
        } => run_get_collateral(pccs_url, quote_file),
    };

    std::process::exit(exit_code);
}

fn run_verify(quote_file: PathBuf, collateral_file: PathBuf, root_ca_file: Option<PathBuf>) -> i32 {
    // Read quote
    let quote_bytes = match fs::read(&quote_file) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Failed to read quote file: {}", e);
            return 2;
        }
    };

    // Read collateral
    let collateral_json = match fs::read_to_string(&collateral_file) {
        Ok(json) => json,
        Err(e) => {
            eprintln!("Failed to read collateral file: {}", e);
            return 2;
        }
    };

    let collateral: QuoteCollateralV3 = match serde_json::from_str(&collateral_json) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to parse collateral JSON: {}", e);
            return 2;
        }
    };

    // Read custom root CA if provided
    let root_ca_der = if let Some(ref ca_file) = root_ca_file {
        match fs::read(ca_file) {
            Ok(der) => Some(der),
            Err(e) => {
                eprintln!("Failed to read root CA file: {}", e);
                return 2;
            }
        }
    } else {
        None
    };

    // Verify
    #[allow(clippy::expect_used)]
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Invalid system time")
        .as_secs();

    let ring_backend = dcap_qvl::verify::ring::backend();
    let rustcrypto_backend = dcap_qvl::verify::rustcrypto::backend();
    let ring_verifier = match root_ca_der.clone() {
        Some(root_ca_der) => QuoteVerifier::new(root_ca_der, ring_backend),
        None => QuoteVerifier::new_prod(ring_backend),
    };
    let rustcrypto_verifier = match root_ca_der {
        Some(root_ca_der) => QuoteVerifier::new(root_ca_der, rustcrypto_backend),
        None => QuoteVerifier::new_prod(rustcrypto_backend),
    };

    let ring_result = ring_verifier
        .verify(&quote_bytes, &collateral, now)
        .map_err(|e| format!("{e:#}"));
    let rustcrypto_result = rustcrypto_verifier
        .verify(&quote_bytes, &collateral, now)
        .map_err(|e| format!("{e:#}"));
    if ring_result != rustcrypto_result {
        eprintln!("Verification results differ between ring and rustcrypto");
        eprintln!("Ring result: {ring_result:?}");
        eprintln!("Rustcrypto result: {rustcrypto_result:?}");
        return 1;
    }

    let ring_result1 = ring_verifier.verify(&quote_bytes, &collateral, now);
    match ring_result1 {
        Ok(verified_report) => {
            println!("Verification successful");
            println!("Status: {:?}", verified_report.status);
            0
        }
        Err(e) => {
            eprintln!("Verification failed: {}", e);
            let mut source = e.source();
            while let Some(err) = source {
                eprintln!("  Caused by: {}", err);
                source = err.source();
            }
            1
        }
    }
}

fn run_get_collateral(pccs_url: String, quote_file: PathBuf) -> i32 {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Failed to create async runtime: {}", e);
            return 2;
        }
    };

    runtime.block_on(async {
        // Read quote
        let quote_bytes = match fs::read(&quote_file) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!("Failed to read quote file: {}", e);
                return 2;
            }
        };

        // Fetch collateral
        let result = get_collateral(&pccs_url, &quote_bytes)
            .await
            .and_then(|collateral| {
                serde_json::to_string(&collateral).context("Failed to serialize collateral")
            });
        match result {
            Ok(collateral) => {
                // Output collateral JSON directly
                println!("{collateral}");
                0
            }
            Err(e) => {
                eprintln!("Get collateral failed: {}", e);
                1
            }
        }
    })
}
