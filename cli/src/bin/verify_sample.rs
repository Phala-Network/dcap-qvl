/// CLI tool for verifying test samples
///
/// Usage:
///   verify_sample <quote_file> <collateral_file> [root_ca_file]
///
/// Exit codes:
///   0 - Verification successful
///   1 - Verification failed
///   2 - Unexpected error (file not found, parse error, etc.)
///
/// Output:
///   Prints verification result to stdout
///   Prints errors to stderr
use dcap_qvl::{verify::QuoteVerifier, QuoteCollateralV3};
use std::fs;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        eprintln!(
            "Usage: {} <quote_file> <collateral_file> [root_ca_file]",
            args[0]
        );
        std::process::exit(2);
    }

    let quote_file = PathBuf::from(&args[1]);
    let collateral_file = PathBuf::from(&args[2]);
    let root_ca_file = args.get(3).map(PathBuf::from);

    // Read quote
    let quote_bytes = match fs::read(&quote_file) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Failed to read quote file: {}", e);
            std::process::exit(2);
        }
    };

    // Read collateral
    let collateral_json = match fs::read_to_string(&collateral_file) {
        Ok(json) => json,
        Err(e) => {
            eprintln!("Failed to read collateral file: {}", e);
            std::process::exit(2);
        }
    };

    let collateral: QuoteCollateralV3 = match serde_json::from_str(&collateral_json) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to parse collateral JSON: {}", e);
            std::process::exit(2);
        }
    };

    // Read custom root CA if provided
    let root_ca_der = if let Some(ref ca_file) = root_ca_file {
        match fs::read(ca_file) {
            Ok(der) => Some(der),
            Err(e) => {
                eprintln!("Failed to read root CA file: {}", e);
                std::process::exit(2);
            }
        }
    } else {
        None
    };

    // Verify
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let verifier = match root_ca_der {
        Some(root_ca_der) => QuoteVerifier::new_with_root_ca(root_ca_der),
        None => QuoteVerifier::new_prod(),
    };
    match verifier.verify(&quote_bytes, &collateral, now) {
        Ok(verified_report) => {
            println!("Verification successful");
            println!("Status: {}", verified_report.status);
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("Verification failed: {}", e);
            let mut source = e.source();
            while let Some(err) = source {
                eprintln!("  Caused by: {}", err);
                source = err.source();
            }
            std::process::exit(1);
        }
    }
}
