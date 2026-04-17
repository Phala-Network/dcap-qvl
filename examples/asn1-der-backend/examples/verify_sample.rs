//! End-to-end usage demo: verify a bundled TDX sample quote with the
//! `asn1_der`-based `Config` instead of `DefaultConfig`.
//!
//! Run from this crate's directory:
//!
//! ```sh
//! cargo run --example verify_sample
//! ```
//!
//! Or, with explicit paths to your own quote / collateral / `now`:
//!
//! ```sh
//! cargo run --example verify_sample -- path/to/quote.bin path/to/collateral.json 1700000000
//! ```
//!
//! The only `dcap-qvl` API call that differs from a standard `verify(...)`
//! is the [`verify_with`] line — that's the entire opt-in surface for a
//! custom backend.

use std::{env, fs, process::ExitCode, time::SystemTime};

use anyhow::{Context, Result};
use asn1_der_backend_example::Asn1DerConfig;
use dcap_qvl::{verify::verify_with, QuoteCollateralV3};

const DEFAULT_QUOTE: &[u8] = include_bytes!("../../../sample/tdx_quote");
const DEFAULT_COLLATERAL: &[u8] = include_bytes!("../../../sample/tdx_quote_collateral.json");

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("verify failed: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    let (quote, collateral, now) = match args.as_slice() {
        [] => {
            // The bundled TDX collateral was issued in 2024 and has long
            // since expired. Pin `now` to just before its `nextUpdate`
            // so the demo verifies cleanly out of the box.
            let collateral: QuoteCollateralV3 = serde_json::from_slice(DEFAULT_COLLATERAL)
                .context("parse bundled tdx_quote_collateral.json")?;
            let now = pin_now_before_next_update(&collateral.tcb_info)?;
            (DEFAULT_QUOTE.to_vec(), collateral, now)
        }
        [quote_path, collateral_path] => {
            let quote = fs::read(quote_path).with_context(|| format!("read {quote_path}"))?;
            let collateral_bytes =
                fs::read(collateral_path).with_context(|| format!("read {collateral_path}"))?;
            let collateral: QuoteCollateralV3 =
                serde_json::from_slice(&collateral_bytes).context("parse collateral json")?;
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .context("system time before unix epoch")?
                .as_secs();
            (quote, collateral, now)
        }
        [quote_path, collateral_path, now] => {
            let quote = fs::read(quote_path).with_context(|| format!("read {quote_path}"))?;
            let collateral_bytes =
                fs::read(collateral_path).with_context(|| format!("read {collateral_path}"))?;
            let collateral: QuoteCollateralV3 =
                serde_json::from_slice(&collateral_bytes).context("parse collateral json")?;
            let now: u64 = now.parse().context("`now` arg must be a unix timestamp")?;
            (quote, collateral, now)
        }
        _ => {
            anyhow::bail!(
                "usage: verify_sample [<quote> <collateral.json> [<now-unix-secs>]]"
            );
        }
    };

    // === The one line that picks the custom backend. ===
    let report = verify_with::<Asn1DerConfig>(&quote, &collateral, now)
        .context("verify_with::<Asn1DerConfig>")?;

    println!("verified using Asn1DerConfig (asn1_der downstream backend)");
    println!("  tcb status:      {:?}", report.status);
    println!("  advisory ids:    {:?}", report.advisory_ids);
    println!("  qe tcb:          {:?}", report.qe_status);
    println!("  platform tcb:    {:?}", report.platform_status);
    println!("  ppid (hex):      {}", hex::encode(&report.ppid));
    Ok(())
}

/// Parse `tcbInfo.nextUpdate` and back off by a 2-hour margin. The
/// margin covers the bundled CRLs, which typically expire slightly
/// earlier than the JSON collateral. Used so the bundled (long-expired)
/// sample collateral verifies cleanly without requiring the user to
/// supply a `now` value.
fn pin_now_before_next_update(tcb_info: &str) -> Result<u64> {
    const CRL_MARGIN_SECS: u64 = 2 * 60 * 60;
    let v: serde_json::Value = serde_json::from_str(tcb_info).context("parse tcbInfo")?;
    let next_update = v
        .get("nextUpdate")
        .and_then(|v| v.as_str())
        .context("tcbInfo.nextUpdate missing")?;
    let ts = chrono::DateTime::parse_from_rfc3339(next_update)
        .context("parse tcbInfo.nextUpdate as rfc3339")?
        .timestamp();
    let ts_u64: u64 = ts.try_into().context("nextUpdate timestamp before epoch")?;
    Ok(ts_u64.saturating_sub(CRL_MARGIN_SECS))
}
