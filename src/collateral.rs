use alloc::string::{String, ToString};
use anyhow::{anyhow, Context, Result};
use scale::Decode;

use crate::quote::{Header, Quote};
use crate::verify::VerifiedReport;
use crate::QuoteCollateralV3;

#[cfg(not(feature = "js"))]
use core::time::Duration;
use std::borrow::Cow;
use std::time::SystemTime;

fn get_header(resposne: &reqwest::Response, name: &str) -> Result<String> {
    let value = resposne
        .headers()
        .get(name)
        .ok_or_else(|| anyhow!("Missing {name}"))?
        .to_str()?;
    let value = urlencoding::decode(value)?;
    Ok(value.into_owned())
}

/// Get collateral given DCAP quote and base URL of PCCS server URL.
///
/// # Arguments
///
/// * `pccs_url` - The base URL of PCCS server. (e.g. `https://pccs.example.com/sgx/certification/v4`)
/// * `quote` - The raw quote to verify. Supported SGX and TDX quotes.
/// * `timeout` - The timeout for the request. (e.g. `Duration::from_secs(10)`)
///
/// # Returns
///
/// * `Ok(QuoteCollateralV3)` - The quote collateral
/// * `Err(Error)` - The error
pub async fn get_collateral(
    pccs_url: &str,
    mut quote: &[u8],
    #[cfg(not(feature = "js"))] timeout: Duration,
) -> Result<QuoteCollateralV3> {
    let quote = Quote::decode(&mut quote)?;
    let fmspc = hex::encode_upper(quote.fmspc().context("Failed to get FMSPC")?);
    let builder = reqwest::Client::builder();
    #[cfg(not(feature = "js"))]
    let builder = builder.danger_accept_invalid_certs(true).timeout(timeout);
    let client = builder.build()?;
    let base_url = pccs_url.trim_end_matches('/');

    let tcb_info_issuer_chain;
    let raw_tcb_info;
    {
        let resposne = client
            .get(format!("{base_url}/tcb?fmspc={fmspc}"))
            .send()
            .await?;
        tcb_info_issuer_chain = get_header(&resposne, "SGX-TCB-Info-Issuer-Chain")
            .or(get_header(&resposne, "TCB-Info-Issuer-Chain"))?;
        raw_tcb_info = resposne.text().await?;
    };
    let qe_identity_issuer_chain;
    let raw_qe_identity;
    {
        let response = client.get(format!("{base_url}/qe/identity")).send().await?;
        qe_identity_issuer_chain = get_header(&response, "SGX-Enclave-Identity-Issuer-Chain")?;
        raw_qe_identity = response.text().await?;
    };

    let tcb_info_json: serde_json::Value =
        serde_json::from_str(&raw_tcb_info).context("TCB Info should be valid JSON")?;
    let tcb_info = tcb_info_json["tcbInfo"].to_string();
    let tcb_info_signature = tcb_info_json
        .get("signature")
        .context("TCB Info missing 'signature' field")?
        .as_str()
        .context("TCB Info signature must be a string")?;
    let tcb_info_signature = hex::decode(tcb_info_signature)
        .ok()
        .context("TCB Info signature must be valid hex")?;

    let qe_identity_json: serde_json::Value =
        serde_json::from_str(&raw_qe_identity).context("QE Identity should be valid JSON")?;
    let qe_identity = qe_identity_json
        .get("enclaveIdentity")
        .context("QE Identity missing 'enclaveIdentity' field")?
        .to_string();
    let qe_identity_signature = qe_identity_json
        .get("signature")
        .context("QE Identity missing 'signature' field")?
        .as_str()
        .context("QE Identity signature must be a string")?;
    let qe_identity_signature = hex::decode(qe_identity_signature)
        .ok()
        .context("QE Identity signature must be valid hex")?;

    Ok(QuoteCollateralV3 {
        tcb_info_issuer_chain,
        tcb_info,
        tcb_info_signature,
        qe_identity_issuer_chain,
        qe_identity,
        qe_identity_signature,
    })
}

/// Get collateral given DCAP quote from Intel PCS.
///
/// # Arguments
///
/// * `quote` - The raw quote to verify. Supported SGX and TDX quotes.
/// * `timeout` - The timeout for the request. (e.g. `Duration::from_secs(10)`)
///
/// # Returns
///
/// * `Ok(QuoteCollateralV3)` - The quote collateral
/// * `Err(Error)` - The error
pub async fn get_collateral_from_pcs(
    quote: &[u8],
    #[cfg(not(feature = "js"))] timeout: Duration,
) -> Result<QuoteCollateralV3> {
    let header = Header::decode(&mut &quote[..]).context("Failed to decode quote header")?;
    get_collateral(
        pcs_url(header.is_sgx()),
        quote,
        #[cfg(not(feature = "js"))]
        timeout,
    )
    .await
}

/// Get collateral and verify the quote.
pub async fn get_collateral_and_verify(
    quote: &[u8],
    pccs_url: Option<&str>,
) -> Result<VerifiedReport> {
    let header = Header::decode(&mut &quote[..]).context("Failed to decode quote header")?;
    let pccs_url = pccs_url.unwrap_or_default();
    let pccs_url = if pccs_url.is_empty() {
        Cow::Borrowed(pcs_url(header.is_sgx()))
    } else {
        normalize_pccs_url(pccs_url, header.is_sgx())
    };
    let collateral = get_collateral(
        &pccs_url,
        quote,
        #[cfg(not(feature = "js"))]
        Duration::from_secs(120),
    )
    .await?;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("Failed to get current time")?
        .as_secs();
    crate::verify::verify(quote, &collateral, now)
}

fn pcs_url(is_sgx: bool) -> &'static str {
    if is_sgx {
        "https://api.trustedservices.intel.com/sgx/certification/v4"
    } else {
        "https://api.trustedservices.intel.com/tdx/certification/v4"
    }
}

fn normalize_pccs_url(url: &str, is_sgx: bool) -> Cow<'_, str> {
    let url = url.trim_end_matches('/');
    let path = if is_sgx {
        "/sgx/certification/v4"
    } else {
        "/tdx/certification/v4"
    };
    if url.ends_with(path) {
        return Cow::Borrowed(url);
    }
    let base_url = url
        .trim_end_matches("/sgx/certification/v4")
        .trim_end_matches("/tdx/certification/v4");
    Cow::Owned(format!("{}{}", base_url, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_pccs_url_sgx() {
        // Test cases for SGX
        let test_cases = vec![
            (
                "https://any.domain.com",
                "https://any.domain.com/sgx/certification/v4",
            ),
            (
                "https://any.domain.com:8080",
                "https://any.domain.com:8080/sgx/certification/v4",
            ),
            (
                "https://any.domain.com/",
                "https://any.domain.com/sgx/certification/v4",
            ),
            (
                "https://any.domain.com:8080/",
                "https://any.domain.com:8080/sgx/certification/v4",
            ),
            (
                "https://any.domain.com:8080/sgx/certification/v4",
                "https://any.domain.com:8080/sgx/certification/v4",
            ),
            (
                "https://any.domain.com:8080/sgx/certification/v4/",
                "https://any.domain.com:8080/sgx/certification/v4",
            ),
        ];

        for (input, expected) in test_cases {
            assert_eq!(normalize_pccs_url(input, true), expected);
        }
    }

    #[test]
    fn test_normalize_pccs_url_tdx() {
        // Test cases for TDX
        let test_cases = vec![
            (
                "https://any.domain.com",
                "https://any.domain.com/tdx/certification/v4",
            ),
            (
                "https://any.domain.com:8080",
                "https://any.domain.com:8080/tdx/certification/v4",
            ),
            (
                "https://any.domain.com/",
                "https://any.domain.com/tdx/certification/v4",
            ),
            (
                "https://any.domain.com:8080/",
                "https://any.domain.com:8080/tdx/certification/v4",
            ),
            (
                "https://any.domain.com:8080/tdx/certification/v4",
                "https://any.domain.com:8080/tdx/certification/v4",
            ),
            (
                "https://any.domain.com:8080/tdx/certification/v4/",
                "https://any.domain.com:8080/tdx/certification/v4",
            ),
        ];

        for (input, expected) in test_cases {
            assert_eq!(normalize_pccs_url(input, false), expected);
        }
    }

    #[test]
    fn test_pcs_url() {
        assert_eq!(
            pcs_url(true),
            "https://api.trustedservices.intel.com/sgx/certification/v4"
        );
        assert_eq!(
            pcs_url(false),
            "https://api.trustedservices.intel.com/tdx/certification/v4"
        );
    }
}
