use alloc::string::{String, ToString};
use anyhow::{anyhow, bail, Context, Result};
use der::Decode as DerDecode;
use scale::Decode;
use x509_cert::{
    ext::pkix::{
        name::{DistributionPointName, GeneralName},
        CrlDistributionPoints,
    },
    Certificate,
};

use crate::quote::Quote;
use crate::verify::VerifiedReport;
use crate::QuoteCollateralV3;

#[cfg(not(feature = "js"))]
use core::time::Duration;
use std::time::SystemTime;

/// Default PCCS URL (Phala Network's PCCS server).
/// This is the recommended default for most users as it provides better availability
/// and lower rate limits compared to Intel's PCS.
pub const PHALA_PCCS_URL: &str = "https://pccs.phala.network";

/// Intel's official PCS (Provisioning Certification Service) URL.
/// Use `get_collateral_from_pcs()` to fetch collateral directly from Intel.
const INTEL_PCS_URL: &str = "https://api.trustedservices.intel.com";

struct PcsEndpoints {
    base_url: String,
    tee: &'static str,
    fmspc: String,
    ca: &'static str,
}

impl PcsEndpoints {
    fn new(base_url: &str, for_sgx: bool, fmspc: String, ca: &'static str) -> Self {
        let tee = if for_sgx { "sgx" } else { "tdx" };
        let base_url = base_url
            .trim_end_matches('/')
            .trim_end_matches("/sgx/certification/v4")
            .trim_end_matches("/tdx/certification/v4")
            .to_owned();
        Self {
            base_url,
            tee,
            fmspc,
            ca,
        }
    }

    fn is_pcs(&self) -> bool {
        self.base_url.starts_with(INTEL_PCS_URL)
    }

    fn url_pckcrl(&self) -> String {
        self.mk_url("sgx", &format!("pckcrl?ca={}&encoding=der", self.ca))
    }

    fn url_rootcacrl(&self) -> String {
        self.mk_url("sgx", "rootcacrl")
    }

    fn url_tcb(&self) -> String {
        self.mk_url(self.tee, &format!("tcb?fmspc={}", self.fmspc))
    }

    fn url_qe_identity(&self) -> String {
        self.mk_url(self.tee, "qe/identity?update=standard")
    }

    fn mk_url(&self, tee: &str, path: &str) -> String {
        format!("{}/{}/certification/v4/{}", self.base_url, tee, path)
    }
}

fn get_header(response: &reqwest::Response, name: &str) -> Result<String> {
    let value = response
        .headers()
        .get(name)
        .ok_or_else(|| anyhow!("Missing {name}"))?
        .to_str()?;
    let value = urlencoding::decode(value)?;
    Ok(value.into_owned())
}

/// Extracts the CRL Distribution Point URL from a certificate.
///
/// This function parses the certificate and looks for the CRL Distribution Points extension (OID 2.5.29.31).
/// It then extracts the first URL found in the extension's FullName field.
///
/// # Arguments
/// * `cert_der` - The DER-encoded certificate bytes
///
/// # Returns
/// * `Ok(Some(String))` - The CRL distribution point URL if found
/// * `Ok(None)` - If no CRL distribution point was found in the certificate
/// * `Err(_)` - If there was an error parsing the certificate or the extension
fn extract_crl_url(cert_der: &[u8]) -> Result<Option<String>> {
    let cert: Certificate = DerDecode::from_der(cert_der).context("Failed to parse certificate")?;

    let Some(extensions) = &cert.tbs_certificate.extensions else {
        return Ok(None);
    };
    for ext in extensions.iter() {
        if ext.extn_id.to_string() != "2.5.29.31" {
            continue;
        }
        let crl_dist_points: CrlDistributionPoints = DerDecode::from_der(ext.extn_value.as_bytes())
            .context("Failed to parse CRL Distribution Points")?;

        for dist_point in crl_dist_points.0.iter() {
            let Some(dist_point_name) = &dist_point.distribution_point else {
                continue;
            };
            let DistributionPointName::FullName(general_names) = dist_point_name else {
                continue;
            };
            for general_name in general_names.iter() {
                let GeneralName::UniformResourceIdentifier(uri) = general_name else {
                    continue;
                };
                return Ok(Some(uri.to_string()));
            }
        }
    }
    Ok(None)
}

/// Get collateral given DCAP quote and base URL of PCCS server URL.
///
/// # Arguments
///
/// * `pccs_url` - The base URL of PCCS server. (e.g. `https://pccs.example.com/sgx/certification/v4`)
/// * `quote` - The raw quote to verify. Supported SGX and TDX quotes.
///
/// # Returns
///
/// * `Ok(QuoteCollateralV3)` - The quote collateral
/// * `Err(Error)` - The error
pub async fn get_collateral(pccs_url: &str, mut quote: &[u8]) -> Result<QuoteCollateralV3> {
    let quote = Quote::decode(&mut quote)?;
    let ca = quote.ca().context("Failed to get CA")?;
    let fmspc = hex::encode_upper(quote.fmspc().context("Failed to get FMSPC")?);
    get_collateral_for_fmspc(pccs_url, fmspc, ca, quote.header.is_sgx()).await
}

pub async fn get_collateral_for_fmspc(
    pccs_url: &str,
    fmspc: String,
    ca: &'static str,
    for_sgx: bool,
) -> Result<QuoteCollateralV3> {
    let builder = reqwest::Client::builder();
    #[cfg(not(feature = "js"))]
    let builder = builder
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(180));
    let client = builder.build()?;

    let endpoints = PcsEndpoints::new(pccs_url, for_sgx, fmspc, ca);

    let pck_crl_issuer_chain;
    let pck_crl;
    {
        let response = client.get(endpoints.url_pckcrl()).send().await?;
        pck_crl_issuer_chain = get_header(&response, "SGX-PCK-CRL-Issuer-Chain")?;
        pck_crl = response.bytes().await?.to_vec();
    };

    let tcb_info_issuer_chain;
    let raw_tcb_info;
    {
        let response = client.get(endpoints.url_tcb()).send().await?;
        tcb_info_issuer_chain = get_header(&response, "SGX-TCB-Info-Issuer-Chain")
            .or(get_header(&response, "TCB-Info-Issuer-Chain"))?;
        raw_tcb_info = response.text().await?;
    };
    let qe_identity_issuer_chain;
    let raw_qe_identity;
    {
        let response = client.get(endpoints.url_qe_identity()).send().await?;
        qe_identity_issuer_chain = get_header(&response, "SGX-Enclave-Identity-Issuer-Chain")?;
        raw_qe_identity = response.text().await?;
    };

    async fn http_get(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
        let response = client.get(url).send().await?;
        if !response.status().is_success() {
            bail!("Failed to fetch {url}: {}", response.status());
        }
        Ok(response.bytes().await?.to_vec())
    }

    // First try to get root CA CRL directly from the PCCS endpoint
    let mut root_ca_crl = None;
    if !endpoints.is_pcs() {
        root_ca_crl = http_get(&client, &endpoints.url_rootcacrl()).await.ok();

        if let Some(ref crl) = root_ca_crl {
            // PCCS returns hex-encoded CRL instead of binary DER.
            let hex_str =
                core::str::from_utf8(crl).context("Failed to convert hex-encoded CRL to string")?;
            let ca_crl = hex::decode(hex_str)
                .map_err(|_| anyhow!("Failed to decode hex-encoded root CA CRL"))?;
            root_ca_crl = Some(ca_crl);
        }
    }
    let root_ca_crl = match root_ca_crl {
        Some(crl) => crl,
        None => {
            let certs = crate::utils::extract_certs(qe_identity_issuer_chain.as_bytes())
                .context("Failed to extract certificates from PCK CRL issuer chain")?;
            if certs.is_empty() {
                bail!("No certificates found in PCK CRL issuer chain");
            }
            let root_cert_der = certs.last().unwrap();
            let crl_url = extract_crl_url(root_cert_der)?;
            let Some(url) = crl_url else {
                bail!("Could not find CRL distribution point in root certificate");
            };
            http_get(&client, &url).await?
        }
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
        pck_crl_issuer_chain,
        root_ca_crl,
        pck_crl,
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
///
/// # Returns
///
/// * `Ok(QuoteCollateralV3)` - The quote collateral
/// * `Err(Error)` - The error
pub async fn get_collateral_from_pcs(quote: &[u8]) -> Result<QuoteCollateralV3> {
    get_collateral(INTEL_PCS_URL, quote).await
}

/// Get collateral and verify the quote.
///
/// # Arguments
///
/// * `quote` - The raw quote to verify.
/// * `pccs_url` - Optional PCCS URL. Defaults to Phala PCCS if not provided.
pub async fn get_collateral_and_verify(
    quote: &[u8],
    pccs_url: Option<&str>,
) -> Result<VerifiedReport> {
    let pccs_url = pccs_url
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or(PHALA_PCCS_URL);
    let collateral = get_collateral(pccs_url, quote).await?;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("Failed to get current time")?
        .as_secs();
    crate::verify::verify(quote, &collateral, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{PLATFORM_ISSUER_ID, PROCESSOR_ISSUER_ID};

    #[test]
    fn test_pcs_endpoints_new() {
        // Test SGX endpoint initialization
        let sgx_endpoints = PcsEndpoints::new(
            "https://pccs.example.com",
            true,
            "B0C06F000000".to_string(),
            PROCESSOR_ISSUER_ID,
        );
        assert_eq!(sgx_endpoints.base_url, "https://pccs.example.com");
        assert_eq!(sgx_endpoints.tee, "sgx");
        assert_eq!(sgx_endpoints.fmspc, "B0C06F000000");
        assert_eq!(sgx_endpoints.ca, PROCESSOR_ISSUER_ID);

        // Test TDX endpoint initialization
        let tdx_endpoints = PcsEndpoints::new(
            "https://pccs.example.com",
            false,
            "B0C06F000000".to_string(),
            PROCESSOR_ISSUER_ID,
        );
        assert_eq!(tdx_endpoints.base_url, "https://pccs.example.com");
        assert_eq!(tdx_endpoints.tee, "tdx");
        assert_eq!(tdx_endpoints.fmspc, "B0C06F000000");
        assert_eq!(tdx_endpoints.ca, PROCESSOR_ISSUER_ID);

        // Test URL normalization during initialization
        let endpoints_with_trailing_slash = PcsEndpoints::new(
            "https://pccs.example.com/",
            true,
            "B0C06F000000".to_string(),
            PROCESSOR_ISSUER_ID,
        );
        assert_eq!(
            endpoints_with_trailing_slash.base_url,
            "https://pccs.example.com"
        );

        // Test URL normalization with SGX certification path
        let endpoints_with_sgx_path = PcsEndpoints::new(
            "https://pccs.example.com/sgx/certification/v4",
            true,
            "B0C06F000000".to_string(),
            PROCESSOR_ISSUER_ID,
        );
        assert_eq!(endpoints_with_sgx_path.base_url, "https://pccs.example.com");

        // Test URL normalization with TDX certification path
        let endpoints_with_tdx_path = PcsEndpoints::new(
            "https://pccs.example.com/tdx/certification/v4",
            false,
            "B0C06F000000".to_string(),
            PROCESSOR_ISSUER_ID,
        );
        assert_eq!(endpoints_with_tdx_path.base_url, "https://pccs.example.com");
    }

    #[test]
    fn test_pcs_endpoints_url_pckcrl() {
        // Test with processor CA
        let processor_endpoints = PcsEndpoints::new(
            "https://pccs.example.com",
            true,
            "B0C06F000000".to_string(),
            PROCESSOR_ISSUER_ID,
        );
        assert_eq!(
            processor_endpoints.url_pckcrl(),
            "https://pccs.example.com/sgx/certification/v4/pckcrl?ca=processor&encoding=der"
        );

        // Test with platform CA
        let platform_endpoints = PcsEndpoints::new(
            "https://pccs.example.com",
            true,
            "B0C06F000000".to_string(),
            PLATFORM_ISSUER_ID,
        );
        assert_eq!(
            platform_endpoints.url_pckcrl(),
            "https://pccs.example.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der"
        );
    }

    #[test]
    fn test_pcs_endpoints_url_rootcacrl() {
        let endpoints = PcsEndpoints::new(
            "https://pccs.example.com",
            true,
            "B0C06F000000".to_string(),
            PROCESSOR_ISSUER_ID,
        );
        assert_eq!(
            endpoints.url_rootcacrl(),
            "https://pccs.example.com/sgx/certification/v4/rootcacrl"
        );
    }

    #[test]
    fn test_pcs_endpoints_url_tcb() {
        // Test SGX TCB URL
        let sgx_endpoints = PcsEndpoints::new(
            "https://pccs.example.com",
            true,
            "B0C06F000000".to_string(),
            PROCESSOR_ISSUER_ID,
        );
        assert_eq!(
            sgx_endpoints.url_tcb(),
            "https://pccs.example.com/sgx/certification/v4/tcb?fmspc=B0C06F000000"
        );

        // Test TDX TCB URL
        let tdx_endpoints = PcsEndpoints::new(
            "https://pccs.example.com",
            false,
            "B0C06F000000".to_string(),
            PROCESSOR_ISSUER_ID,
        );
        assert_eq!(
            tdx_endpoints.url_tcb(),
            "https://pccs.example.com/tdx/certification/v4/tcb?fmspc=B0C06F000000"
        );
    }

    #[test]
    fn test_pcs_endpoints_url_qe_identity() {
        // Test SGX QE identity URL
        let sgx_endpoints = PcsEndpoints::new(
            "https://pccs.example.com",
            true,
            "B0C06F000000".to_string(),
            PROCESSOR_ISSUER_ID,
        );
        assert_eq!(
            sgx_endpoints.url_qe_identity(),
            "https://pccs.example.com/sgx/certification/v4/qe/identity?update=standard"
        );

        // Test TDX QE identity URL
        let tdx_endpoints = PcsEndpoints::new(
            "https://pccs.example.com",
            false,
            "B0C06F000000".to_string(),
            PROCESSOR_ISSUER_ID,
        );
        assert_eq!(
            tdx_endpoints.url_qe_identity(),
            "https://pccs.example.com/tdx/certification/v4/qe/identity?update=standard"
        );
    }

    #[test]
    fn test_intel_pcs_url() {
        // Test the Intel PCS URL constant
        assert_eq!(INTEL_PCS_URL, "https://api.trustedservices.intel.com");

        // Test the Phala PCCS URL constant
        assert_eq!(PHALA_PCCS_URL, "https://pccs.phala.network");

        // Test with the known FMSPC from memory
        let fmspc = "B0C06F000000";
        let intel_endpoints =
            PcsEndpoints::new(INTEL_PCS_URL, true, fmspc.to_string(), PROCESSOR_ISSUER_ID);

        assert_eq!(
            intel_endpoints.url_pckcrl(),
            "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=processor&encoding=der"
        );

        assert_eq!(
            intel_endpoints.url_rootcacrl(),
            "https://api.trustedservices.intel.com/sgx/certification/v4/rootcacrl"
        );

        assert_eq!(
            intel_endpoints.url_tcb(),
            "https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc=B0C06F000000"
        );

        assert_eq!(
            intel_endpoints.url_qe_identity(),
            "https://api.trustedservices.intel.com/sgx/certification/v4/qe/identity?update=standard"
        );
    }
}
