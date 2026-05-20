//! UniFFI-friendly type mirrors for the dcap-qvl public types.
//!
//! UniFFI's Record/Enum derives require concrete types with named fields and
//! no const generics, so we re-shape `[u8; N]` fields as `Vec<u8>` and convert
//! at the boundary. Conversions are direct field copies — no validation.

use dcap_qvl::{
    intel::PckExtension as CorePckExtension,
    quote::{EnclaveReport, Header, Quote as CoreQuote, Report as CoreReport, TDReport10, TDReport15},
    tcb_info::{TcbStatus as CoreTcbStatus, TcbStatusWithAdvisory as CoreTcbStatusWithAdvisory},
    verify::VerifiedReport as CoreVerifiedReport,
    QuoteCollateralV3,
};

// ---------------------------------------------------------------------------
// QuoteCollateral
// ---------------------------------------------------------------------------

/// PCCS collateral required to verify a quote offline.
#[derive(Clone, uniffi::Record)]
pub struct QuoteCollateral {
    pub pck_crl_issuer_chain: String,
    pub root_ca_crl: Vec<u8>,
    pub pck_crl: Vec<u8>,
    pub tcb_info_issuer_chain: String,
    pub tcb_info: String,
    pub tcb_info_signature: Vec<u8>,
    pub qe_identity_issuer_chain: String,
    pub qe_identity: String,
    pub qe_identity_signature: Vec<u8>,
    pub pck_certificate_chain: Option<String>,
}

impl From<QuoteCollateral> for QuoteCollateralV3 {
    fn from(c: QuoteCollateral) -> Self {
        QuoteCollateralV3 {
            pck_crl_issuer_chain: c.pck_crl_issuer_chain,
            root_ca_crl: c.root_ca_crl,
            pck_crl: c.pck_crl,
            tcb_info_issuer_chain: c.tcb_info_issuer_chain,
            tcb_info: c.tcb_info,
            tcb_info_signature: c.tcb_info_signature,
            qe_identity_issuer_chain: c.qe_identity_issuer_chain,
            qe_identity: c.qe_identity,
            qe_identity_signature: c.qe_identity_signature,
            pck_certificate_chain: c.pck_certificate_chain,
        }
    }
}

impl From<QuoteCollateralV3> for QuoteCollateral {
    fn from(c: QuoteCollateralV3) -> Self {
        QuoteCollateral {
            pck_crl_issuer_chain: c.pck_crl_issuer_chain,
            root_ca_crl: c.root_ca_crl,
            pck_crl: c.pck_crl,
            tcb_info_issuer_chain: c.tcb_info_issuer_chain,
            tcb_info: c.tcb_info,
            tcb_info_signature: c.tcb_info_signature,
            qe_identity_issuer_chain: c.qe_identity_issuer_chain,
            qe_identity: c.qe_identity,
            qe_identity_signature: c.qe_identity_signature,
            pck_certificate_chain: c.pck_certificate_chain,
        }
    }
}

// ---------------------------------------------------------------------------
// Quote / Report
// ---------------------------------------------------------------------------

/// Header section of a quote.
#[derive(Clone, uniffi::Record)]
pub struct QuoteHeader {
    pub version: u16,
    pub attestation_key_type: u16,
    pub tee_type: u32,
    pub qe_svn: u16,
    pub pce_svn: u16,
    pub qe_vendor_id: Vec<u8>,
    pub user_data: Vec<u8>,
}

impl From<&Header> for QuoteHeader {
    fn from(h: &Header) -> Self {
        QuoteHeader {
            version: h.version,
            attestation_key_type: h.attestation_key_type,
            tee_type: h.tee_type,
            qe_svn: h.qe_svn,
            pce_svn: h.pce_svn,
            qe_vendor_id: h.qe_vendor_id.to_vec(),
            user_data: h.user_data.to_vec(),
        }
    }
}

/// SGX enclave report fields.
#[derive(Clone, uniffi::Record)]
pub struct SgxReport {
    pub cpu_svn: Vec<u8>,
    pub misc_select: u32,
    pub attributes: Vec<u8>,
    pub mr_enclave: Vec<u8>,
    pub mr_signer: Vec<u8>,
    pub isv_prod_id: u16,
    pub isv_svn: u16,
    pub report_data: Vec<u8>,
}

impl From<&EnclaveReport> for SgxReport {
    fn from(r: &EnclaveReport) -> Self {
        SgxReport {
            cpu_svn: r.cpu_svn.to_vec(),
            misc_select: r.misc_select,
            attributes: r.attributes.to_vec(),
            mr_enclave: r.mr_enclave.to_vec(),
            mr_signer: r.mr_signer.to_vec(),
            isv_prod_id: r.isv_prod_id,
            isv_svn: r.isv_svn,
            report_data: r.report_data.to_vec(),
        }
    }
}

/// TDX 1.0 report fields.
#[derive(Clone, uniffi::Record)]
pub struct Td10Report {
    pub tee_tcb_svn: Vec<u8>,
    pub mr_seam: Vec<u8>,
    pub mr_signer_seam: Vec<u8>,
    pub seam_attributes: Vec<u8>,
    pub td_attributes: Vec<u8>,
    pub xfam: Vec<u8>,
    pub mr_td: Vec<u8>,
    pub mr_config_id: Vec<u8>,
    pub mr_owner: Vec<u8>,
    pub mr_owner_config: Vec<u8>,
    pub rt_mr0: Vec<u8>,
    pub rt_mr1: Vec<u8>,
    pub rt_mr2: Vec<u8>,
    pub rt_mr3: Vec<u8>,
    pub report_data: Vec<u8>,
}

impl From<&TDReport10> for Td10Report {
    fn from(r: &TDReport10) -> Self {
        Td10Report {
            tee_tcb_svn: r.tee_tcb_svn.to_vec(),
            mr_seam: r.mr_seam.to_vec(),
            mr_signer_seam: r.mr_signer_seam.to_vec(),
            seam_attributes: r.seam_attributes.to_vec(),
            td_attributes: r.td_attributes.to_vec(),
            xfam: r.xfam.to_vec(),
            mr_td: r.mr_td.to_vec(),
            mr_config_id: r.mr_config_id.to_vec(),
            mr_owner: r.mr_owner.to_vec(),
            mr_owner_config: r.mr_owner_config.to_vec(),
            rt_mr0: r.rt_mr0.to_vec(),
            rt_mr1: r.rt_mr1.to_vec(),
            rt_mr2: r.rt_mr2.to_vec(),
            rt_mr3: r.rt_mr3.to_vec(),
            report_data: r.report_data.to_vec(),
        }
    }
}

/// TDX 1.5 report fields (extends 1.0).
#[derive(Clone, uniffi::Record)]
pub struct Td15Report {
    pub base: Td10Report,
    pub tee_tcb_svn2: Vec<u8>,
    pub mr_service_td: Vec<u8>,
}

impl From<&TDReport15> for Td15Report {
    fn from(r: &TDReport15) -> Self {
        Td15Report {
            base: Td10Report::from(&r.base),
            tee_tcb_svn2: r.tee_tcb_svn2.to_vec(),
            mr_service_td: r.mr_service_td.to_vec(),
        }
    }
}

/// Tagged-union report: one of SGX, TDX 1.0, or TDX 1.5.
#[derive(Clone, uniffi::Enum)]
pub enum Report {
    Sgx { report: SgxReport },
    Td10 { report: Td10Report },
    Td15 { report: Td15Report },
}

impl From<&CoreReport> for Report {
    fn from(r: &CoreReport) -> Self {
        match r {
            CoreReport::SgxEnclave(r) => Report::Sgx { report: r.into() },
            CoreReport::TD10(r) => Report::Td10 { report: r.into() },
            CoreReport::TD15(r) => Report::Td15 { report: r.into() },
        }
    }
}

/// SGX or TDX quote type tag.
#[derive(Clone, Copy, uniffi::Enum)]
pub enum QuoteKind {
    Sgx,
    Tdx,
}

/// Parsed quote with its envelope metadata.
#[derive(Clone, uniffi::Record)]
pub struct Quote {
    pub header: QuoteHeader,
    pub report: Report,
    pub cert_type: u16,
    /// PCK certificate chain (PEM) when embedded in the quote (cert_type 5).
    pub cert_chain_pem: Option<String>,
    /// Hex-encoded FMSPC when extractable from the embedded cert chain.
    pub fmspc: Option<String>,
    /// CA identifier ("processor" or "platform") when extractable.
    pub ca: Option<String>,
    pub kind: QuoteKind,
}

impl Quote {
    pub(crate) fn from_core(q: &CoreQuote) -> Self {
        let cert_chain_pem = q.raw_cert_chain().ok().map(|raw| {
            let mut end = raw.len();
            while end > 0 && raw[end.saturating_sub(1)] == 0 {
                end = end.saturating_sub(1);
            }
            String::from_utf8_lossy(&raw[..end]).into_owned()
        });

        let (fmspc, ca) = if cert_chain_pem.is_some() {
            let fmspc = dcap_qvl::intel::quote_fmspc(q)
                .ok()
                .map(|f| hex::encode_upper(f));
            let ca = dcap_qvl::intel::quote_ca(q).ok().map(|c| c.to_string());
            (fmspc, ca)
        } else {
            (None, None)
        };

        Quote {
            header: (&q.header).into(),
            report: (&q.report).into(),
            cert_type: q.inner_cert_type(),
            cert_chain_pem,
            fmspc,
            ca,
            kind: if q.header.is_sgx() { QuoteKind::Sgx } else { QuoteKind::Tdx },
        }
    }
}

// ---------------------------------------------------------------------------
// VerifiedReport
// ---------------------------------------------------------------------------

/// Mirror of `dcap_qvl::tcb_info::TcbStatus`.
#[derive(Clone, Copy, uniffi::Enum)]
pub enum TcbStatus {
    UpToDate,
    OutOfDateConfigurationNeeded,
    OutOfDate,
    ConfigurationAndSwHardeningNeeded,
    ConfigurationNeeded,
    SwHardeningNeeded,
    Revoked,
}

impl From<CoreTcbStatus> for TcbStatus {
    fn from(s: CoreTcbStatus) -> Self {
        match s {
            CoreTcbStatus::UpToDate => TcbStatus::UpToDate,
            CoreTcbStatus::OutOfDateConfigurationNeeded => TcbStatus::OutOfDateConfigurationNeeded,
            CoreTcbStatus::OutOfDate => TcbStatus::OutOfDate,
            CoreTcbStatus::ConfigurationAndSWHardeningNeeded => {
                TcbStatus::ConfigurationAndSwHardeningNeeded
            }
            CoreTcbStatus::ConfigurationNeeded => TcbStatus::ConfigurationNeeded,
            CoreTcbStatus::SWHardeningNeeded => TcbStatus::SwHardeningNeeded,
            CoreTcbStatus::Revoked => TcbStatus::Revoked,
        }
    }
}

/// TCB status paired with the associated advisory IDs.
#[derive(Clone, uniffi::Record)]
pub struct TcbStatusWithAdvisory {
    pub status: TcbStatus,
    pub advisory_ids: Vec<String>,
}

impl From<CoreTcbStatusWithAdvisory> for TcbStatusWithAdvisory {
    fn from(t: CoreTcbStatusWithAdvisory) -> Self {
        TcbStatusWithAdvisory {
            status: t.status.into(),
            advisory_ids: t.advisory_ids,
        }
    }
}

/// Verified-quote result.
#[derive(Clone, uniffi::Record)]
pub struct VerifiedReport {
    pub status: String,
    pub advisory_ids: Vec<String>,
    pub report: Report,
    pub ppid: Vec<u8>,
    pub qe_status: TcbStatusWithAdvisory,
    pub platform_status: TcbStatusWithAdvisory,
}

impl VerifiedReport {
    pub(crate) fn from_core(r: CoreVerifiedReport) -> Self {
        VerifiedReport {
            status: r.status,
            advisory_ids: r.advisory_ids,
            report: (&r.report).into(),
            ppid: r.ppid,
            qe_status: r.qe_status.into(),
            platform_status: r.platform_status.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// PckExtension
// ---------------------------------------------------------------------------

/// Parsed Intel SGX extension fields from a PCK certificate.
#[derive(Clone, uniffi::Record)]
pub struct PckExtension {
    pub ppid: Vec<u8>,
    pub cpu_svn: Vec<u8>,
    pub pce_svn: u16,
    pub pce_id: Vec<u8>,
    pub fmspc: Vec<u8>,
    pub sgx_type: u64,
    pub platform_instance_id: Option<Vec<u8>>,
    pub raw_extension: Vec<u8>,
}

impl PckExtension {
    pub(crate) fn from_core(e: CorePckExtension) -> Self {
        PckExtension {
            ppid: e.ppid,
            cpu_svn: e.cpu_svn.to_vec(),
            pce_svn: e.pce_svn,
            pce_id: e.pce_id.to_vec(),
            fmspc: e.fmspc.to_vec(),
            sgx_type: e.sgx_type,
            platform_instance_id: e.platform_instance_id,
            raw_extension: e.raw_extension,
        }
    }
}
