use alloc::string::String;
use alloc::vec::Vec;

use anyhow::{anyhow, bail, Context, Result};
use scale::{Decode, Input};
use serde::{Deserialize, Serialize};
use x509_cert::Certificate;

#[cfg(feature = "borsh_schema")]
use borsh::BorshSchema;
#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

use crate::{
    constants::{self, *},
    utils,
};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct Data<T> {
    pub data: Vec<u8>,
    _marker: core::marker::PhantomData<T>,
}

impl<T> Serialize for Data<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde_bytes::serialize(&self.data, serializer)
    }
}

impl<'de, T> Deserialize<'de> for Data<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let data = serde_bytes::deserialize(deserializer)?;
        Ok(Data {
            data,
            _marker: core::marker::PhantomData,
        })
    }
}

impl<T: Decode + Into<u64>> Decode for Data<T> {
    fn decode<I: Input>(input: &mut I) -> Result<Self, scale::Error> {
        let len = T::decode(input)?;
        let mut data = vec![0u8; len.into() as usize];
        input.read(&mut data)?;
        Ok(Data {
            data,
            _marker: core::marker::PhantomData,
        })
    }
}

#[derive(
    Decode, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize,
)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct Header {
    pub version: u16,
    pub attestation_key_type: u16,
    pub tee_type: u32,
    pub qe_svn: u16,
    pub pce_svn: u16,
    #[serde(with = "serde_bytes")]
    pub qe_vendor_id: [u8; 16],
    #[serde(with = "serde_bytes")]
    pub user_data: [u8; 20],
}

impl Header {
    pub fn is_sgx(&self) -> bool {
        self.tee_type == TEE_TYPE_SGX
    }
}

#[derive(Decode, Debug)]
pub struct Body {
    pub body_type: u16,
    pub size: u32,
}

#[derive(
    Decode, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize,
)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct EnclaveReport {
    #[serde(with = "serde_bytes")]
    pub cpu_svn: [u8; 16],
    pub misc_select: u32,
    #[serde(with = "serde_bytes")]
    pub reserved1: [u8; 28],
    #[serde(with = "serde_bytes")]
    pub attributes: [u8; 16],
    #[serde(with = "serde_bytes")]
    pub mr_enclave: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub reserved2: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub mr_signer: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub reserved3: [u8; 96],
    pub isv_prod_id: u16,
    pub isv_svn: u16,
    #[serde(with = "serde_bytes")]
    pub reserved4: [u8; 60],
    #[serde(with = "serde_bytes")]
    pub report_data: [u8; 64],
}

/// TD Attributes as defined in Intel TDX Module specification A.3.4
#[derive(Debug, Clone)]
pub struct TDAttributes {
    /// TUD (TD Under Debug) flags (bits 7:0)
    /// If any of the bits in this group are set to 1, the TD is untrusted.
    pub tud: u8,

    /// SEC attributes that may impact the security of the TD (bits 31:8)
    pub sec: SECFlags,

    /// OTHER attributes that do not impact the security of the TD (bits 63:32)
    pub other: OTHERFlags,
}

/// TUD (TD Under Debug) flags (bits 7:0)
#[derive(Debug, Clone)]
pub struct TUDFlags {
    /// DEBUG: Defines whether the TD runs in TD debug mode (set to 1) or not (set to 0).
    /// In TD debug mode, the CPU state and private memory are accessible by the host VMM.
    pub debug: bool,

    /// Reserved for future TUD flags - must be 0 (bits 7:1)
    pub reserved: u8,
}

/// SEC attributes that may impact the security of the TD (bits 31:8)
#[derive(Debug, Clone)]
pub struct SECFlags {
    /// Reserved for future SEC flags - must be 0 (bits 27:8)
    pub reserved_lower: u32,

    /// SEPT_VE_DISABLE: Disable EPT violation conversion to #VE on TD access of PENDING pages
    pub sept_ve_disable: bool,

    /// Reserved for future SEC flags - must be 0 (bit 29)
    pub reserved_bit29: bool,

    /// PKS: TD is allowed to use Supervisor Protection Keys
    pub pks: bool,

    /// KL: TD is allowed to use Key Locker
    pub kl: bool,
}

/// OTHER attributes that do not impact the security of the TD (bits 63:32)
#[derive(Debug, Clone)]
pub struct OTHERFlags {
    /// Reserved for future OTHER flags - must be 0 (bits 62:32)
    pub reserved: u32,

    /// PERFMON: TD is allowed to use Perfmon and PERF_METRICS capabilities
    pub perfmon: bool,
}

impl TDAttributes {
    pub fn parse(input: [u8; 8]) -> Result<Self, scale::Error> {
        let tud = input[0];
        // Extract SEC flags (27:8 bits, bytes 1-3 and part of byte 4)
        let reserved_lower =
            (((input[3] & 0x0f) as u32) << 16) | ((input[2] as u32) << 8) | (input[1] as u32);
        let sept_ve_disable = (input[3] & 0x10) != 0; // Bit 28
        let reserved_bit29 = (input[3] & 0x20) != 0; // Bit 29
        let pks = (input[3] & 0x40) != 0; // Bit 30
        let kl = (input[3] & 0x80) != 0; // Bit 31

        // Extract OTHER flags (bytes 4-7)
        let reserved_other = ((input[7] as u32) << 24)
            | ((input[6] as u32) << 16)
            | ((input[5] as u32) << 8)
            | ((input[4] as u32) & 0x7F);
        let perfmon = (input[7] & 0x80) != 0; // Bit 63

        Ok(TDAttributes {
            tud,
            sec: SECFlags {
                reserved_lower,
                sept_ve_disable,
                reserved_bit29,
                pks,
                kl,
            },
            other: OTHERFlags {
                reserved: reserved_other,
                perfmon,
            },
        })
    }
}

#[derive(
    Decode, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize,
)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct TDReport10 {
    #[serde(with = "serde_bytes")]
    pub tee_tcb_svn: [u8; 16],
    #[serde(with = "serde_bytes")]
    pub mr_seam: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub mr_signer_seam: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub seam_attributes: [u8; 8],
    #[serde(with = "serde_bytes")]
    pub td_attributes: [u8; 8],
    #[serde(with = "serde_bytes")]
    pub xfam: [u8; 8],
    #[serde(with = "serde_bytes")]
    pub mr_td: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub mr_config_id: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub mr_owner: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub mr_owner_config: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub rt_mr0: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub rt_mr1: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub rt_mr2: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub rt_mr3: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub report_data: [u8; 64],
}

#[derive(
    Decode, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize,
)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct TDReport15 {
    pub base: TDReport10,
    #[serde(with = "serde_bytes")]
    pub tee_tcb_svn2: [u8; 16],
    #[serde(with = "serde_bytes")]
    pub mr_service_td: [u8; 48],
}

#[derive(Decode, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct CertificationData {
    pub cert_type: u16,
    pub body: Data<u32>,
}

impl core::fmt::Debug for CertificationData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let body_str = String::from_utf8_lossy(&self.body.data);
        f.debug_struct("CertificationData")
            .field("cert_type", &self.cert_type)
            .field("body", &body_str)
            .finish()
    }
}

#[derive(Decode, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct QEReportCertificationData {
    #[serde(with = "serde_bytes")]
    pub qe_report: [u8; ENCLAVE_REPORT_BYTE_LEN],
    #[serde(with = "serde_bytes")]
    pub qe_report_signature: [u8; QE_REPORT_SIG_BYTE_LEN],
    pub qe_auth_data: Data<u16>,
    pub certification_data: CertificationData,
}

#[derive(Decode, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct AuthDataV3 {
    #[serde(with = "serde_bytes")]
    pub ecdsa_signature: [u8; ECDSA_SIGNATURE_BYTE_LEN],
    #[serde(with = "serde_bytes")]
    pub ecdsa_attestation_key: [u8; ECDSA_PUBKEY_BYTE_LEN],
    #[serde(with = "serde_bytes")]
    pub qe_report: [u8; ENCLAVE_REPORT_BYTE_LEN],
    #[serde(with = "serde_bytes")]
    pub qe_report_signature: [u8; QE_REPORT_SIG_BYTE_LEN],
    pub qe_auth_data: Data<u16>,
    pub certification_data: CertificationData,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct AuthDataV4 {
    #[serde(with = "serde_bytes")]
    pub ecdsa_signature: [u8; ECDSA_SIGNATURE_BYTE_LEN],
    #[serde(with = "serde_bytes")]
    pub ecdsa_attestation_key: [u8; ECDSA_PUBKEY_BYTE_LEN],
    pub certification_data: CertificationData,
    pub qe_report_data: QEReportCertificationData,
}

impl AuthDataV4 {
    pub fn into_v3(self) -> AuthDataV3 {
        AuthDataV3 {
            ecdsa_signature: self.ecdsa_signature,
            ecdsa_attestation_key: self.ecdsa_attestation_key,
            qe_report: self.qe_report_data.qe_report,
            qe_report_signature: self.qe_report_data.qe_report_signature,
            qe_auth_data: self.qe_report_data.qe_auth_data,
            certification_data: self.qe_report_data.certification_data,
        }
    }
}

impl Decode for AuthDataV4 {
    fn decode<I: Input>(input: &mut I) -> Result<Self, scale::Error> {
        let ecdsa_signature = Decode::decode(input)?;
        let ecdsa_attestation_key = Decode::decode(input)?;
        let certification_data: CertificationData = Decode::decode(input)?;
        let qe_report_data =
            QEReportCertificationData::decode(&mut &certification_data.body.data[..])?;
        Ok(AuthDataV4 {
            ecdsa_signature,
            ecdsa_attestation_key,
            certification_data,
            qe_report_data,
        })
    }
}

#[derive(Decode, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
pub enum AuthData {
    V3(AuthDataV3),
    V4(AuthDataV4),
}

// Manual implementation of BorshSchema for AuthData to work around
// the derive bug described in https://github.com/near/borsh-rs/issues/355
#[cfg(feature = "borsh_schema")]
impl borsh::BorshSchema for AuthData {
    fn declaration() -> borsh::schema::Declaration {
        "AuthData".to_string()
    }

    fn add_definitions_recursively(
        definitions: &mut borsh::__private::maybestd::collections::BTreeMap<
            borsh::schema::Declaration,
            borsh::schema::Definition,
        >,
    ) {
        let definition = borsh::schema::Definition::Enum {
            tag_width: 1,
            variants: vec![
                (0, "V3".to_string(), AuthDataV3::declaration()),
                (1, "V4".to_string(), AuthDataV4::declaration()),
            ],
        };

        borsh::schema::add_definition(Self::declaration(), definition, definitions);

        AuthDataV3::add_definitions_recursively(definitions);
        AuthDataV4::add_definitions_recursively(definitions);
    }
}

impl AuthData {
    pub fn into_v3(self) -> AuthDataV3 {
        match self {
            AuthData::V3(data) => data,
            AuthData::V4(data) => data.into_v3(),
        }
    }
}

fn decode_auth_data(ver: u16, input: &mut &[u8]) -> Result<AuthData, scale::Error> {
    match ver {
        3 => {
            let auth_data = AuthDataV3::decode(input)?;
            Ok(AuthData::V3(auth_data))
        }
        4 => {
            let auth_data = AuthDataV4::decode(input)?;
            Ok(AuthData::V4(auth_data))
        }
        _ => Err(scale::Error::from("Unsupported auth data version")),
    }
}

#[derive(Decode, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub enum Report {
    SgxEnclave(EnclaveReport),
    TD10(TDReport10),
    TD15(TDReport15),
}

impl Report {
    pub fn is_sgx(&self) -> bool {
        matches!(self, Report::SgxEnclave(_))
    }

    pub fn as_td10(&self) -> Option<&TDReport10> {
        match self {
            Report::TD10(report) => Some(report),
            Report::TD15(report) => Some(&report.base),
            _ => None,
        }
    }

    pub fn as_td15(&self) -> Option<&TDReport15> {
        match self {
            Report::TD15(report) => Some(report),
            _ => None,
        }
    }

    pub fn as_sgx(&self) -> Option<&EnclaveReport> {
        match self {
            Report::SgxEnclave(report) => Some(report),
            _ => None,
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct Quote {
    pub header: Header,
    pub report: Report,
    pub auth_data: AuthData,
}

impl Decode for Quote {
    fn decode<I: Input>(input: &mut I) -> Result<Self, scale::Error> {
        let header = Header::decode(input)?;
        let report;
        match header.version {
            3 => {
                if header.tee_type != TEE_TYPE_SGX {
                    return Err(scale::Error::from("invalid tee type"));
                }
                report = Report::SgxEnclave(EnclaveReport::decode(input)?);
            }
            4 => match header.tee_type {
                TEE_TYPE_SGX => {
                    report = Report::SgxEnclave(EnclaveReport::decode(input)?);
                }
                TEE_TYPE_TDX => {
                    report = Report::TD10(TDReport10::decode(input)?);
                }
                _ => return Err(scale::Error::from("Invalid TEE type")),
            },
            5 => {
                let body = Body::decode(input)?;
                match body.body_type {
                    BODY_SGX_ENCLAVE_REPORT_TYPE => {
                        report = Report::SgxEnclave(EnclaveReport::decode(input)?);
                    }
                    BODY_TD_REPORT10_TYPE => {
                        report = Report::TD10(TDReport10::decode(input)?);
                    }
                    BODY_TD_REPORT15_TYPE => {
                        report = Report::TD15(TDReport15::decode(input)?);
                    }
                    _ => return Err(scale::Error::from("Unsupported body type")),
                }
            }
            _ => return Err(scale::Error::from("Unsupported quote version")),
        }
        let data = Data::<u32>::decode(input)?;
        let auth_data = decode_auth_data(header.version, &mut &data.data[..])?;
        Ok(Quote {
            header,
            report,
            auth_data,
        })
    }
}

impl Quote {
    /// Parse a TEE quote from a byte slice.
    pub fn parse(quote: &[u8]) -> Result<Self> {
        let mut input = quote;
        let quote = Quote::decode(&mut input)?;
        Ok(quote)
    }

    /// Get the raw certificate chain from the quote.
    pub fn raw_cert_chain(&self) -> Result<&[u8]> {
        let cert_data = match &self.auth_data {
            AuthData::V3(data) => &data.certification_data,
            AuthData::V4(data) => &data.qe_report_data.certification_data,
        };
        if cert_data.cert_type != 5 {
            bail!("Unsupported cert type: {}", cert_data.cert_type);
        }
        Ok(&cert_data.body.data)
    }

    /// Get the FMSPC from the quote.
    pub fn fmspc(&self) -> Result<Fmspc> {
        let raw_cert_chain = self
            .raw_cert_chain()
            .context("Failed to get raw cert chain")?;
        let certs = utils::extract_certs(raw_cert_chain).context("Failed to extract certs")?;
        let cert = certs.first().ok_or(anyhow!("Invalid certificate"))?;
        let extension_section =
            utils::get_intel_extension(cert).context("Failed to get Intel extension")?;
        utils::get_fmspc(&extension_section)
    }

    /// Get the Certificate Authority (CA) type from the quote.
    /// Returns "processor" or "platform" based on the issuer of the PCK certificate.
    pub fn ca(&self) -> Result<&'static str> {
        let raw_cert_chain = self
            .raw_cert_chain()
            .context("Failed to get raw cert chain")?;
        let certs = utils::extract_certs(raw_cert_chain).context("Failed to extract certs")?;
        let cert = certs.first().ok_or(anyhow!("Invalid certificate"))?;
        let cert_der: Certificate =
            der::Decode::from_der(cert).context("Failed to decode certificate")?;
        let issuer = cert_der.tbs_certificate.issuer.to_string();
        if issuer.contains(constants::PROCESSOR_ISSUER) {
            return Ok(constants::PROCESSOR_ISSUER_ID);
        } else if issuer.contains(constants::PLATFORM_ISSUER) {
            return Ok(constants::PLATFORM_ISSUER_ID);
        }
        Ok(constants::PROCESSOR_ISSUER_ID)
    }

    /// Get the the length of signed data in the quote.
    pub fn signed_length(&self) -> usize {
        let mut len = match self.report {
            Report::SgxEnclave(_) => HEADER_BYTE_LEN + ENCLAVE_REPORT_BYTE_LEN,
            Report::TD10(_) => HEADER_BYTE_LEN + TD_REPORT10_BYTE_LEN,
            Report::TD15(_) => HEADER_BYTE_LEN + TD_REPORT15_BYTE_LEN,
        };
        if self.header.version == 5 {
            len += BODY_BYTE_SIZE;
        }
        len
    }
}
