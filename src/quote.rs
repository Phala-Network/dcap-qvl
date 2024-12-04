use alloc::string::String;
use alloc::vec::Vec;

use anyhow::Result;
use proptest::prelude::*;
use scale::{Decode, Encode, Input};
use serde::{Deserialize, Serialize};
use sha2::{Sha384,Digest};

use crate::{constants::*, utils, Error};

#[derive(Decode, Encode, PartialEq, Eq, Debug, Serialize)]
pub struct TdxEventLog {
    /// IMR index, starts from 0
    pub imr: u32,
    /// Event type
    pub event_type: u32,
    /// Digest
    #[serde(serialize_with = "hex::serialize")]
    pub digest: [u8; 48],
    /// Event name
    pub event: String,
    /// Event payload
    #[serde(serialize_with = "hex::serialize")]
    pub event_payload: Vec<u8>,
}

// Add this helper module for hex serialization
mod hex {
    use serde::Serializer;

    pub fn serialize<S, T>(bytes: T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: AsRef<[u8]>,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }
}

impl Arbitrary for TdxEventLog {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        // Create a strategy for imr that only generates values 0-3
        let imr_strategy = 0..=3u32;

        (
            imr_strategy,
            any::<u32>(),
            any::<[u8; 48]>(),
            any::<String>(),
            any::<Vec<u8>>(),
        )
            .prop_map(|(imr, event_type, digest, event, event_payload)| {
                TdxEventLog {
                    imr,
                    event_type,
                    digest,
                    event,
                    event_payload,
                }
            })
            .boxed()
    }
}

#[derive(Decode, Encode, PartialEq, Eq, Debug, Serialize)]
pub struct TdxEventLogs {
    pub logs: Vec<TdxEventLog>,
}

impl TdxEventLogs {
    /// Convert event logs to a vector of RTMR values by accumulating digests with SHA384.
    /// Returns a vector of 48-byte arrays representing the RTMR values,
    /// where the index corresponds to the IMR index.
    pub fn get_rtmr(&self) -> Vec<[u8; 48]> {
        let mut rtmrs = vec![[0u8; 48]; 4]; // Initialize with 4 zero-filled RTMRs

        // Process events for each IMR index
        for imr_idx in 0..4 {
            let mut current_rtmr = [0u8; 48];

            // Get all events for this IMR index in order
            let imr_events: Vec<_> = self.logs.iter()
                .filter(|event| event.imr == imr_idx as u32)
                .collect();

            // If we have events for this IMR, calculate the accumulated hash
            if !imr_events.is_empty() {
                for event in imr_events {
                    // Create hasher and update with current RTMR
                    let mut hasher = Sha384::new();
                    hasher.update(current_rtmr);
                    // Update with event digest
                    hasher.update(event.digest);
                    // Get the new RTMR value
                    current_rtmr.copy_from_slice(&hasher.finalize());
                }
            }

            rtmrs[imr_idx] = current_rtmr;
        }

        rtmrs
    }

    /// Convert event logs to a JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

impl Arbitrary for TdxEventLogs {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        let size = 2..=32usize;
        prop::collection::vec(any::<TdxEventLog>(), size)
            .prop_map(|logs| TdxEventLogs { logs })
            .boxed()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Data<T> {
    pub data: Vec<u8>,
    _marker: core::marker::PhantomData<T>,
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

impl<T> Encode for Data<T>
where
    T: Encode + TryFrom<usize>,
    <T as TryFrom<usize>>::Error: std::fmt::Debug,
{
    fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        let len = T::try_from(self.data.len()).expect("Length conversion failed");
        encoded.extend(len.encode());
        encoded.extend(&self.data);
        encoded
    }
}

#[derive(Decode, Encode, PartialEq, Eq, Debug)]
pub struct Header {
    pub version: u16,
    pub attestation_key_type: u16,
    pub tee_type: u32,
    pub qe_svn: u16,
    pub pce_svn: u16,
    pub qe_vendor_id: [u8; 16],
    pub user_data: [u8; 20],
}

impl Arbitrary for Header {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        let version_strategy = prop_oneof![Just(3u16), Just(4u16), Just(5u16)];
        let attestation_key_strategy = prop_oneof![Just(2u16), Just(3u16)];
        let tee_type_strategy = prop::strategy::Union::new_weighted(vec![
            (1, Just(TEE_TYPE_SGX).boxed()),
            (1, Just(TEE_TYPE_TDX).boxed()),
        ]);

        (
            version_strategy,
            attestation_key_strategy,
            tee_type_strategy,
            any::<u16>(),
            any::<u16>(),
            any::<[u8; 16]>(),
            any::<[u8; 20]>(),
            any::<u32>(),
        )
            .prop_flat_map(
                |(
                    version,
                    attestation_key_type,
                    tee_type,
                    qe_svn,
                    pce_svn,
                    qe_vendor_id,
                    user_data,
                    v5_tee_type,
                )| {
                    let tee_type = match version {
                        3 => TEE_TYPE_SGX,
                        4 => tee_type,
                        5 => v5_tee_type,
                        _ => unreachable!(),
                    };

                    (
                        Just(version),
                        Just(attestation_key_type),
                        Just(tee_type),
                        Just(qe_svn),
                        Just(pce_svn),
                        Just(qe_vendor_id),
                        Just(user_data),
                    )
                },
            )
            .prop_map(
                |(
                    version,
                    attestation_key_type,
                    tee_type,
                    qe_svn,
                    pce_svn,
                    qe_vendor_id,
                    user_data,
                )| {
                    Header {
                        version,
                        attestation_key_type,
                        tee_type,
                        qe_svn,
                        pce_svn,
                        qe_vendor_id,
                        user_data,
                    }
                },
            )
            .boxed()
    }
}

#[derive(Decode, Encode, PartialEq, Eq, Debug)]
pub struct Body {
    pub body_type: u16,
    pub size: u32,
}

#[derive(Serialize, Deserialize, Decode, Encode, PartialEq, Eq, Debug, Clone)]
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

impl Arbitrary for EnclaveReport {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            any::<[u8; 16]>(),
            any::<u32>(),
            any::<[u8; 28]>(),
            any::<[u8; 16]>(),
            any::<[u8; 32]>(),
            any::<[u8; 32]>(),
            any::<[u8; 32]>(),
            any::<[u8; 96]>(),
            any::<u16>(),
            any::<u16>(),
            any::<[u8; 60]>(),
            any::<[u8; 64]>(),
        )
            .prop_map(
                |(
                    cpu_svn,
                    misc_select,
                    reserved1,
                    attributes,
                    mr_enclave,
                    reserved2,
                    mr_signer,
                    reserved3,
                    isv_prod_id,
                    isv_svn,
                    reserved4,
                    report_data,
                )| {
                    EnclaveReport {
                        cpu_svn,
                        misc_select,
                        reserved1,
                        attributes,
                        mr_enclave,
                        reserved2,
                        mr_signer,
                        reserved3,
                        isv_prod_id,
                        isv_svn,
                        reserved4,
                        report_data,
                    }
                },
            )
            .boxed()
    }
}

#[derive(Decode, Encode, PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
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

impl Arbitrary for TDReport10 {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        let part1 = (
            any::<[u8; 16]>(),
            any::<[u8; 48]>(),
            any::<[u8; 48]>(),
            any::<[u8; 8]>(),
            any::<[u8; 8]>(),
            any::<[u8; 8]>(),
            any::<[u8; 48]>(),
        );

        let part2 = (
            any::<[u8; 48]>(),
            any::<[u8; 48]>(),
            any::<[u8; 48]>(),
            any::<[u8; 48]>(),
            any::<[u8; 48]>(),
            any::<[u8; 48]>(),
            any::<[u8; 48]>(),
            any::<[u8; 64]>(),
        );

        (part1, part2)
            .prop_map(
                |(
                    (
                        tee_tcb_svn,
                        mr_seam,
                        mr_signer_seam,
                        seam_attributes,
                        td_attributes,
                        xfam,
                        mr_td,
                    ),
                    (
                        mr_config_id,
                        mr_owner,
                        mr_owner_config,
                        rt_mr0,
                        rt_mr1,
                        rt_mr2,
                        rt_mr3,
                        report_data,
                    ),
                )| {
                    TDReport10 {
                        tee_tcb_svn,
                        mr_seam,
                        mr_signer_seam,
                        seam_attributes,
                        td_attributes,
                        xfam,
                        mr_td,
                        mr_config_id,
                        mr_owner,
                        mr_owner_config,
                        rt_mr0,
                        rt_mr1,
                        rt_mr2,
                        rt_mr3,
                        report_data,
                    }
                },
            )
            .boxed()
    }
}

#[derive(Decode, Encode, PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub struct TDReport15 {
    pub base: TDReport10,
    #[serde(with = "serde_bytes")]
    pub tee_tcb_svn2: [u8; 16],
    #[serde(with = "serde_bytes")]
    pub mr_service_td: [u8; 48],
}

impl Arbitrary for TDReport15 {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (any::<TDReport10>(), any::<[u8; 16]>(), any::<[u8; 48]>())
            .prop_map(|(base, tee_tcb_svn2, mr_service_td)| TDReport15 {
                base,
                tee_tcb_svn2,
                mr_service_td,
            })
            .boxed()
    }
}

#[derive(Decode, Encode, PartialEq, Eq)]
pub struct CertificationData {
    pub cert_type: u16,
    pub body: Data<u32>,
}

impl Arbitrary for CertificationData {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        any::<u16>()
            .prop_map(|cert_type| {
                let data = vec![0u8; 10];
                let body = Data {
                    data,
                    _marker: core::marker::PhantomData,
                };
                CertificationData {
                    cert_type,
                    body: body,
                }
            })
            .boxed()
    }
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

#[derive(Decode, Encode, PartialEq, Eq, Debug)]
pub struct QEReportCertificationData {
    pub qe_report: [u8; ENCLAVE_REPORT_BYTE_LEN],
    pub qe_report_signature: [u8; QE_REPORT_SIG_BYTE_LEN],
    pub qe_auth_data: Data<u16>,
    pub certification_data: CertificationData,
}

impl Arbitrary for QEReportCertificationData {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            any::<[u8; ENCLAVE_REPORT_BYTE_LEN]>(),
            any::<[u8; QE_REPORT_SIG_BYTE_LEN]>(),
            any::<CertificationData>(),
        )
            .prop_map(|(qe_report, qe_report_signature, certification_data)| {
                let data = vec![0u8; 10];
                let qe_auth_data = Data {
                    data,
                    _marker: core::marker::PhantomData,
                };
                QEReportCertificationData {
                    qe_report,
                    qe_report_signature,
                    qe_auth_data,
                    certification_data,
                }
            })
            .boxed()
    }
}

#[derive(Decode, Encode, PartialEq, Eq, Debug)]
pub struct AuthDataV3 {
    pub ecdsa_signature: [u8; ECDSA_SIGNATURE_BYTE_LEN],
    pub ecdsa_attestation_key: [u8; ECDSA_PUBKEY_BYTE_LEN],
    pub qe_report: [u8; ENCLAVE_REPORT_BYTE_LEN],
    pub qe_report_signature: [u8; QE_REPORT_SIG_BYTE_LEN],
    pub qe_auth_data: Data<u16>,
    pub certification_data: CertificationData,
}

impl Arbitrary for AuthDataV3 {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            any::<[u8; ECDSA_SIGNATURE_BYTE_LEN]>(),
            any::<[u8; ECDSA_PUBKEY_BYTE_LEN]>(),
            any::<[u8; ENCLAVE_REPORT_BYTE_LEN]>(),
            any::<[u8; QE_REPORT_SIG_BYTE_LEN]>(),
            any::<CertificationData>(),
        )
            .prop_map(
                |(
                    ecdsa_signature,
                    ecdsa_attestation_key,
                    qe_report,
                    qe_report_signature,
                    certification_data,
                )| {
                    let data = vec![0u8; 10];
                    let qe_auth_data = Data {
                        data,
                        _marker: core::marker::PhantomData,
                    };
                    AuthDataV3 {
                        ecdsa_signature,
                        ecdsa_attestation_key,
                        qe_report,
                        qe_report_signature,
                        qe_auth_data,
                        certification_data,
                    }
                },
            )
            .boxed()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct AuthDataV4 {
    pub ecdsa_signature: [u8; ECDSA_SIGNATURE_BYTE_LEN],
    pub ecdsa_attestation_key: [u8; ECDSA_PUBKEY_BYTE_LEN],
    pub certification_data: CertificationData,
    pub qe_report_data: QEReportCertificationData,
}

impl Arbitrary for AuthDataV4 {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            any::<[u8; ECDSA_SIGNATURE_BYTE_LEN]>(),
            any::<[u8; ECDSA_PUBKEY_BYTE_LEN]>(),
            any::<QEReportCertificationData>(),
        )
            .prop_map(|(ecdsa_signature, ecdsa_attestation_key, qe_report_data)| {
                let certification_data = CertificationData {
                    cert_type: 0,
                    body: Data {
                        data: qe_report_data.encode(),
                        _marker: core::marker::PhantomData,
                    },
                };
                AuthDataV4 {
                    ecdsa_signature,
                    ecdsa_attestation_key,
                    certification_data,
                    qe_report_data,
                }
            })
            .boxed()
    }
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

impl Encode for AuthDataV4 {
    fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend(self.ecdsa_signature.encode());
        encoded.extend(self.ecdsa_attestation_key.encode());
        encoded.extend(self.certification_data.encode());
        encoded
    }
}

#[derive(Debug)]
pub enum AuthData {
    V3(AuthDataV3),
    V4(AuthDataV4),
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
        _ => Err(scale::Error::from("unsupported quote version")),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Report {
    SgxEnclave(EnclaveReport),
    TD10(TDReport10),
    TD15(TDReport15),
}

#[derive(Debug)]
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
                _ => return Err(scale::Error::from("invalid tee type")),
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
                    _ => return Err(scale::Error::from("unsupported body type")),
                }
            }
            _ => return Err(scale::Error::from("unsupported quote version")),
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
        let mut input = &quote[..];
        let quote = Quote::decode(&mut input)?;
        Ok(quote)
    }

    /// Get the raw certificate chain from the quote.
    pub fn raw_cert_chain(&self) -> &[u8] {
        match &self.auth_data {
            AuthData::V3(data) => &data.certification_data.body.data,
            AuthData::V4(data) => &data.qe_report_data.certification_data.body.data,
        }
    }

    /// Get the FMSPC from the quote.
    pub fn fmspc(&self) -> Result<Fmspc, Error> {
        let raw_cert_chain = self.raw_cert_chain();
        let certs = utils::extract_certs(raw_cert_chain)?;
        let extension_section = utils::get_intel_extension(&certs[0])?;
        utils::get_fmspc(&extension_section)
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
