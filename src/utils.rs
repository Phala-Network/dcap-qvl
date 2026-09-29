use alloc::vec::Vec;
use anyhow::{anyhow, bail, ensure, Context, Result};
use asn1_der::{
    typed::{DerDecodable, Sequence},
    DerObject,
};
use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};
use webpki::CertRevocationList;
use webpki::{self, OwnedCertRevocationList};

use crate::{
    config::{Config, ParsedCert, X509Codec},
    constants::*,
    oids,
};

/// Look up the Intel SGX OID extension's OCTET STRING contents in a PCK
/// certificate. Generic over [`Config`].
pub fn get_intel_extension_with<C: Config>(der_encoded: &[u8]) -> Result<Vec<u8>> {
    C::X509::from_der(der_encoded)?
        .extension(oids::SGX_EXTENSION.as_bytes())?
        .context("Intel extension not found")
}

pub fn find_extension(path: &[&[u8]], raw: &[u8]) -> Result<Vec<u8>> {
    let obj = DerObject::decode(raw).context("Failed to decode DER object")?;
    let subobj = get_obj(path, obj).context("Failed to get subobject")?;
    Ok(subobj.value().to_vec())
}

fn get_obj<'a>(path: &[&[u8]], mut obj: DerObject<'a>) -> Result<DerObject<'a>> {
    for oid in path {
        let seq = Sequence::load(obj).context("Failed to load sequence")?;
        obj = sub_obj(oid, seq).context("Failed to get subobject")?;
    }
    Ok(obj)
}

fn sub_obj<'a>(oid: &[u8], seq: Sequence<'a>) -> Result<DerObject<'a>> {
    for i in 0..seq.len() {
        let entry = seq.get(i).context("Failed to get entry")?;
        let entry = Sequence::load(entry).context("Failed to load sequence")?;
        let name = entry.get(0).context("Failed to get name")?;
        let value = entry.get(1).context("Failed to get value")?;
        if name.value() == oid {
            return Ok(value);
        }
    }
    bail!("OID is missing");
}

pub(crate) fn get_fmspc(extension_section: &[u8]) -> Result<Fmspc> {
    let data = find_extension(&[oids::FMSPC.as_bytes()], extension_section)
        .context("Failed to find Fmspc")?;
    if data.len() != 6 {
        bail!("Fmspc length mismatch");
    }

    data.try_into()
        .map_err(|_| anyhow!("Failed to decode Fmspc"))
}

pub fn get_cpu_svn(extension_section: &[u8]) -> Result<CpuSvn> {
    let data = find_extension(
        &[oids::TCB.as_bytes(), oids::CPUSVN.as_bytes()],
        extension_section,
    )?;
    if data.len() != 16 {
        bail!("CpuSvn length mismatch");
    }

    data.try_into()
        .map_err(|_| anyhow!("Failed to decode CpuSvn"))
}

pub fn get_pce_svn(extension_section: &[u8]) -> Result<Svn> {
    let data = find_extension(
        &[oids::TCB.as_bytes(), oids::PCESVN.as_bytes()],
        extension_section,
    )
    .context("Failed to find PceSvn")?;

    match data[..] {
        [byte0] => Ok(u16::from(byte0)),
        [byte0, byte1] => Ok(u16::from_be_bytes([byte0, byte1])),
        _ => bail!("PceSvn length mismatch"),
    }
}

pub(crate) fn parse_rfc3339_unix_secs(value: &str) -> Result<u64> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map_err(|e| anyhow!("Failed to parse RFC3339 datetime: {e}"))?
        .timestamp()
        .try_into()
        .context("RFC3339 datetime is before Unix epoch")
}

pub(crate) mod serde_vec_bytes {
    use alloc::vec::Vec;
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serializer};
    use serde_bytes::{ByteBuf, Bytes};

    pub fn serialize<S>(value: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(value.len()))?;
        for item in value {
            seq.serialize_element(Bytes::new(item))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Vec::<ByteBuf>::deserialize(deserializer)?;
        Ok(value.into_iter().map(ByteBuf::into_vec).collect())
    }
}

pub fn extract_certs(cert_chain: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    Ok(pem::parse_many(cert_chain)
        .context("Failed to parse certs")?
        .into_iter()
        .map(|pem| CertificateDer::from(pem.into_contents()))
        .collect())
}

/// Split a 64-byte raw `r ‖ s` payload at byte 32 and DER-encode it as
/// `Ecdsa-Sig-Value` (RFC 5480) using the [`Config::SigEncoder`] of `C`.
pub fn encode_as_der_with<C: Config>(data: &[u8]) -> Result<Vec<u8>> {
    use crate::config::EcdsaSigEncoder;
    let (first, second) = data.split_at_checked(32).context("Invalid key length")?;
    C::SigEncoder::encode_ecdsa_sig(first, second)
}

/// Dates and CRL Number of a CRL.
#[cfg(feature = "default-x509")]
pub(crate) struct CrlInfo {
    pub this_update: u64,
    pub next_update: Option<u64>,
    /// CRL Number (OID 2.5.29.20), or 0 if the extension is not present.
    pub number: u32,
}

#[cfg(feature = "default-x509")]
pub(crate) fn parse_crl_info(crl_der: &[u8]) -> Result<CrlInfo> {
    use der::Decode as _;
    let crl: x509_cert::crl::CertificateList<x509_cert::certificate::Rfc5280> =
        x509_cert::crl::CertificateList::from_der(crl_der).context("Failed to parse CRL")?;
    let tbs = &crl.tbs_cert_list;
    let mut number = 0;
    // OID 2.5.29.20 = id-ce-cRLNumber
    if let Some(ext) = tbs
        .crl_extensions
        .iter()
        .flatten()
        .find(|ext| ext.extn_id.to_string() == "2.5.29.20")
    {
        // CRL Number is encoded as an ASN.1 INTEGER
        let crl_num =
            der::asn1::UintRef::from_der(ext.extn_value.as_bytes()).context("CRL number")?;
        let bytes = crl_num.as_bytes();
        // Convert big-endian bytes to u32 (CRL numbers are typically small)
        ensure!(bytes.len() <= 4, "CRL number too large for u32");
        for &b in bytes {
            number = (number << 8) | u32::from(b);
        }
    }
    Ok(CrlInfo {
        this_update: tbs.this_update.to_unix_duration().as_secs(),
        next_update: tbs.next_update.map(|t| t.to_unix_duration().as_secs()),
        number,
    })
}

/// Parse the root CA CRL and the PCK CRL for reuse across all certificate chain
/// verifications.
///
/// Every chain checks the root CA CRL, so its signature is verified here once with the
/// root CA key (`root_spki`) instead of on each chain.
pub fn parse_crls(
    root_ca_crl: &[u8],
    pck_crl: &[u8],
    root_spki: &[u8],
) -> Result<[CertRevocationList<'static>; 2]> {
    Ok([
        OwnedCertRevocationList::from_der_verified(
            root_ca_crl,
            root_spki,
            webpki::ALL_VERIFICATION_ALGS,
        )
        .context("Failed to parse root CA CRL")?
        .into(),
        OwnedCertRevocationList::from_der(pck_crl)
            .context("Failed to parse PCK CRL")?
            .into(),
    ])
}

/// Verifies that the `leaf_cert` in combination with the `intermediate_certs` establishes
/// a valid certificate chain that is rooted in one of the trust anchors that was compiled into the pallet
///
/// It will also check that the certificate is not revoked according to the CRL
pub fn verify_certificate_chain(
    leaf_cert: &webpki::EndEntityCert,
    intermediate_certs: &[CertificateDer],
    time: UnixTime,
    crls: &[CertRevocationList<'_>],
    trust_anchor: TrustAnchor<'_>,
) -> Result<()> {
    let sig_algs = webpki::ALL_VERIFICATION_ALGS;

    let crl_slice = crls.iter().collect::<Vec<_>>();

    // Create a RevocationOptions object with the CRL
    let builder = match webpki::RevocationOptionsBuilder::new(&crl_slice) {
        Ok(builder) => builder,
        Err(_) => bail!("Failed to create RevocationOptionsBuilder - CRLs required"),
    };
    let revocation = builder
        .with_depth(webpki::RevocationCheckDepth::Chain)
        .with_status_policy(webpki::UnknownStatusPolicy::Deny)
        .with_expiration_policy(webpki::ExpirationPolicy::Enforce)
        .build();

    leaf_cert
        .verify_for_usage(
            sig_algs,
            &[trust_anchor],
            intermediate_certs,
            time,
            webpki::KeyUsage::server_auth(),
            Some(revocation),
            None,
        )
        .context("Failed to verify certificate chain")?;

    Ok(())
}
