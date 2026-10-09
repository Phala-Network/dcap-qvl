use alloc::vec::Vec;
use anyhow::{anyhow, bail, ensure, Context, Result};
use asn1_der::{
    typed::{DerDecodable, DerTypeView, Sequence},
    DerObject,
};
use rustls_pki_types::{CertificateDer, SignatureVerificationAlgorithm, TrustAnchor, UnixTime};
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
    let obj = DerObject::decode(raw)
        .map_err(anyhow::Error::msg)
        .context("Failed to decode DER object")?;
    let subobj = get_obj(path, obj).context("Failed to get subobject")?;
    Ok(subobj.value().to_vec())
}

fn get_obj<'a>(path: &[&[u8]], mut obj: DerObject<'a>) -> Result<DerObject<'a>> {
    for oid in path {
        let seq = Sequence::load(obj)
            .map_err(anyhow::Error::msg)
            .context("Failed to load sequence")?;
        obj = sub_obj(oid, seq).context("Failed to get subobject")?;
    }
    Ok(obj)
}

/// Iterates over the entries of a DER SEQUENCE in a single pass.
///
/// `Sequence::get(i)` re-walks the sequence from its start on every call, so
/// an indexed loop is quadratic in the number of entries.
pub(crate) fn seq_entries<'a>(seq: &Sequence<'a>) -> impl Iterator<Item = Result<DerObject<'a>>> {
    let mut rest = seq.object().value();
    core::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let entry = DerObject::decode(rest).map_err(anyhow::Error::msg);
        rest = entry
            .as_ref()
            .ok()
            .and_then(|obj| rest.get(obj.header().len().saturating_add(obj.value().len())..))
            .unwrap_or_default();
        Some(entry)
    })
}

fn sub_obj<'a>(oid: &[u8], seq: Sequence<'a>) -> Result<DerObject<'a>> {
    for entry in seq_entries(&seq) {
        let entry = entry.context("Failed to get entry")?;
        let entry = Sequence::load(entry)
            .map_err(anyhow::Error::msg)
            .context("Failed to load sequence")?;
        let name = entry
            .get(0)
            .map_err(anyhow::Error::msg)
            .context("Failed to get name")?;
        let value = entry
            .get(1)
            .map_err(anyhow::Error::msg)
            .context("Failed to get value")?;
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
        .map_err(anyhow::Error::msg)
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
    if let Some(ext) = tbs
        .crl_extensions
        .iter()
        .flatten()
        .find(|ext| ext.extn_id == crate::oids::CRL_NUMBER)
    {
        // CRL Number is encoded as an ASN.1 INTEGER
        let crl_num =
            der::asn1::UintRef::from_der(ext.extn_value.as_bytes()).context("CRL number")?;
        let bytes = crl_num.as_bytes();
        // Convert big-endian bytes to u32 (CRL numbers are typically small)
        anyhow::ensure!(bytes.len() <= 4, "CRL number too large for u32");
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
/// root CA key (`root_spki`) and `sig_algo` instead of on each chain.
pub fn parse_crls(
    root_ca_crl: &[u8],
    pck_crl: &[u8],
    root_spki: &[u8],
    sig_algo: &dyn SignatureVerificationAlgorithm,
) -> Result<[CertRevocationList<'static>; 2]> {
    Ok([
        OwnedCertRevocationList::from_der_verified(root_ca_crl, root_spki, &[sig_algo])
            .map_err(anyhow::Error::msg)
            .context("Failed to parse root CA CRL")?
            .into(),
        OwnedCertRevocationList::from_der(pck_crl)
            .map_err(anyhow::Error::msg)
            .context("Failed to parse PCK CRL")?
            .into(),
    ])
}

/// Intel's DCAP chains carry at most an intermediate CA and the root above the
/// leaf. The path builder re-parses every candidate on each of its up to 200k
/// build steps, so a long attacker-supplied list is a CPU-exhaustion vector.
const MAX_INTERMEDIATE_CERTS: usize = 4;

/// Verifies that the `leaf_cert` in combination with the `intermediate_certs` establishes
/// a valid certificate chain that is rooted in one of the trust anchors that was compiled into the pallet
///
/// It will also check that the certificate is not revoked according to the CRL.
///
/// Returns the certificates of the verified path (leaf first, trust anchor excluded).
/// Certificates in `intermediate_certs` that are not on the path are left out.
///
/// `sig_algo` is the only accepted signature algorithm: Intel's PKI uses ECDSA
/// P-256/SHA-256 throughout, and not referencing other algorithms keeps them out of
/// the binary.
pub fn verify_certificate_chain(
    leaf_cert: &webpki::EndEntityCert,
    intermediate_certs: &[CertificateDer],
    time: UnixTime,
    crls: &[CertRevocationList<'_>],
    trust_anchor: TrustAnchor<'_>,
    sig_algo: &dyn SignatureVerificationAlgorithm,
) -> Result<Vec<CertificateDer<'static>>> {
    ensure!(
        intermediate_certs.len() <= MAX_INTERMEDIATE_CERTS,
        "Too many intermediate certificates: {}",
        intermediate_certs.len()
    );
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

    let trust_anchors = [trust_anchor];
    let path = leaf_cert
        .verify_for_usage(
            &[sig_algo],
            &trust_anchors,
            intermediate_certs,
            time,
            webpki::KeyUsage::server_auth(),
            Some(revocation),
            None,
        )
        .map_err(anyhow::Error::msg)
        .context("Failed to verify certificate chain")?;

    Ok(core::iter::once(path.end_entity().der())
        .chain(path.intermediate_certificates().map(|cert| cert.der()))
        .map(CertificateDer::into_owned)
        .collect())
}
