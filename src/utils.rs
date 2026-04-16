use alloc::{string::String, vec::Vec};
use anyhow::{anyhow, bail, Context, Result};
use asn1_der::{
    typed::{DerDecodable, Integer, Sequence},
    DerObject, VecBacking,
};
use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};
use webpki::{self, CertRevocationList, OwnedCertRevocationList};

use crate::{constants::*, oids};

/// Parse the tbsCertificate SEQUENCE from a DER-encoded X.509 certificate.
///
/// X.509 structure:
///   Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
fn parse_tbs_certificate(der_encoded: &[u8]) -> Result<Sequence<'_>> {
    let cert = Sequence::decode(der_encoded).context("Failed to decode certificate")?;
    cert.get_as::<Sequence>(0)
        .context("Failed to decode tbsCertificate")
}

pub fn get_intel_extension(der_encoded: &[u8]) -> Result<Vec<u8>> {
    let tbs = parse_tbs_certificate(der_encoded)?;

    // Find the extensions field: context-tagged [3] EXPLICIT wrapper
    let mut extensions_raw = None;
    for i in 0..tbs.len() {
        let elem = tbs.get(i).context("Failed to get tbsCertificate element")?;
        if elem.tag() == 0xA3 {
            extensions_raw = Some(elem.value());
            break;
        }
    }
    let extensions_raw = extensions_raw.context("No extensions found in certificate")?;

    // The [3] wrapper contains a SEQUENCE OF Extension
    // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN OPTIONAL, extnValue OCTET STRING }
    let ext_seq =
        Sequence::decode(extensions_raw).context("Failed to decode extensions sequence")?;

    let sgx_oid = oids::SGX_EXTENSION.as_bytes();
    let mut found: Option<Vec<u8>> = None;
    for i in 0..ext_seq.len() {
        let ext: Sequence = ext_seq.get_as(i).context("Failed to decode extension")?;

        let oid_obj = ext.get(0).context("Missing extension OID")?;
        if oid_obj.value() == sgx_oid {
            if found.is_some() {
                bail!("Intel extension ambiguity");
            }
            // The value is the last element (index 1 or 2 depending on critical flag)
            let value_idx = ext
                .len()
                .checked_sub(1)
                .context("Empty extension sequence")?;
            let value_obj = ext.get(value_idx).context("Missing extension value")?;
            found = Some(value_obj.value().to_vec());
        }
    }
    found.context("Intel extension not found")
}

/// Extract the issuer's human-readable name from a DER-encoded X.509 certificate.
///
/// Navigates the ASN.1 structure: Certificate -> tbsCertificate -> issuer (4th field),
/// then concatenates all printable/UTF-8 string values from the RDN sequence.
pub fn get_cert_issuer_string(der_encoded: &[u8]) -> Result<String> {
    let tbs = parse_tbs_certificate(der_encoded)?;

    // tbsCertificate fields: version[0], serialNumber, signature, issuer, ...
    // version is context-tagged [0] EXPLICIT, so if the first element's tag is 0xA0,
    // issuer is at index 3; otherwise (v1 certs without explicit version) at index 2.
    let first_tag = tbs.get(0).context("Empty tbsCertificate")?.tag();
    let issuer_idx = if first_tag == 0xA0 { 3 } else { 2 };

    let issuer: Sequence = tbs.get_as(issuer_idx).context("Failed to decode issuer")?;

    // Issuer is a SEQUENCE OF RelativeDistinguishedName
    // Each RDN is a SET (tag 0x31) OF AttributeTypeAndValue
    // Each ATV is a SEQUENCE { OID, value }
    let mut parts = Vec::new();
    for i in 0..issuer.len() {
        let rdn_obj = issuer.get(i).context("Failed to get RDN")?;
        // RDN is a SET (tag 0x31) - iterate its AttributeTypeAndValue SEQUENCEs
        let rdn_bytes = rdn_obj.value();
        let mut pos: usize = 0;
        while pos < rdn_bytes.len() {
            let atv = DerObject::decode_at(rdn_bytes, pos).context("Failed to decode ATV")?;
            pos = pos
                .checked_add(atv.raw().len())
                .context("ATV offset overflow")?;
            let atv_seq = Sequence::load(atv).context("Failed to load ATV as sequence")?;
            let value = match atv_seq.get(1) {
                Ok(v) if matches!(v.tag(), 0x13 | 0x0C | 0x16) => v,
                _ => continue,
            };
            if let Ok(s) = core::str::from_utf8(value.value()) {
                parts.push(s);
            }
        }
    }
    Ok(parts.join(","))
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

pub(crate) fn extract_raw_certs(cert_chain: &[u8]) -> Result<Vec<Vec<u8>>> {
    Ok(pem::parse_many(cert_chain)
        .context("Failed to parse certs")?
        .iter()
        .map(|i| i.contents().to_vec())
        .collect())
}

pub fn extract_certs<'a>(cert_chain: &'a [u8]) -> Result<Vec<CertificateDer<'a>>> {
    Ok(extract_raw_certs(cert_chain)?
        .into_iter()
        .map(CertificateDer::from)
        .collect())
}

/// Encode two 32-byte values as a DER SEQUENCE of two INTEGERs.
/// This is meant for 256 bit ECC signatures (r, s components).
///
/// Uses `asn1_der::typed::Integer::write` for correct DER integer encoding
/// (leading zero stripping and sign-bit padding).
pub fn encode_as_der(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() != 64 {
        bail!("Expected 64 bytes (two 32-byte values), got {}", data.len());
    }
    let (first, second) = data.split_at(32);

    // Encode both integers into a temporary buffer
    let mut inner = Vec::with_capacity(72);
    Integer::write(first, false, &mut VecBacking(&mut inner))
        .context("Failed to encode first integer")?;
    Integer::write(second, false, &mut VecBacking(&mut inner))
        .context("Failed to encode second integer")?;

    // Wrap in SEQUENCE
    let mut result = Vec::with_capacity(72);
    DerObject::write(
        0x30,
        inner.len(),
        &mut inner.iter(),
        &mut VecBacking(&mut result),
    )
    .context("Failed to encode DER sequence")?;

    Ok(result)
}

/// Parse CRL DER bytes into CertRevocationList objects.
/// Call this once and pass the results to `verify_certificate_chain`.
pub fn parse_crls(crl_der: &[&[u8]]) -> Result<Vec<CertRevocationList<'static>>> {
    crl_der
        .iter()
        .map(|der| OwnedCertRevocationList::from_der(der).map(CertRevocationList::from))
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse CRL")
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
