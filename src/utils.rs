use alloc::vec::Vec;
use anyhow::{anyhow, bail, Context, Result};
use asn1_der::{
    typed::{DerDecodable, Sequence},
    DerObject,
};
use webpki::{
    self,
    types::{TrustAnchor, UnixTime},
    BorrowedCertRevocationList,
};
use webpki::{types::CertificateDer, CertRevocationList};
use x509_cert::Certificate;

use crate::{constants::*, oids};

pub fn get_intel_extension(der_encoded: &[u8]) -> Result<Vec<u8>> {
    let cert: Certificate =
        der::Decode::from_der(der_encoded).context("Failed to decode certificate")?;
    let mut extension_iter = cert
        .tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .filter(|e| e.extn_id == oids::SGX_EXTENSION)
        .map(|e| e.extn_value.clone());

    let extension = extension_iter.next().context("Intel extension not found")?;
    if extension_iter.next().is_some() {
        //"There should only be one section containing Intel extensions"
        bail!("Intel extension ambiguity");
    }
    Ok(extension.into_bytes())
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
    bail!("Oid is missing");
}

pub fn get_fmspc(extension_section: &[u8]) -> Result<Fmspc> {
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

    match data.len() {
        1 => Ok(u16::from(data[0])),
        2 => Ok(u16::from_be_bytes(
            data.try_into()
                .map_err(|_| anyhow!("Failed to decode PceSvn"))?,
        )),
        _ => bail!("PceSvn length mismatch"),
    }
}

pub fn extract_raw_certs(cert_chain: &[u8]) -> Result<Vec<Vec<u8>>> {
    Ok(pem::parse_many(cert_chain)
        .context("Failed to parse certs")?
        .iter()
        .map(|i| i.contents().to_vec())
        .collect())
}

pub fn extract_certs<'a>(cert_chain: &'a [u8]) -> Result<Vec<CertificateDer<'a>>> {
    let mut certs = Vec::<CertificateDer<'a>>::new();

    let raw_certs = extract_raw_certs(cert_chain)?;
    for raw_cert in raw_certs.iter() {
        let cert = webpki::types::CertificateDer::<'a>::from(raw_cert.to_vec());
        certs.push(cert);
    }

    Ok(certs)
}

/// Encode two 32-byte values in DER format
/// This is meant for 256 bit ECC signatures or public keys
/// TODO: We may could use `asn1_der` crate reimplement this, so we can remove `der` which overlap with `asn1_der`
pub fn encode_as_der(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() != 64 {
        bail!("Key length is invalid");
    }
    let mut sequence = der::asn1::SequenceOf::<der::asn1::UintRef, 2>::new();
    sequence
        .add(der::asn1::UintRef::new(&data[0..32]).context("Failed to add first element")?)
        .context("Failed to add second element")?;
    sequence
        .add(der::asn1::UintRef::new(&data[32..]).context("Failed to add third element")?)
        .context("Failed to add third element")?;
    // 72 should be enough in all cases. 2 + 2 x (32 + 3)
    let mut asn1 = alloc::vec![0u8; 72];
    let mut writer = der::SliceWriter::new(&mut asn1);
    writer
        .encode(&sequence)
        .context("Failed to encode sequence")?;
    Ok(writer.finish().context("Failed to finish writer")?.to_vec())
}

/// Verifies that the `leaf_cert` in combination with the `intermediate_certs` establishes
/// a valid certificate chain that is rooted in one of the trust anchors that was compiled into to the pallet
///
/// It will also check that the certificate is not revoked according to the CRL
pub fn verify_certificate_chain(
    leaf_cert: &webpki::EndEntityCert,
    intermediate_certs: &[CertificateDer],
    time: UnixTime,
    crl_der: &[&[u8]],
    trust_anchor: TrustAnchor<'_>,
) -> Result<()> {
    let sig_algs = webpki::ALL_VERIFICATION_ALGS;

    // Parse the CRL
    let crls: Vec<CertRevocationList> = crl_der
        .iter()
        .map(|der| BorrowedCertRevocationList::from_der(der).map(|crl| crl.into()))
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse CRL")?;
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
