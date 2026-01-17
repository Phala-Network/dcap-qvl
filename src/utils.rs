use alloc::vec::Vec;
use anyhow::{anyhow, bail, Context, Result};
use asn1_der::{
    typed::{DerDecodable, Sequence},
    DerObject,
};
use der::{Decode, Encode};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use x509_cert::crl::CertificateList;
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

    match data[..] {
        [byte0] => Ok(u16::from(byte0)),
        [byte0, byte1] => Ok(u16::from_be_bytes([byte0, byte1])),
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

/// Extract DER-encoded certificates from a PEM chain
pub fn extract_certs(cert_chain: &[u8]) -> Result<Vec<Vec<u8>>> {
    extract_raw_certs(cert_chain)
}

/// Encode two 32-byte values in DER format
/// This is meant for 256 bit ECC signatures or public keys
/// TODO: We may could use `asn1_der` crate reimplement this, so we can remove `der` which overlap with `asn1_der`
pub fn encode_as_der(data: &[u8]) -> Result<Vec<u8>> {
    let (first, second) = data.split_at_checked(32).context("Invalid key length")?;
    let mut sequence = der::asn1::SequenceOf::<der::asn1::UintRef, 2>::new();
    let element0 = der::asn1::UintRef::new(first).context("Failed to add first element")?;
    sequence
        .add(element0)
        .context("Failed to add second element")?;
    let element1 = der::asn1::UintRef::new(second).context("Failed to add second element")?;
    sequence
        .add(element1)
        .context("Failed to add third element")?;
    // 72 should be enough in all cases. 2 + 2 x (32 + 3)
    let mut asn1 = alloc::vec![0u8; 72];
    let mut writer = der::SliceWriter::new(&mut asn1);
    writer
        .encode(&sequence)
        .context("Failed to encode sequence")?;
    Ok(writer.finish().context("Failed to finish writer")?.to_vec())
}

/// Check CRL validity window (thisUpdate and nextUpdate)
fn check_crl_validity(crl: &CertificateList, now_secs: u64) -> Result<()> {
    // Check thisUpdate - CRL must not be used before this time
    let this_update = crl.tbs_cert_list.this_update.to_unix_duration().as_secs();
    if now_secs < this_update {
        bail!("CRL is not yet valid (thisUpdate in the future)");
    }

    // Check nextUpdate - CRL must not be used after this time (if present)
    if let Some(next_update) = &crl.tbs_cert_list.next_update {
        let next_update_secs = next_update.to_unix_duration().as_secs();
        if now_secs > next_update_secs {
            bail!("CRL has expired (past nextUpdate)");
        }
    }

    Ok(())
}

/// Check if a certificate serial number is in the CRL
fn is_revoked(cert: &Certificate, crl: &CertificateList) -> bool {
    let serial = cert.tbs_certificate.serial_number.as_bytes();

    // Check if the CRL has any revoked certificates
    let Some(revoked_certs) = crl.tbs_cert_list.revoked_certificates.as_ref() else {
        return false;
    };

    // Check if the certificate's serial number is in the revoked list
    revoked_certs
        .iter()
        .any(|revoked| revoked.serial_number.as_bytes() == serial)
}

/// Check that a certificate has KeyUsage with cRLSign bit set
fn check_key_usage_crl_sign(cert: &Certificate) -> Result<()> {
    let extensions = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .context("Certificate has no extensions")?;

    // Find KeyUsage extension (OID 2.5.29.15)
    let key_usage_oid = const_oid::db::rfc5280::ID_CE_KEY_USAGE;
    let ku_ext = extensions
        .iter()
        .find(|ext| ext.extn_id == key_usage_oid)
        .context("KeyUsage extension not found")?;

    // Parse KeyUsage - it's a BIT STRING
    use der::Decode;
    let key_usage = x509_cert::ext::pkix::KeyUsage::from_der(ku_ext.extn_value.as_bytes())
        .context("Failed to parse KeyUsage")?;

    // Check cRLSign bit (bit 6)
    if !key_usage.crl_sign() {
        bail!("Certificate does not have cRLSign in KeyUsage");
    }

    Ok(())
}

/// Verify that a CRL was signed by the given issuer certificate
fn verify_crl_signature(crl: &CertificateList, issuer_cert: &Certificate) -> Result<()> {
    // Check that the issuer certificate is authorized to sign CRLs
    check_key_usage_crl_sign(issuer_cert)
        .context("CRL issuer certificate not authorized to sign CRLs")?;

    // Encode the TBS cert list to DER
    let tbs_bytes = crl
        .tbs_cert_list
        .to_der()
        .context("Failed to encode TBS cert list")?;

    // Get the signature bytes from the CRL
    let signature = crl.signature.raw_bytes();

    // Get the issuer's public key
    let issuer_public_key = extract_public_key(issuer_cert)?;

    // Verify the signature
    verify_ecdsa_signature(&issuer_public_key, &tbs_bytes, signature)
        .context("CRL signature verification failed")
}

/// Verify a CRL from DER bytes against a potential issuer certificate
/// This wrapper parses both, verifies the signature, and checks validity window
pub fn verify_crl_from_der(
    crl_der: &[u8],
    issuer_cert_der: &[u8],
    now_secs: u64,
) -> Result<()> {
    let crl = CertificateList::from_der(crl_der).context("Failed to parse CRL")?;
    let issuer_cert =
        Certificate::from_der(issuer_cert_der).context("Failed to parse issuer certificate")?;

    // Check CRL validity window BEFORE checking signature
    check_crl_validity(&crl, now_secs).context("CRL validity window check failed")?;

    // Verify CRL signature and KeyUsage
    verify_crl_signature(&crl, &issuer_cert)
}

/// Extract the public key bytes from a certificate's SubjectPublicKeyInfo
fn extract_public_key(cert: &Certificate) -> Result<Vec<u8>> {
    let spki = &cert.tbs_certificate.subject_public_key_info;
    // The public key is in the subject_public_key field as a BIT STRING
    // For ECDSA P-256, this is the uncompressed point (65 bytes with 0x04 prefix)
    Ok(spki.subject_public_key.raw_bytes().to_vec())
}

/// Verify an ECDSA P-256 signature
fn verify_ecdsa_signature(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|_| anyhow!("Failed to parse public key"))?;

    // The signature in X.509 is DER-encoded, we need to parse it
    let sig =
        Signature::from_der(signature).map_err(|_| anyhow!("Failed to parse DER signature"))?;

    verifying_key
        .verify(message, &sig)
        .map_err(|_| anyhow!("Signature verification failed"))
}

/// Get the TBS (To Be Signed) certificate bytes for signature verification
fn get_tbs_certificate_bytes(cert: &Certificate) -> Result<Vec<u8>> {
    cert.tbs_certificate
        .to_der()
        .context("Failed to encode TBS certificate")
}

/// Get signature bytes from a certificate
fn get_signature_bytes(cert: &Certificate) -> Vec<u8> {
    cert.signature.raw_bytes().to_vec()
}

/// Verify a certificate was signed by an issuer
fn verify_cert_signature(cert_der: &[u8], issuer_cert: &Certificate) -> Result<()> {
    let cert = Certificate::from_der(cert_der).context("Failed to parse certificate")?;
    let tbs_bytes = get_tbs_certificate_bytes(&cert)?;
    let signature = get_signature_bytes(&cert);
    let issuer_public_key = extract_public_key(issuer_cert)?;

    verify_ecdsa_signature(&issuer_public_key, &tbs_bytes, &signature)
        .context("Certificate signature verification failed")
}

/// Check that a CA certificate has BasicConstraints with ca=true
fn check_basic_constraints_ca(cert: &Certificate) -> Result<()> {
    let extensions = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .context("Certificate has no extensions")?;

    // Find BasicConstraints extension (OID 2.5.29.19)
    let basic_constraints_oid = const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS;
    let bc_ext = extensions
        .iter()
        .find(|ext| ext.extn_id == basic_constraints_oid)
        .context("BasicConstraints extension not found")?;

    // Parse BasicConstraints
    use der::Decode;
    let basic_constraints = x509_cert::ext::pkix::BasicConstraints::from_der(bc_ext.extn_value.as_bytes())
        .context("Failed to parse BasicConstraints")?;

    if !basic_constraints.ca {
        bail!("Certificate does not have ca=true in BasicConstraints");
    }

    Ok(())
}

/// Check that a certificate is valid at the given time
fn check_validity(cert: &Certificate, now_secs: u64) -> Result<()> {
    let validity = &cert.tbs_certificate.validity;

    // Convert times to unix timestamps
    let not_before = match &validity.not_before {
        x509_cert::time::Time::UtcTime(t) => t.to_unix_duration().as_secs(),
        x509_cert::time::Time::GeneralTime(t) => t.to_unix_duration().as_secs(),
    };

    let not_after = match &validity.not_after {
        x509_cert::time::Time::UtcTime(t) => t.to_unix_duration().as_secs(),
        x509_cert::time::Time::GeneralTime(t) => t.to_unix_duration().as_secs(),
    };

    if now_secs < not_before {
        bail!("Certificate is not yet valid");
    }
    if now_secs > not_after {
        bail!("Certificate has expired");
    }

    Ok(())
}

/// Verify the certificate chain and check CRLs.
/// The leaf certificate is first, followed by intermediate certificates.
/// The chain is verified against the provided root CA.
pub fn verify_certificate_chain(
    leaf_cert_der: &[u8],
    intermediate_certs_der: &[Vec<u8>],
    now_secs: u64,
    crl_der: &[&[u8]],
    root_ca_der: &[u8],
) -> Result<()> {
    // Parse all CRLs with strict error handling (no silent failures)
    let crls: Vec<CertificateList> = crl_der
        .iter()
        .enumerate()
        .map(|(i, der)| {
            CertificateList::from_der(der)
                .with_context(|| format!("Failed to parse CRL {}", i))
        })
        .collect::<Result<_>>()?;

    // Check CRL validity windows before using them
    for (i, crl) in crls.iter().enumerate() {
        check_crl_validity(crl, now_secs)
            .with_context(|| format!("CRL {} validity check failed", i))?;
    }

    // Parse the root CA
    let root_cert = Certificate::from_der(root_ca_der).context("Failed to parse root CA")?;

    // Build the certificate chain: leaf -> intermediates -> root
    let leaf_cert =
        Certificate::from_der(leaf_cert_der).context("Failed to parse leaf certificate")?;

    // Check leaf certificate validity
    check_validity(&leaf_cert, now_secs)?;

    // Check if leaf is revoked
    for crl in &crls {
        if is_revoked(&leaf_cert, crl) {
            bail!("Leaf certificate is revoked");
        }
    }

    // Verify the chain: each certificate should be signed by the next one
    let mut current_cert_der = leaf_cert_der;
    let mut current_cert = &leaf_cert;

    // Parse intermediate certificates
    let intermediate_certs: Vec<Certificate> = intermediate_certs_der
        .iter()
        .map(|der| Certificate::from_der(der).context("Failed to parse intermediate certificate"))
        .collect::<Result<Vec<_>>>()?;

    // Verify intermediates
    for (i, (intermediate, intermediate_der)) in intermediate_certs
        .iter()
        .zip(intermediate_certs_der.iter())
        .enumerate()
    {
        // Check validity
        check_validity(intermediate, now_secs)?;

        // Check BasicConstraints: intermediates must have ca=true
        check_basic_constraints_ca(intermediate)
            .with_context(|| format!("Intermediate certificate {} must be a CA", i))?;

        // Check issuer/subject linkage: current cert's issuer must match intermediate's subject
        if current_cert.tbs_certificate.issuer != intermediate.tbs_certificate.subject {
            bail!(
                "Certificate chain broken at intermediate {}: issuer does not match subject",
                i
            );
        }

        // Check if revoked
        for crl in &crls {
            if is_revoked(intermediate, crl) {
                bail!("Intermediate certificate {} is revoked", i);
            }
        }

        // Verify current cert was signed by this intermediate
        verify_cert_signature(current_cert_der, intermediate)?;

        current_cert_der = intermediate_der;
        current_cert = intermediate;
    }

    // Verify the last certificate (either leaf or last intermediate) was signed by root
    // Check issuer/subject linkage to root
    if current_cert.tbs_certificate.issuer != root_cert.tbs_certificate.subject {
        bail!("Certificate chain broken at root: issuer does not match root CA subject");
    }

    // Verify signature by root
    verify_cert_signature(current_cert_der, &root_cert)
        .context("Failed to verify chain against root CA")?;

    Ok(())
}

/// Check if a single certificate is revoked according to the CRLs
/// This is used for checking the root CA against CRLs
pub fn check_single_cert_crl(cert_der: &[u8], crl_der: &[&[u8]], now_secs: u64) -> Result<()> {
    let cert = Certificate::from_der(cert_der).context("Failed to parse certificate")?;

    // Check validity
    check_validity(&cert, now_secs)?;

    // Parse and check CRLs with strict error handling (no silent failures)
    for (i, crl_bytes) in crl_der.iter().enumerate() {
        let crl = CertificateList::from_der(crl_bytes)
            .with_context(|| format!("Failed to parse CRL {}", i))?;

        // Check CRL validity window
        check_crl_validity(&crl, now_secs)
            .with_context(|| format!("CRL {} validity check failed", i))?;

        if is_revoked(&cert, &crl) {
            bail!("Certificate is revoked");
        }
    }

    Ok(())
}

/// Verify a signature on data using a certificate's public key
pub fn verify_signature_with_cert(cert_der: &[u8], data: &[u8], signature: &[u8]) -> Result<()> {
    let cert = Certificate::from_der(cert_der).context("Failed to parse certificate")?;
    let public_key = extract_public_key(&cert)?;

    // The signature is DER-encoded
    verify_ecdsa_signature(&public_key, data, signature)
}
