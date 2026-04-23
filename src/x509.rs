//! Audited [`X509Codec`] implementation backed by `x509-cert` + `der`.
//!
//! Selected by [`crate::configs::RingConfig`] / [`crate::configs::RustCryptoConfig`]
//! / [`crate::configs::DefaultConfig`].

use alloc::vec::Vec;
use anyhow::{bail, Context, Result};
use der::{Tag, Tagged};

use crate::config::{ParsedCert, X509Codec};

/// Audited default [`X509Codec`] implementation, built on `x509-cert` + `der`.
///
/// Zero-sized factory; produces [`X509CertParsed`] from raw DER bytes. The
/// `x509_cert::Certificate` type owns its parsed data, so this backend does
/// not borrow from the input slice — but the GAT shape leaves room for
/// downstream zero-copy backends (e.g. `asn1_der`).
pub struct X509CertBackend;

/// Owned, parsed X.509 certificate produced by [`X509CertBackend`].
pub struct X509CertParsed {
    cert: x509_cert::Certificate,
}

impl X509Codec for X509CertBackend {
    type Parsed<'a> = X509CertParsed;

    fn from_der<'a>(cert_der: &'a [u8]) -> Result<Self::Parsed<'a>> {
        let cert: x509_cert::Certificate =
            der::Decode::from_der(cert_der).context("Failed to decode certificate")?;
        Ok(X509CertParsed { cert })
    }
}

impl ParsedCert for X509CertParsed {
    fn issuer_contains(&self, needle: &[u8]) -> bool {
        if needle.is_empty() {
            return true;
        }
        for rdn in self.cert.tbs_certificate.issuer.0.iter() {
            for atv in rdn.0.iter() {
                if matches!(
                    atv.value.tag(),
                    Tag::PrintableString | Tag::Utf8String | Tag::Ia5String | Tag::TeletexString
                ) && atv.value.value().windows(needle.len()).any(|w| w == needle)
                {
                    return true;
                }
            }
        }
        false
    }

    fn extension(&self, oid: &[u8]) -> Result<Option<Vec<u8>>> {
        // Compare raw DER-encoded OID bodies byte-for-byte. Callers pass the
        // body of a `const_oid`-constructed OID, so there is nothing left to
        // validate at runtime. (The parse itself would not add footprint —
        // `der::Decode<ObjectIdentifier>` is already reachable via cert
        // parsing — but it is pure runtime cost for no benefit.)
        let mut found: Option<&[u8]> = None;
        for ext in self
            .cert
            .tbs_certificate
            .extensions
            .as_deref()
            .unwrap_or(&[])
        {
            if ext.extn_id.as_bytes() == oid {
                if found.is_some() {
                    // NOTE: would be friendlier to include the offending OID here
                    // (e.g. `"extension {} appears more than once", ext.extn_id`),
                    // but using `<ObjectIdentifier as Display>` from this call
                    // site adds ~60–100 B of format-args setup to the stripped
                    // contract wasm (measured on wasm32 `opt-level=z` + `lto=fat`
                    // + `wasm-opt -O -Oz`). The duplicate-extension path is only
                    // reachable on a malformed cert, which Intel-signed chains
                    // never produce, so the ergonomics aren't worth the binary
                    // cost. Revisit if a maintainer pushes back.
                    bail!("extension appears more than once");
                }
                found = Some(ext.extn_value.as_bytes());
            }
        }
        Ok(found.map(<[u8]>::to_vec))
    }
}
