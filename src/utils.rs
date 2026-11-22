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

/// Parses an RFC 3339 date-time and returns its Unix timestamp in seconds.
///
/// Accepted form: `YYYY-MM-DD` (`T`|`t`|space) `HH:MM:SS[.f+]`
/// (`Z`|`z`|`+HH:MM`|`-HH:MM`). Fractional seconds are accepted and ignored,
/// and a seconds value of `60` counts as `59`. Anything else, including
/// trailing input, is rejected.
pub(crate) fn parse_rfc3339_unix_secs(value: &str) -> Result<u64> {
    let secs = rfc3339_to_unix(value.as_bytes())
        .map_err(|e| anyhow!("Failed to parse RFC3339 datetime: {e}"))?;
    secs.try_into()
        .context("RFC3339 datetime is before Unix epoch")
}

/// Splits `n` ASCII digits off the front of `input` and returns their value.
fn take_digits(input: &mut &[u8], n: usize) -> core::result::Result<i64, &'static str> {
    let (head, tail) = input.split_at_checked(n).ok_or("input too short")?;
    *input = tail;
    head.iter().try_fold(0i64, |acc, &c| {
        if c.is_ascii_digit() {
            acc.checked_mul(10)
                .and_then(|v| v.checked_add(i64::from(c.wrapping_sub(b'0'))))
                .ok_or("number out of range")
        } else {
            Err("expected digit")
        }
    })
}

/// Consumes one byte of `input` if it is one of `allowed`.
fn take_byte(input: &mut &[u8], allowed: &[u8]) -> core::result::Result<(), &'static str> {
    match input.split_first() {
        Some((c, tail)) if allowed.contains(c) => {
            *input = tail;
            Ok(())
        }
        Some(_) => Err("unexpected character"),
        None => Err("input too short"),
    }
}

// All operands below are bounded by the range checks before them (the year has
// four digits, every other field is a validated two-digit value), so none of
// the arithmetic can overflow an i64.
#[allow(clippy::arithmetic_side_effects)]
fn rfc3339_to_unix(mut b: &[u8]) -> core::result::Result<i64, &'static str> {
    let year = take_digits(&mut b, 4)?;
    take_byte(&mut b, b"-")?;
    let month = take_digits(&mut b, 2)?;
    take_byte(&mut b, b"-")?;
    let day = take_digits(&mut b, 2)?;
    take_byte(&mut b, b"Tt ")?;
    let hour = take_digits(&mut b, 2)?;
    take_byte(&mut b, b":")?;
    let min = take_digits(&mut b, 2)?;
    take_byte(&mut b, b":")?;
    let sec = take_digits(&mut b, 2)?;

    let is_leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap => 29,
        2 => 28,
        _ => return Err("month out of range"),
    };
    if !(1..=days_in_month).contains(&day) {
        return Err("day out of range");
    }
    if hour > 23 || min > 59 || sec > 60 {
        return Err("time out of range");
    }
    // Like the parser this replaced, a leap second maps to the preceding second.
    let sec = sec.min(59);

    if let Some((b'.', tail)) = b.split_first() {
        let digits = tail.iter().take_while(|c| c.is_ascii_digit()).count();
        if digits == 0 {
            return Err("empty fractional seconds");
        }
        b = tail.get(digits..).unwrap_or_default();
    }

    let offset = if b == b"Z" || b == b"z" {
        b = &[];
        0
    } else {
        let negative = match b.first() {
            Some(b'+') => false,
            Some(b'-') => true,
            Some(_) => return Err("invalid timezone offset"),
            None => return Err("input too short"),
        };
        b = b.get(1..).unwrap_or_default();
        let off_hour = take_digits(&mut b, 2)?;
        take_byte(&mut b, b":")?;
        let off_min = take_digits(&mut b, 2)?;
        if off_hour > 23 || off_min > 59 {
            return Err("offset out of range");
        }
        let off = off_hour * 3600 + off_min * 60;
        if negative {
            -off
        } else {
            off
        }
    };
    if !b.is_empty() {
        return Err("trailing characters");
    }

    // Days since 1970-01-01 in the proleptic Gregorian calendar.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;

    Ok(days * 86_400 + hour * 3600 + min * 60 + sec - offset)
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_accepts_intel_collateral_timestamps() {
        // Shapes Intel PCS emits for issueDate, nextUpdate and tcbDate.
        for (input, expected) in [
            ("1970-01-01T00:00:00Z", 0),
            ("2018-01-04T01:02:03Z", 1_515_027_723),
            ("2023-02-15T00:00:00Z", 1_676_419_200),
            ("2024-03-13T00:00:00Z", 1_710_288_000),
            ("2024-02-29T23:59:59Z", 1_709_251_199),
            ("2038-01-19T03:14:08Z", 2_147_483_648),
            ("2106-02-07T06:28:16Z", 4_294_967_296),
            ("9999-12-31T23:59:59Z", 253_402_300_799),
        ] {
            assert_eq!(parse_rfc3339_unix_secs(input).unwrap(), expected, "{input}");
        }
    }

    #[test]
    fn rfc3339_handles_offsets_fractions_and_separators() {
        let base = parse_rfc3339_unix_secs("2024-03-13T12:00:00Z").unwrap();
        for input in [
            "2024-03-13t12:00:00z",
            "2024-03-13 12:00:00Z",
            "2024-03-13T12:00:00.000Z",
            "2024-03-13T12:00:00.999999999999Z",
            "2024-03-13T14:30:00+02:30",
            "2024-03-13T09:00:00-03:00",
            "2024-03-13T12:00:00+00:00",
            "2024-03-13T12:00:00-00:00",
        ] {
            assert_eq!(parse_rfc3339_unix_secs(input).unwrap(), base, "{input}");
        }
        // Leap second maps to the preceding second.
        assert_eq!(
            parse_rfc3339_unix_secs("2016-12-31T23:59:60Z").unwrap(),
            parse_rfc3339_unix_secs("2016-12-31T23:59:59Z").unwrap()
        );
    }

    #[test]
    fn rfc3339_rejects_malformed_input() {
        for input in [
            "",
            "2024",
            "2024-03-13",
            "2024-03-13T12:00:00",
            "2024-03-13T12:00Z",
            "2024-3-13T12:00:00Z",
            "24-03-13T12:00:00Z",
            "+024-03-13T12:00:00Z",
            "2024/03/13T12:00:00Z",
            "2024-03-13X12:00:00Z",
            "2024-03-13T12-00-00Z",
            "2024-13-01T00:00:00Z",
            "2024-00-01T00:00:00Z",
            "2024-04-31T00:00:00Z",
            "2023-02-29T00:00:00Z",
            "1900-02-29T00:00:00Z",
            "2024-03-00T00:00:00Z",
            "2024-03-13T24:00:00Z",
            "2024-03-13T12:60:00Z",
            "2024-03-13T12:00:61Z",
            "2024-03-13T12:00:00.Z",
            "2024-03-13T12:00:00ZZ",
            "2024-03-13T12:00:00Z ",
            " 2024-03-13T12:00:00Z",
            "2024-03-13T12:00:00UTC",
            "2024-03-13T12:00:00+02",
            "2024-03-13T12:00:00+0200",
            "2024-03-13T12:00:00+24:00",
            "2024-03-13T12:00:00+02:60",
            "2024-03-1\u{e9}T12:00:00Z",
            "\u{ff12}024-03-13T12:00:00Z",
        ] {
            let err = parse_rfc3339_unix_secs(input).unwrap_err();
            assert!(
                err.to_string()
                    .starts_with("Failed to parse RFC3339 datetime"),
                "{input:?}: {err}"
            );
        }
    }

    #[test]
    fn rfc3339_rejects_unicode_minus_offset() {
        // chrono tolerates U+2212 as an offset sign; RFC 3339 does not.
        assert!(parse_rfc3339_unix_secs("2024-03-13T12:00:00\u{2212}02:00").is_err());
    }

    #[test]
    fn rfc3339_rejects_pre_epoch() {
        for input in [
            "1969-12-31T23:59:59Z",
            "1970-01-01T00:00:00+01:00",
            "0000-01-01T00:00:00Z",
        ] {
            let err = parse_rfc3339_unix_secs(input).unwrap_err();
            assert_eq!(
                err.to_string(),
                "RFC3339 datetime is before Unix epoch",
                "{input}"
            );
        }
        assert_eq!(
            parse_rfc3339_unix_secs("1969-12-31T23:00:00-01:00").unwrap(),
            0
        );
    }

    /// Cross-check against chrono over a deterministic spread of inputs,
    /// including every valid/invalid shape the cases above exercise.
    #[test]
    fn rfc3339_agrees_with_chrono() {
        let reference = |s: &str| -> Option<u64> {
            chrono::DateTime::parse_from_rfc3339(s)
                .ok()
                .and_then(|d| u64::try_from(d.timestamp()).ok())
        };
        let mut checked = 0u32;
        for year in [1970, 1999, 2000, 2024, 2100, 2400, 9999] {
            for month in 1..=12u32 {
                for day in [1, 28, 29, 30, 31] {
                    for time in ["00:00:00", "12:34:56", "23:59:59", "23:59:60"] {
                        for tz in ["Z", "+05:30", "-08:00", "+23:59"] {
                            let s = format!("{year:04}-{month:02}-{day:02}T{time}{tz}");
                            assert_eq!(parse_rfc3339_unix_secs(&s).ok(), reference(&s), "{s}");
                            checked += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(checked, 6720);
    }

    #[test]
    fn seq_entries_yields_each_entry_in_order() {
        let seq = |der: &'static [u8]| Sequence::decode(der).unwrap();
        let values = |der| {
            seq_entries(&seq(der))
                .map(|e| e.unwrap().value().to_vec())
                .collect::<Vec<_>>()
        };
        assert!(values(&[0x30, 0x00]).is_empty());
        assert_eq!(
            values(&[0x30, 0x07, 0x02, 0x01, 0x01, 0x04, 0x02, 0xAA, 0xBB]),
            [vec![0x01], vec![0xAA, 0xBB]]
        );
    }

    #[cfg(feature = "ring")]
    #[test]
    fn verify_certificate_chain_rejects_too_many_intermediates() {
        let quote = crate::quote::Quote::parse(include_bytes!("../sample/sgx_quote")).unwrap();
        let chain = crate::intel::extract_cert_chain(&quote).unwrap();
        let leaf_der = CertificateDer::from_slice(&chain[0]);
        let leaf = webpki::EndEntityCert::try_from(&leaf_der).unwrap();
        let root = CertificateDer::from_slice(crate::constants::TRUSTED_ROOT_CA_DER);
        let anchor = webpki::anchor_from_trusted_cert(&root).unwrap();
        let verify = |count| {
            let intermediates = vec![CertificateDer::from_slice(&chain[1]); count];
            verify_certificate_chain(
                &leaf,
                &intermediates,
                UnixTime::now(),
                &[],
                anchor.clone(),
                webpki::ring::ECDSA_P256_SHA256,
            )
        };
        let too_many = |count| {
            verify(count)
                .is_err_and(|e| e.to_string().contains("Too many intermediate certificates"))
        };
        assert!(!too_many(MAX_INTERMEDIATE_CERTS));
        assert!(too_many(MAX_INTERMEDIATE_CERTS + 1));
    }
}
