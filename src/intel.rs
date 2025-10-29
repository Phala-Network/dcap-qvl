use anyhow::{anyhow, bail, Context, Result};
use asn1_der::{
    typed::{DerDecodable, Sequence},
    DerObject,
};

use crate::{
    constants::{self, CpuSvn, Fmspc, Svn},
    oids,
    quote::{AuthData, Quote},
    utils,
};

/// Parsed values from the Intel SGX extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PckExtension {
    pub ppid: Vec<u8>,
    pub cpu_svn: CpuSvn,
    pub pce_svn: Svn,
    pub pce_id: Vec<u8>,
    pub fmspc: Fmspc,
    pub sgx_type: u64,
    pub platform_instance_id: Option<Vec<u8>>,
}

/// Return the PCK certificate chain (DER encoded) embedded inside the quote.
///
/// * For certification data type 5 this returns the entire chain.
/// * For certification data type 4 this returns the single PCK certificate.
pub fn extract_cert_chain(quote: &Quote) -> Result<Vec<Vec<u8>>> {
    if let Ok(chain_bytes) = quote.raw_cert_chain() {
        let certs = utils::extract_certs(chain_bytes)?;
        return Ok(certs
            .into_iter()
            .map(|cert| cert.as_ref().to_vec())
            .collect());
    }

    let cert_data = match &quote.auth_data {
        AuthData::V3(data) => &data.certification_data,
        AuthData::V4(data) => &data.qe_report_data.certification_data,
    };
    if cert_data.cert_type == constants::PCK_ID_PCK_CERTIFICATE {
        return Ok(vec![cert_data.body.data.clone()]);
    }

    bail!(
        "Certification data type {} is not supported (expecting 4 or 5)",
        cert_data.cert_type
    );
}

/// Parse the Intel SGX extension values from a DER-encoded PCK certificate.
pub fn parse_pck_extension(cert_der: &[u8]) -> Result<PckExtension> {
    let extension = utils::get_intel_extension(cert_der)?;

    let ppid = find_extension_required(&[oids::PPID], &extension)?;
    let cpu_svn = utils::get_cpu_svn(&extension)?;
    let pce_svn = utils::get_pce_svn(&extension)?;
    let pce_id = find_extension_required(&[oids::PCEID], &extension)?;
    let fmspc = utils::get_fmspc(&extension)?;
    let sgx_type = decode_enumerated(&find_extension_required(&[oids::SGX_TYPE], &extension)?)?;
    let platform_instance_id = find_extension_optional(&[oids::PLATFORM_INSTANCE_ID], &extension)?;

    Ok(PckExtension {
        ppid,
        cpu_svn,
        pce_svn,
        pce_id,
        fmspc,
        sgx_type,
        platform_instance_id,
    })
}

fn find_extension_required(
    path: &[const_oid::ObjectIdentifier],
    extension: &[u8],
) -> Result<Vec<u8>> {
    find_extension_optional(path, extension)?
        .ok_or_else(|| anyhow!("Intel extension path {:?} is missing", path))
}

fn find_extension_optional(
    path: &[const_oid::ObjectIdentifier],
    extension: &[u8],
) -> Result<Option<Vec<u8>>> {
    let mut obj = DerObject::decode(extension).context("Failed to decode DER object")?;
    for oid in path {
        let seq = Sequence::load(obj).context("Failed to load sequence")?;
        match sub_object_opt(oid, seq)? {
            Some(value) => obj = value,
            None => return Ok(None),
        }
    }
    Ok(Some(obj.value().to_vec()))
}

fn sub_object_opt<'a>(
    oid: &const_oid::ObjectIdentifier,
    seq: Sequence<'a>,
) -> Result<Option<DerObject<'a>>> {
    for idx in 0..seq.len() {
        let entry = seq
            .get(idx)
            .context("Failed to read entry inside Intel extension")?;
        let entry_seq = Sequence::load(entry).context("Failed to load nested sequence")?;
        let name = entry_seq.get(0).context("Failed to read OID")?;
        let value = entry_seq.get(1).context("Failed to read value")?;
        if name.value() == oid.as_bytes() {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

fn decode_enumerated(bytes: &[u8]) -> Result<u64> {
    match bytes.len() {
        1 => Ok(bytes[0] as u64),
        2 => Ok(u16::from_be_bytes([bytes[0], bytes[1]]) as u64),
        len => bail!("Unexpected ENUMERATED length: {len}"),
    }
}
