#![allow(clippy::indexing_slicing)]

/// Comprehensive test sample generator for DCAP quote verification
/// Generates samples in the correct directory structure with quote.bin, collateral.json, and expected.json
use anyhow::Result;
use dcap_qvl::quote::*;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use scale::Encode;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

const CERT_DIR: &str = "test_data/certs";
const SAMPLES_DIR: &str = "test_data/samples";

type CollateralModifier = Box<dyn Fn(&mut serde_json::Value) -> Result<()>>;

struct TestSample {
    name: String,
    description: String,
    should_succeed: bool,
    expected_error: Option<String>,
    quote_generator: Box<dyn Fn() -> Result<Vec<u8>>>,
    collateral_modifier: Option<CollateralModifier>,
}

fn load_private_key(path: &str) -> Result<EcdsaKeyPair> {
    let pem = fs::read_to_string(path)?;
    let der = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    use base64::Engine;
    let der_bytes = base64::engine::general_purpose::STANDARD.decode(&der)?;
    let rng = SystemRandom::new();
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der_bytes, &rng)
        .map_err(|e| anyhow::anyhow!("Failed to parse private key: {:?}", e))
}

fn sign_data(key_pair: &EcdsaKeyPair, data: &[u8]) -> Result<[u8; 64]> {
    let rng = SystemRandom::new();
    let signature = key_pair
        .sign(&rng, data)
        .map_err(|e| anyhow::anyhow!("Failed to sign: {:?}", e))?;
    let sig_bytes = signature.as_ref();
    let mut result = [0u8; 64];
    result.copy_from_slice(&sig_bytes[..64]);
    Ok(result)
}

fn create_sgx_header(version: u16, attestation_key_type: u16, tee_type: u32) -> Header {
    Header {
        version,
        attestation_key_type,
        tee_type,
        qe_svn: 1,
        pce_svn: 1,
        qe_vendor_id: [0u8; 16],
        user_data: [0u8; 20],
    }
}

fn create_sgx_report(debug: bool) -> EnclaveReport {
    let mut attributes = [0u8; 16];
    if debug {
        attributes[0] = 0x02; // Set debug flag
    }
    EnclaveReport {
        cpu_svn: [1u8; 16],
        misc_select: 0,
        reserved1: [0u8; 28],
        attributes,
        mr_enclave: [0u8; 32],
        reserved2: [0u8; 32],
        mr_signer: [0u8; 32],
        reserved3: [0u8; 96],
        isv_prod_id: 0,
        isv_svn: 0,
        reserved4: [0u8; 60],
        report_data: [0u8; 64],
    }
}

fn create_tdx_report() -> TDReport10 {
    // TD attributes: bit 28 (SEPT_VE_DISABLE) must be set
    // Byte 3, bit 4 = 0x10
    let mut td_attributes = [0u8; 8];
    td_attributes[3] = 0x10; // SEPT_VE_DISABLE enabled

    TDReport10 {
        tee_tcb_svn: [1u8; 16],
        mr_seam: [0x01; 48],
        mr_signer_seam: [0x02; 48],
        seam_attributes: [0u8; 8],
        td_attributes,
        xfam: [0u8; 8],
        mr_td: [0x03; 48],
        mr_config_id: [0x04; 48],
        mr_owner: [0x05; 48],
        mr_owner_config: [0x06; 48],
        rt_mr0: [0x07; 48],
        rt_mr1: [0x08; 48],
        rt_mr2: [0x09; 48],
        rt_mr3: [0x0A; 48],
        report_data: [0u8; 64],
    }
}

fn generate_base_quote(version: u16, key_type: u16, debug: bool) -> Result<Vec<u8>> {
    let header = create_sgx_header(version, key_type, 0);
    let report = create_sgx_report(debug);

    // Load PCK certificate chain (PCK + Root CA)
    // Note: Our test certs don't have Intel extension, which is expected
    // The "missing Intel extension" error is a valid test case
    let pck_cert = fs::read_to_string(format!("{}/pck.pem", CERT_DIR))
        .unwrap_or_else(|_| String::from("DUMMY_CERT"));
    let root_cert = fs::read_to_string(format!("{}/root_ca.pem", CERT_DIR))
        .unwrap_or_else(|_| String::from("DUMMY_CERT"));
    let pck_chain_for_quote = format!("{}{}", pck_cert, root_cert);

    // Load PCK private key for signing
    let pck_key_path = &format!("{}/pck.pkcs8.key", CERT_DIR);
    let pck_key_pair = load_private_key(pck_key_path)?;

    // Generate attestation key pair
    let rng = SystemRandom::new();
    let attestation_pkcs8 =
        ring::signature::EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)?;
    let attestation_key_pair = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        attestation_pkcs8.as_ref(),
        &rng,
    )?;

    // Get public key (skip 0x04 prefix, take 64 bytes)
    let attestation_public_key = attestation_key_pair.public_key().as_ref();
    let mut ecdsa_attestation_key = [0u8; 64];
    // Ring public key format: 0x04 || x (32 bytes) || y (32 bytes)
    ecdsa_attestation_key.copy_from_slice(&attestation_public_key[1..65]);

    // Create auth data
    let qe_auth_data = vec![0u8; 32];

    // Calculate QE hash (attestation_key + qe_auth_data)
    let mut qe_hash_data = [0u8; 96]; // 64 + 32
    qe_hash_data[0..64].copy_from_slice(&ecdsa_attestation_key);
    qe_hash_data[64..].copy_from_slice(&qe_auth_data);
    let qe_hash = ring::digest::digest(&ring::digest::SHA256, &qe_hash_data);

    // Create QE report with correct hash in report_data
    let mut qe_report_data = create_sgx_report(false);
    qe_report_data.report_data[0..32].copy_from_slice(qe_hash.as_ref());
    let qe_report_bytes = qe_report_data.encode();
    let mut qe_report = [0u8; 384];
    qe_report[..qe_report_bytes.len()].copy_from_slice(&qe_report_bytes);

    // Sign QE report with PCK key
    let qe_report_signature = sign_data(&pck_key_pair, &qe_report)?;

    // Create minimal auth data
    let auth_data = if version >= 4 {
        let certification_data = CertificationData {
            cert_type: 5,
            body: Data::<u32>::new(pck_chain_for_quote.clone().into_bytes()),
        };
        let qe_report_data = QEReportCertificationData {
            qe_report,
            qe_report_signature,
            qe_auth_data: Data::<u16>::new(qe_auth_data.clone()),
            certification_data,
        };

        // Sign the quote with attestation key (header + report)
        let mut signed_data = header.encode();
        signed_data.extend_from_slice(&report.encode());
        let ecdsa_signature = sign_data(&attestation_key_pair, &signed_data)?;

        AuthData::V4(AuthDataV4 {
            ecdsa_signature,
            ecdsa_attestation_key,
            certification_data: CertificationData {
                cert_type: 5,
                body: Data::<u32>::new(vec![]),
            },
            qe_report_data,
        })
    } else {
        let certification_data = CertificationData {
            cert_type: 5,
            body: Data::<u32>::new(pck_chain_for_quote.into_bytes()),
        };

        // Sign the quote with attestation key (header + report)
        let mut signed_data = header.encode();
        signed_data.extend_from_slice(&report.encode());
        let ecdsa_signature = sign_data(&attestation_key_pair, &signed_data)?;

        AuthData::V3(AuthDataV3 {
            ecdsa_signature,
            ecdsa_attestation_key,
            qe_report,
            qe_report_signature,
            qe_auth_data: Data::<u16>::new(qe_auth_data),
            certification_data,
        })
    };

    let quote = Quote {
        header,
        report: Report::SgxEnclave(report),
        auth_data,
    };

    Ok(quote.encode())
}

fn generate_sgx_v5_quote() -> Result<Vec<u8>> {
    // Quote v5 uses Body structure and v4 auth data
    let header = create_sgx_header(5, 2, 0);
    let report = create_sgx_report(false);

    // Create Body for v5
    let body = Body {
        body_type: 1, // BODY_SGX_ENCLAVE_REPORT_TYPE
        size: 384,    // Size of EnclaveReport
    };

    let pck_cert = fs::read_to_string(format!("{}/pck.pem", CERT_DIR))?;
    let root_cert = fs::read_to_string(format!("{}/root_ca.pem", CERT_DIR))?;
    let pck_chain_for_quote = format!("{}{}", pck_cert, root_cert);

    let pck_key_path = &format!("{}/pck.pkcs8.key", CERT_DIR);
    let pck_key_pair = load_private_key(pck_key_path)?;

    let rng = SystemRandom::new();
    let attestation_pkcs8 =
        ring::signature::EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)?;
    let attestation_key_pair = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        attestation_pkcs8.as_ref(),
        &rng,
    )?;

    let attestation_public_key = attestation_key_pair.public_key().as_ref();
    let mut ecdsa_attestation_key = [0u8; 64];
    ecdsa_attestation_key.copy_from_slice(&attestation_public_key[1..65]);

    let qe_auth_data = vec![0u8; 32];
    let mut qe_hash_data = [0u8; 96];
    qe_hash_data[0..64].copy_from_slice(&ecdsa_attestation_key);
    qe_hash_data[64..].copy_from_slice(&qe_auth_data);
    let qe_hash = ring::digest::digest(&ring::digest::SHA256, &qe_hash_data);

    let mut qe_report_data = create_sgx_report(false);
    qe_report_data.report_data[0..32].copy_from_slice(qe_hash.as_ref());
    let qe_report_bytes = qe_report_data.encode();
    let mut qe_report = [0u8; 384];
    qe_report[..qe_report_bytes.len()].copy_from_slice(&qe_report_bytes);

    let qe_report_signature = sign_data(&pck_key_pair, &qe_report)?;

    // Sign quote (header + body + report)
    let mut signed_data = header.encode();
    signed_data.extend_from_slice(&body.encode());
    signed_data.extend_from_slice(&report.encode());
    let ecdsa_signature = sign_data(&attestation_key_pair, &signed_data)?;

    // Use v4 auth data for v5 quote
    let qe_report_data = QEReportCertificationData {
        qe_report,
        qe_report_signature,
        qe_auth_data: Data::<u16>::new(qe_auth_data.clone()),
        certification_data: CertificationData {
            cert_type: 5,
            body: Data::<u32>::new(pck_chain_for_quote.into_bytes()),
        },
    };

    let auth_data = AuthData::V4(AuthDataV4 {
        ecdsa_signature,
        ecdsa_attestation_key,
        certification_data: CertificationData {
            cert_type: 5,
            body: Data::<u32>::new(vec![]),
        },
        qe_report_data,
    });

    let quote = Quote {
        header,
        report: Report::SgxEnclave(report),
        auth_data,
    };

    Ok(quote.encode())
}

fn generate_tdx_quote_v4() -> Result<Vec<u8>> {
    let header = create_sgx_header(4, 2, 0x00000081); // TEE_TYPE_TDX = 0x81
    let report = create_tdx_report();

    // Load PCK certificate chain
    let pck_cert = fs::read_to_string(format!("{}/pck.pem", CERT_DIR))
        .unwrap_or_else(|_| String::from("DUMMY_CERT"));
    let root_cert = fs::read_to_string(format!("{}/root_ca.pem", CERT_DIR))
        .unwrap_or_else(|_| String::from("DUMMY_CERT"));
    let pck_chain_for_quote = format!("{}{}", pck_cert, root_cert);

    // Load PCK private key for signing
    let pck_key_path = &format!("{}/pck.pkcs8.key", CERT_DIR);
    let pck_key_pair = load_private_key(pck_key_path)?;

    // Generate attestation key pair
    let rng = SystemRandom::new();
    let attestation_pkcs8 =
        ring::signature::EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)?;
    let attestation_key_pair = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        attestation_pkcs8.as_ref(),
        &rng,
    )?;

    // Get public key
    let attestation_public_key = attestation_key_pair.public_key().as_ref();
    let mut ecdsa_attestation_key = [0u8; 64];
    ecdsa_attestation_key.copy_from_slice(&attestation_public_key[1..65]);

    // Create auth data
    let qe_auth_data = vec![0u8; 32];

    // Calculate QE hash
    let mut qe_hash_data = [0u8; 96];
    qe_hash_data[0..64].copy_from_slice(&ecdsa_attestation_key);
    qe_hash_data[64..].copy_from_slice(&qe_auth_data);
    let qe_hash = ring::digest::digest(&ring::digest::SHA256, &qe_hash_data);

    // Create QE report with correct hash
    let mut qe_report_data = create_sgx_report(false);
    qe_report_data.report_data[0..32].copy_from_slice(qe_hash.as_ref());
    let qe_report_bytes = qe_report_data.encode();
    let mut qe_report = [0u8; 384];
    qe_report[..qe_report_bytes.len()].copy_from_slice(&qe_report_bytes);

    // Sign QE report with PCK key
    let qe_report_signature = sign_data(&pck_key_pair, &qe_report)?;

    // Sign the quote with attestation key (header + report)
    let mut signed_data = header.encode();
    signed_data.extend_from_slice(&report.encode());
    let ecdsa_signature = sign_data(&attestation_key_pair, &signed_data)?;

    // Create auth data v4 with nested structure
    let qe_report_data = QEReportCertificationData {
        qe_report,
        qe_report_signature,
        qe_auth_data: Data::<u16>::new(qe_auth_data.clone()),
        certification_data: CertificationData {
            cert_type: 5,
            body: Data::<u32>::new(pck_chain_for_quote.into_bytes()),
        },
    };

    let auth_data = AuthData::V4(AuthDataV4 {
        ecdsa_signature,
        ecdsa_attestation_key,
        certification_data: CertificationData {
            cert_type: 5,
            body: Data::<u32>::new(vec![]), // Empty for v4
        },
        qe_report_data,
    });

    let quote = Quote {
        header,
        report: Report::TD10(report),
        auth_data,
    };

    Ok(quote.encode())
}

fn generate_invalid_quote() -> Result<Vec<u8>> {
    Ok(vec![0xFF; 100]) // Invalid binary data
}

fn generate_truncated_quote() -> Result<Vec<u8>> {
    Ok(vec![0x03, 0x00, 0x02, 0x00]) // Only 4 bytes
}

/// Generate a quote with cert_type 3 (encrypted PPID).
/// The quote contains encrypted PPID parameters instead of PCK certificate chain.
/// The PCK certificate chain must be provided via collateral.pck_certificate_chain.
fn generate_cert_type_3_quote() -> Result<Vec<u8>> {
    let header = create_sgx_header(3, 2, 0);
    let report = create_sgx_report(false);

    // Generate attestation key pair
    let rng = SystemRandom::new();
    let attestation_pkcs8 =
        ring::signature::EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)?;
    let attestation_key_pair = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        attestation_pkcs8.as_ref(),
        &rng,
    )?;

    // Get public key
    let attestation_public_key = attestation_key_pair.public_key().as_ref();
    let mut ecdsa_attestation_key = [0u8; 64];
    ecdsa_attestation_key.copy_from_slice(&attestation_public_key[1..65]);

    // Create auth data
    let qe_auth_data = vec![0u8; 32];

    // Calculate QE hash (attestation_key + qe_auth_data)
    let mut qe_hash_data = [0u8; 96]; // 64 + 32
    qe_hash_data[0..64].copy_from_slice(&ecdsa_attestation_key);
    qe_hash_data[64..].copy_from_slice(&qe_auth_data);
    let qe_hash = ring::digest::digest(&ring::digest::SHA256, &qe_hash_data);

    // Create QE report with correct hash in report_data
    let mut qe_report_data = create_sgx_report(false);
    qe_report_data.report_data[0..32].copy_from_slice(qe_hash.as_ref());
    let qe_report_bytes = qe_report_data.encode();
    let mut qe_report = [0u8; 384];
    qe_report[..qe_report_bytes.len()].copy_from_slice(&qe_report_bytes);

    // Load PCK private key for signing QE report
    let pck_key_path = &format!("{}/pck.pkcs8.key", CERT_DIR);
    let pck_key_pair = load_private_key(pck_key_path)?;

    // Sign QE report with PCK key
    let qe_report_signature = sign_data(&pck_key_pair, &qe_report)?;

    // Create encrypted PPID certification data (cert_type 3)
    // Format: encrypted_ppid (384 bytes for RSA-3072) + cpusvn (16) + pcesvn (2) + pceid (2)
    let encrypted_ppid = vec![0xAB; 384]; // Dummy encrypted PPID
    let mut cert_body = encrypted_ppid;
    cert_body.extend_from_slice(&[1u8; 16]); // cpusvn
    cert_body.extend_from_slice(&1u16.to_le_bytes()); // pcesvn
    cert_body.extend_from_slice(&[0u8, 1u8]); // pceid

    let certification_data = CertificationData {
        cert_type: 3, // PCK_ID_ENCRYPTED_PPID_3072
        body: Data::<u32>::new(cert_body),
    };

    // Sign the quote with attestation key (header + report)
    let mut signed_data = header.encode();
    signed_data.extend_from_slice(&report.encode());
    let ecdsa_signature = sign_data(&attestation_key_pair, &signed_data)?;

    let auth_data = AuthData::V3(AuthDataV3 {
        ecdsa_signature,
        ecdsa_attestation_key,
        qe_report,
        qe_report_signature,
        qe_auth_data: Data::<u16>::new(qe_auth_data),
        certification_data,
    });

    let quote = Quote {
        header,
        report: Report::SgxEnclave(report),
        auth_data,
    };

    Ok(quote.encode())
}

fn generate_base_collateral() -> Result<serde_json::Value> {
    // Load certificate chains
    let tcb_chain =
        fs::read_to_string(format!("{}/tcb_chain.pem", CERT_DIR)).unwrap_or_else(|_| {
            String::from("-----BEGIN CERTIFICATE-----\nDUMMY\n-----END CERTIFICATE-----\n")
        });

    // Load CRLs
    let root_crl = fs::read(format!("{}/root_ca.crl.der", CERT_DIR))
        .unwrap_or_else(|_| vec![0x30, 0x81, 0x00]); // Minimal ASN.1
    let pck_crl =
        fs::read(format!("{}/pck.crl.der", CERT_DIR)).unwrap_or_else(|_| vec![0x30, 0x81, 0x00]);

    // Create TCB info
    let tcb_info = json!({
        "id": "SGX",
        "version": 3,
        "issueDate": "2024-01-01T00:00:00Z",
        "nextUpdate": "2099-12-31T23:59:59Z",
        "fmspc": "00906EA10000",
        "pceId": "0000",
        "tcbType": 0,
        "tcbEvaluationDataNumber": 12,
        "tcbLevels": [{
            "tcb": {
                "sgxtcbcomponents": [
                    {"svn": 1}, {"svn": 1}, {"svn": 1}, {"svn": 1},
                    {"svn": 1}, {"svn": 1}, {"svn": 1}, {"svn": 1},
                    {"svn": 1}, {"svn": 1}, {"svn": 1}, {"svn": 1},
                    {"svn": 1}, {"svn": 1}, {"svn": 1}, {"svn": 1}
                ],
                "pcesvn": 1
            },
            "tcbDate": "2024-01-01T00:00:00Z",
            "tcbStatus": "UpToDate"
        }]
    });

    let tcb_info_json = serde_json::to_string(&tcb_info)?;

    // Sign TCB info with real signature
    let key_path = &format!("{}/tcb_signing.pkcs8.key", CERT_DIR);
    let key_pair = load_private_key(key_path)?;
    let tcb_signature = sign_data(&key_pair, tcb_info_json.as_bytes())?;

    // Create QE Identity matching the QE report we generate
    let qe_identity = json!({
        "id": "QE",
        "version": 2,
        "issueDate": "2024-01-01T00:00:00Z",
        "nextUpdate": "2099-12-31T23:59:59Z",
        "tcbEvaluationDataNumber": 17,
        "miscselect": "00000000",
        "miscselectMask": "FFFFFFFF",
        "attributes": "00000000000000000000000000000000",
        "attributesMask": "00000000000000000000000000000000",
        "mrsigner": "0000000000000000000000000000000000000000000000000000000000000000",
        "isvprodid": 0,
        "tcbLevels": [{
            "tcb": { "isvsvn": 0 },
            "tcbDate": "2024-01-01T00:00:00Z",
            "tcbStatus": "UpToDate",
            "advisoryIDs": []
        }]
    });
    let qe_identity_json = serde_json::to_string(&qe_identity)?;

    // Sign QE identity with real signature
    let qe_identity_signature = sign_data(&key_pair, qe_identity_json.as_bytes())?;

    Ok(json!({
        "pck_crl_issuer_chain": tcb_chain,
        "root_ca_crl": hex::encode(&root_crl),
        "pck_crl": hex::encode(&pck_crl),
        "tcb_info_issuer_chain": tcb_chain.clone(),
        "tcb_info": tcb_info_json,
        "tcb_info_signature": hex::encode(tcb_signature),
        "qe_identity_issuer_chain": tcb_chain,
        "qe_identity": qe_identity_json,
        "qe_identity_signature": hex::encode(qe_identity_signature)
    }))
}

fn create_sample_directory(name: &str) -> Result<PathBuf> {
    let dir = Path::new(SAMPLES_DIR).join(name);
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn write_sample(sample: &TestSample) -> Result<()> {
    let dir = create_sample_directory(&sample.name)?;

    // Generate and write quote.bin
    let quote_data = (sample.quote_generator)()?;
    fs::write(dir.join("quote.bin"), &quote_data)?;

    // Generate and write collateral.json
    let mut collateral = generate_base_collateral()?;
    if let Some(modifier) = &sample.collateral_modifier {
        modifier(&mut collateral)?;
    }
    fs::write(
        dir.join("collateral.json"),
        serde_json::to_string_pretty(&collateral)?,
    )?;

    // Write expected.json
    let expected = json!({
        "should_succeed": sample.should_succeed,
        "description": sample.description,
        "expected_error": sample.expected_error.as_deref().unwrap_or("")
    });
    fs::write(
        dir.join("expected.json"),
        serde_json::to_string_pretty(&expected)?,
    )?;

    let status = if sample.should_succeed { "✓" } else { "✗" };
    println!("  {} {}: {}", status, sample.name, sample.description);

    Ok(())
}

fn main() -> Result<()> {
    println!("=== Generating Comprehensive Test Samples ===\n");

    // Create samples directory
    fs::create_dir_all(SAMPLES_DIR)?;

    // Check if certificates exist
    if !Path::new(CERT_DIR).exists() {
        println!("Error: Test certificates not found at {}", CERT_DIR);
        println!("Please run: ./tests/generate_test_certs.sh");
        std::process::exit(1);
    }

    let mut samples = vec![];

    // Category 1: Valid quotes
    println!("Category 1: Valid quotes");
    samples.push(TestSample {
        name: "valid_sgx_v3".to_string(),
        description: "Valid SGX quote v3".to_string(),
        should_succeed: true,
        expected_error: None,
        quote_generator: Box::new(|| generate_base_quote(3, 2, false)),
        collateral_modifier: None,
    });

    samples.push(TestSample {
        name: "valid_sgx_v4".to_string(),
        description: "Valid SGX quote v4".to_string(),
        should_succeed: true,
        expected_error: None,
        quote_generator: Box::new(|| generate_base_quote(4, 2, false)),
        collateral_modifier: None,
    });

    samples.push(TestSample {
        name: "valid_tdx_v4".to_string(),
        description: "Valid TDX quote v4".to_string(),
        should_succeed: true,
        expected_error: None,
        quote_generator: Box::new(generate_tdx_quote_v4),
        collateral_modifier: Some(Box::new(|collateral| {
            // TDX requires TCB info version 3 with id="TDX" and tdxtcbcomponents in main tcbLevels
            if let Some(tcb_str) = collateral["tcb_info"].as_str() {
                if let Ok(mut tcb) = serde_json::from_str::<serde_json::Value>(tcb_str) {
                    tcb["version"] = json!(3);
                    tcb["id"] = json!("TDX");

                    // Add tdxtcbcomponents to the main TCB levels
                    if let Some(tcb_levels) = tcb["tcbLevels"].as_array_mut() {
                        for level in tcb_levels.iter_mut() {
                            if let Some(tcb_obj) = level["tcb"].as_object_mut() {
                                tcb_obj.insert(
                                    "tdxtcbcomponents".to_string(),
                                    json!([
                                        {"svn": 1}, {"svn": 1}, {"svn": 1}, {"svn": 1},
                                        {"svn": 1}, {"svn": 1}, {"svn": 1}, {"svn": 1},
                                        {"svn": 1}, {"svn": 1}, {"svn": 1}, {"svn": 1},
                                        {"svn": 1}, {"svn": 1}, {"svn": 1}, {"svn": 1}
                                    ]),
                                );
                            }
                        }
                    }

                    let new_tcb_info = serde_json::to_string(&tcb)?;

                    // Re-sign the modified TCB info
                    let key_path = &format!("{}/tcb_signing.pkcs8.key", CERT_DIR);
                    let key_pair = load_private_key(key_path)?;
                    let tcb_signature = sign_data(&key_pair, new_tcb_info.as_bytes())?;

                    collateral["tcb_info"] = json!(new_tcb_info);
                    collateral["tcb_info_signature"] = json!(hex::encode(tcb_signature));
                }
            }
            Ok(())
        })),
    });

    samples.push(TestSample {
        name: "valid_sgx_v5".to_string(),
        description: "Valid SGX quote v5 (uses v4 auth data)".to_string(),
        should_succeed: true,
        expected_error: None,
        quote_generator: Box::new(generate_sgx_v5_quote),
        collateral_modifier: None,
    });

    samples.push(TestSample {
        name: "invalid_quote_v5".to_string(),
        description: "Invalid SGX quote v5 format (v5 header with v3 auth data)".to_string(),
        should_succeed: false,
        // Quote v5 with v3 auth data causes auth data version mismatch
        expected_error: Some("Verification failed".to_string()),
        quote_generator: Box::new(|| generate_base_quote(5, 2, false)),
        collateral_modifier: None,
    });

    // Category 1b: TDX error samples
    println!("\nCategory 1b: TDX error samples");

    samples.push(TestSample {
        name: "tdx_missing_components".to_string(),
        description: "TDX quote with missing tdxtcbcomponents in TCB info".to_string(),
        should_succeed: false,
        expected_error: Some("No TDX components in the TCB info".to_string()),
        quote_generator: Box::new(generate_tdx_quote_v4),
        collateral_modifier: Some(Box::new(|collateral| {
            // TDX TCB info without tdxtcbcomponents
            if let Some(tcb_str) = collateral["tcb_info"].as_str() {
                if let Ok(mut tcb) = serde_json::from_str::<serde_json::Value>(tcb_str) {
                    tcb["version"] = json!(3);
                    tcb["id"] = json!("TDX");
                    // Don't add tdxtcbcomponents - this will cause the error
                    let new_tcb_info = serde_json::to_string(&tcb)?;

                    let key_path = &format!("{}/tcb_signing.pkcs8.key", CERT_DIR);
                    let key_pair = load_private_key(key_path)?;
                    let tcb_signature = sign_data(&key_pair, new_tcb_info.as_bytes())?;

                    collateral["tcb_info"] = json!(new_tcb_info);
                    collateral["tcb_info_signature"] = json!(hex::encode(tcb_signature));
                }
            }
            Ok(())
        })),
    });

    samples.push(TestSample {
        name: "tdx_debug_enabled".to_string(),
        description: "TDX quote with debug mode enabled".to_string(),
        should_succeed: false,
        expected_error: Some("Debug mode is enabled".to_string()),
        quote_generator: Box::new(|| {
            // Generate TDX quote with debug bit set
            let header = create_sgx_header(4, 2, 0x00000081);
            let mut report = create_tdx_report();
            // Set debug bit (bit 0 of tud field, which is byte 0)
            report.td_attributes[0] |= 0x01; // Debug enabled

            // Rest is same as generate_tdx_quote_v4...
            let pck_cert = fs::read_to_string(format!("{}/pck.pem", CERT_DIR))?;
            let root_cert = fs::read_to_string(format!("{}/root_ca.pem", CERT_DIR))?;
            let pck_chain_for_quote = format!("{}{}", pck_cert, root_cert);

            let pck_key_path = &format!("{}/pck.pkcs8.key", CERT_DIR);
            let pck_key_pair = load_private_key(pck_key_path)?;

            let rng = SystemRandom::new();
            let attestation_pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                &rng,
            )?;
            let attestation_key_pair = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                attestation_pkcs8.as_ref(),
                &rng,
            )?;

            let attestation_public_key = attestation_key_pair.public_key().as_ref();
            let mut ecdsa_attestation_key = [0u8; 64];
            ecdsa_attestation_key.copy_from_slice(&attestation_public_key[1..65]);

            let qe_auth_data = vec![0u8; 32];
            let mut qe_hash_data = [0u8; 96];
            qe_hash_data[0..64].copy_from_slice(&ecdsa_attestation_key);
            qe_hash_data[64..].copy_from_slice(&qe_auth_data);
            let qe_hash = ring::digest::digest(&ring::digest::SHA256, &qe_hash_data);

            let mut qe_report_data = create_sgx_report(false);
            qe_report_data.report_data[0..32].copy_from_slice(qe_hash.as_ref());
            let qe_report_bytes = qe_report_data.encode();
            let mut qe_report = [0u8; 384];
            qe_report[..qe_report_bytes.len()].copy_from_slice(&qe_report_bytes);

            let qe_report_signature = sign_data(&pck_key_pair, &qe_report)?;

            let mut signed_data = header.encode();
            signed_data.extend_from_slice(&report.encode());
            let ecdsa_signature = sign_data(&attestation_key_pair, &signed_data)?;

            let qe_report_data = QEReportCertificationData {
                qe_report,
                qe_report_signature,
                qe_auth_data: Data::<u16>::new(qe_auth_data.clone()),
                certification_data: CertificationData {
                    cert_type: 5,
                    body: Data::<u32>::new(pck_chain_for_quote.into_bytes()),
                },
            };

            let auth_data = AuthData::V4(AuthDataV4 {
                ecdsa_signature,
                ecdsa_attestation_key,
                certification_data: CertificationData {
                    cert_type: 5,
                    body: Data::<u32>::new(vec![]),
                },
                qe_report_data,
            });

            let quote = Quote {
                header,
                report: Report::TD10(report),
                auth_data,
            };

            Ok(quote.encode())
        }),
        collateral_modifier: Some(Box::new(|collateral| {
            // Add TDX TCB info
            if let Some(tcb_str) = collateral["tcb_info"].as_str() {
                if let Ok(mut tcb) = serde_json::from_str::<serde_json::Value>(tcb_str) {
                    tcb["version"] = json!(3);
                    tcb["id"] = json!("TDX");
                    if let Some(tcb_levels) = tcb["tcbLevels"].as_array_mut() {
                        for level in tcb_levels.iter_mut() {
                            if let Some(tcb_obj) = level["tcb"].as_object_mut() {
                                tcb_obj.insert(
                                    "tdxtcbcomponents".to_string(),
                                    json!([
                                        {"svn": 1}, {"svn": 1}, {"svn": 1}, {"svn": 1},
                                        {"svn": 1}, {"svn": 1}, {"svn": 1}, {"svn": 1},
                                        {"svn": 1}, {"svn": 1}, {"svn": 1}, {"svn": 1},
                                        {"svn": 1}, {"svn": 1}, {"svn": 1}, {"svn": 1}
                                    ]),
                                );
                            }
                        }
                    }
                    let new_tcb_info = serde_json::to_string(&tcb)?;
                    let key_path = &format!("{}/tcb_signing.pkcs8.key", CERT_DIR);
                    let key_pair = load_private_key(key_path)?;
                    let tcb_signature = sign_data(&key_pair, new_tcb_info.as_bytes())?;
                    collateral["tcb_info"] = json!(new_tcb_info);
                    collateral["tcb_info_signature"] = json!(hex::encode(tcb_signature));
                }
            }
            Ok(())
        })),
    });

    samples.push(TestSample {
        name: "tdx_sept_ve_disabled".to_string(),
        description: "TDX quote without SEPT_VE_DISABLE bit".to_string(),
        should_succeed: false,
        expected_error: Some("SEPT_VE_DISABLE is not enabled".to_string()),
        quote_generator: Box::new(|| {
            let header = create_sgx_header(4, 2, 0x00000081);
            let mut report = create_tdx_report();
            // Clear SEPT_VE_DISABLE bit
            report.td_attributes[3] = 0x00;

            // Generate rest of quote (same as tdx_debug_enabled)
            let pck_cert = fs::read_to_string(format!("{}/pck.pem", CERT_DIR))?;
            let root_cert = fs::read_to_string(format!("{}/root_ca.pem", CERT_DIR))?;
            let pck_chain_for_quote = format!("{}{}", pck_cert, root_cert);
            let pck_key_path = &format!("{}/pck.pkcs8.key", CERT_DIR);
            let pck_key_pair = load_private_key(pck_key_path)?;
            let rng = SystemRandom::new();
            let attestation_pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                &rng,
            )?;
            let attestation_key_pair = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                attestation_pkcs8.as_ref(),
                &rng,
            )?;
            let attestation_public_key = attestation_key_pair.public_key().as_ref();
            let mut ecdsa_attestation_key = [0u8; 64];
            ecdsa_attestation_key.copy_from_slice(&attestation_public_key[1..65]);
            let qe_auth_data = vec![0u8; 32];
            let mut qe_hash_data = [0u8; 96];
            qe_hash_data[0..64].copy_from_slice(&ecdsa_attestation_key);
            qe_hash_data[64..].copy_from_slice(&qe_auth_data);
            let qe_hash = ring::digest::digest(&ring::digest::SHA256, &qe_hash_data);
            let mut qe_report_data = create_sgx_report(false);
            qe_report_data.report_data[0..32].copy_from_slice(qe_hash.as_ref());
            let qe_report_bytes = qe_report_data.encode();
            let mut qe_report = [0u8; 384];
            qe_report[..qe_report_bytes.len()].copy_from_slice(&qe_report_bytes);
            let qe_report_signature = sign_data(&pck_key_pair, &qe_report)?;
            let mut signed_data = header.encode();
            signed_data.extend_from_slice(&report.encode());
            let ecdsa_signature = sign_data(&attestation_key_pair, &signed_data)?;
            let qe_report_data = QEReportCertificationData {
                qe_report,
                qe_report_signature,
                qe_auth_data: Data::<u16>::new(qe_auth_data.clone()),
                certification_data: CertificationData {
                    cert_type: 5,
                    body: Data::<u32>::new(pck_chain_for_quote.into_bytes()),
                },
            };
            let auth_data = AuthData::V4(AuthDataV4 {
                ecdsa_signature,
                ecdsa_attestation_key,
                certification_data: CertificationData {
                    cert_type: 5,
                    body: Data::<u32>::new(vec![]),
                },
                qe_report_data,
            });
            let quote = Quote {
                header,
                report: Report::TD10(report),
                auth_data,
            };
            Ok(quote.encode())
        }),
        collateral_modifier: Some(Box::new(|collateral| {
            if let Some(tcb_str) = collateral["tcb_info"].as_str() {
                if let Ok(mut tcb) = serde_json::from_str::<serde_json::Value>(tcb_str) {
                    tcb["version"] = json!(3);
                    tcb["id"] = json!("TDX");
                    if let Some(tcb_levels) = tcb["tcbLevels"].as_array_mut() {
                        for level in tcb_levels.iter_mut() {
                            if let Some(tcb_obj) = level["tcb"].as_object_mut() {
                                tcb_obj.insert(
                                    "tdxtcbcomponents".to_string(),
                                    json!([
                                        {"svn": 1}, {"svn": 1}, {"svn": 1}, {"svn": 1},
                                        {"svn": 1}, {"svn": 1}, {"svn": 1}, {"svn": 1},
                                        {"svn": 1}, {"svn": 1}, {"svn": 1}, {"svn": 1},
                                        {"svn": 1}, {"svn": 1}, {"svn": 1}, {"svn": 1}
                                    ]),
                                );
                            }
                        }
                    }
                    let new_tcb_info = serde_json::to_string(&tcb)?;
                    let key_path = &format!("{}/tcb_signing.pkcs8.key", CERT_DIR);
                    let key_pair = load_private_key(key_path)?;
                    let tcb_signature = sign_data(&key_pair, new_tcb_info.as_bytes())?;
                    collateral["tcb_info"] = json!(new_tcb_info);
                    collateral["tcb_info_signature"] = json!(hex::encode(tcb_signature));
                }
            }
            Ok(())
        })),
    });

    samples.push(TestSample {
        name: "tdx_reserved_bits_set".to_string(),
        description: "TDX quote with reserved bits set in TD attributes".to_string(),
        should_succeed: false,
        expected_error: Some("Reserved bits in TD attributes are set".to_string()),
        quote_generator: Box::new(|| {
            let header = create_sgx_header(4, 2, 0x00000081);
            let mut report = create_tdx_report();
            // Set reserved bit 29 (byte 3, bit 5)
            report.td_attributes[3] |= 0x20; // Reserved bit 29

            let pck_cert = fs::read_to_string(format!("{}/pck.pem", CERT_DIR))?;
            let root_cert = fs::read_to_string(format!("{}/root_ca.pem", CERT_DIR))?;
            let pck_chain_for_quote = format!("{}{}", pck_cert, root_cert);
            let pck_key_path = &format!("{}/pck.pkcs8.key", CERT_DIR);
            let pck_key_pair = load_private_key(pck_key_path)?;
            let rng = SystemRandom::new();
            let attestation_pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                &rng,
            )?;
            let attestation_key_pair = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                attestation_pkcs8.as_ref(),
                &rng,
            )?;
            let attestation_public_key = attestation_key_pair.public_key().as_ref();
            let mut ecdsa_attestation_key = [0u8; 64];
            ecdsa_attestation_key.copy_from_slice(&attestation_public_key[1..65]);
            let qe_auth_data = vec![0u8; 32];
            let mut qe_hash_data = [0u8; 96];
            qe_hash_data[0..64].copy_from_slice(&ecdsa_attestation_key);
            qe_hash_data[64..].copy_from_slice(&qe_auth_data);
            let qe_hash = ring::digest::digest(&ring::digest::SHA256, &qe_hash_data);
            let mut qe_report_data = create_sgx_report(false);
            qe_report_data.report_data[0..32].copy_from_slice(qe_hash.as_ref());
            let qe_report_bytes = qe_report_data.encode();
            let mut qe_report = [0u8; 384];
            qe_report[..qe_report_bytes.len()].copy_from_slice(&qe_report_bytes);
            let qe_report_signature = sign_data(&pck_key_pair, &qe_report)?;
            let mut signed_data = header.encode();
            signed_data.extend_from_slice(&report.encode());
            let ecdsa_signature = sign_data(&attestation_key_pair, &signed_data)?;
            let qe_report_data = QEReportCertificationData {
                qe_report,
                qe_report_signature,
                qe_auth_data: Data::<u16>::new(qe_auth_data.clone()),
                certification_data: CertificationData {
                    cert_type: 5,
                    body: Data::<u32>::new(pck_chain_for_quote.into_bytes()),
                },
            };
            let auth_data = AuthData::V4(AuthDataV4 {
                ecdsa_signature,
                ecdsa_attestation_key,
                certification_data: CertificationData {
                    cert_type: 5,
                    body: Data::<u32>::new(vec![]),
                },
                qe_report_data,
            });
            let quote = Quote {
                header,
                report: Report::TD10(report),
                auth_data,
            };
            Ok(quote.encode())
        }),
        collateral_modifier: Some(Box::new(|collateral| {
            if let Some(tcb_str) = collateral["tcb_info"].as_str() {
                if let Ok(mut tcb) = serde_json::from_str::<serde_json::Value>(tcb_str) {
                    tcb["version"] = json!(3);
                    tcb["id"] = json!("TDX");
                    if let Some(tcb_levels) = tcb["tcbLevels"].as_array_mut() {
                        for level in tcb_levels.iter_mut() {
                            if let Some(tcb_obj) = level["tcb"].as_object_mut() {
                                tcb_obj.insert(
                                    "tdxtcbcomponents".to_string(),
                                    json!([
                                        {"svn": 1}, {"svn": 1}, {"svn": 1}, {"svn": 1},
                                        {"svn": 1}, {"svn": 1}, {"svn": 1}, {"svn": 1},
                                        {"svn": 1}, {"svn": 1}, {"svn": 1}, {"svn": 1},
                                        {"svn": 1}, {"svn": 1}, {"svn": 1}, {"svn": 1}
                                    ]),
                                );
                            }
                        }
                    }
                    let new_tcb_info = serde_json::to_string(&tcb)?;
                    let key_path = &format!("{}/tcb_signing.pkcs8.key", CERT_DIR);
                    let key_pair = load_private_key(key_path)?;
                    let tcb_signature = sign_data(&key_pair, new_tcb_info.as_bytes())?;
                    collateral["tcb_info"] = json!(new_tcb_info);
                    collateral["tcb_info_signature"] = json!(hex::encode(tcb_signature));
                }
            }
            Ok(())
        })),
    });

    samples.push(TestSample {
        name: "tdx_pks_enabled".to_string(),
        description: "TDX quote with PKS (Protection Keys) enabled".to_string(),
        should_succeed: true,
        expected_error: None,
        quote_generator: Box::new(|| {
            let header = create_sgx_header(4, 2, 0x00000081);
            let mut report = create_tdx_report();
            // Set PKS bit (bit 30, byte 3, bit 6)
            report.td_attributes[3] |= 0x40; // PKS enabled

            let pck_cert = fs::read_to_string(format!("{}/pck.pem", CERT_DIR))?;
            let root_cert = fs::read_to_string(format!("{}/root_ca.pem", CERT_DIR))?;
            let pck_chain_for_quote = format!("{}{}", pck_cert, root_cert);
            let pck_key_path = &format!("{}/pck.pkcs8.key", CERT_DIR);
            let pck_key_pair = load_private_key(pck_key_path)?;
            let rng = SystemRandom::new();
            let attestation_pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                &rng,
            )?;
            let attestation_key_pair = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                attestation_pkcs8.as_ref(),
                &rng,
            )?;
            let attestation_public_key = attestation_key_pair.public_key().as_ref();
            let mut ecdsa_attestation_key = [0u8; 64];
            ecdsa_attestation_key.copy_from_slice(&attestation_public_key[1..65]);
            let qe_auth_data = vec![0u8; 32];
            let mut qe_hash_data = [0u8; 96];
            qe_hash_data[0..64].copy_from_slice(&ecdsa_attestation_key);
            qe_hash_data[64..].copy_from_slice(&qe_auth_data);
            let qe_hash = ring::digest::digest(&ring::digest::SHA256, &qe_hash_data);
            let mut qe_report_data = create_sgx_report(false);
            qe_report_data.report_data[0..32].copy_from_slice(qe_hash.as_ref());
            let qe_report_bytes = qe_report_data.encode();
            let mut qe_report = [0u8; 384];
            qe_report[..qe_report_bytes.len()].copy_from_slice(&qe_report_bytes);
            let qe_report_signature = sign_data(&pck_key_pair, &qe_report)?;
            let mut signed_data = header.encode();
            signed_data.extend_from_slice(&report.encode());
            let ecdsa_signature = sign_data(&attestation_key_pair, &signed_data)?;
            let qe_report_data = QEReportCertificationData {
                qe_report,
                qe_report_signature,
                qe_auth_data: Data::<u16>::new(qe_auth_data.clone()),
                certification_data: CertificationData {
                    cert_type: 5,
                    body: Data::<u32>::new(pck_chain_for_quote.into_bytes()),
                },
            };
            let auth_data = AuthData::V4(AuthDataV4 {
                ecdsa_signature,
                ecdsa_attestation_key,
                certification_data: CertificationData {
                    cert_type: 5,
                    body: Data::<u32>::new(vec![]),
                },
                qe_report_data,
            });
            let quote = Quote {
                header,
                report: Report::TD10(report),
                auth_data,
            };
            Ok(quote.encode())
        }),
        collateral_modifier: Some(Box::new(|collateral| {
            if let Some(tcb_str) = collateral["tcb_info"].as_str() {
                if let Ok(mut tcb) = serde_json::from_str::<serde_json::Value>(tcb_str) {
                    tcb["version"] = json!(3);
                    tcb["id"] = json!("TDX");
                    if let Some(tcb_levels) = tcb["tcbLevels"].as_array_mut() {
                        for level in tcb_levels.iter_mut() {
                            if let Some(tcb_obj) = level["tcb"].as_object_mut() {
                                tcb_obj.insert(
                                    "tdxtcbcomponents".to_string(),
                                    json!([
                                        {"svn": 1}, {"svn": 1}, {"svn": 1}, {"svn": 1},
                                        {"svn": 1}, {"svn": 1}, {"svn": 1}, {"svn": 1},
                                        {"svn": 1}, {"svn": 1}, {"svn": 1}, {"svn": 1},
                                        {"svn": 1}, {"svn": 1}, {"svn": 1}, {"svn": 1}
                                    ]),
                                );
                            }
                        }
                    }
                    let new_tcb_info = serde_json::to_string(&tcb)?;
                    let key_path = &format!("{}/tcb_signing.pkcs8.key", CERT_DIR);
                    let key_pair = load_private_key(key_path)?;
                    let tcb_signature = sign_data(&key_pair, new_tcb_info.as_bytes())?;
                    collateral["tcb_info"] = json!(new_tcb_info);
                    collateral["tcb_info_signature"] = json!(hex::encode(tcb_signature));
                }
            }
            Ok(())
        })),
    });

    samples.push(TestSample {
        name: "tdx_kl_enabled".to_string(),
        description: "TDX quote with KL (Key Locker) enabled".to_string(),
        should_succeed: true,
        expected_error: None,
        quote_generator: Box::new(|| {
            let header = create_sgx_header(4, 2, 0x00000081);
            let mut report = create_tdx_report();
            // Set KL bit (bit 31, byte 3, bit 7)
            report.td_attributes[3] |= 0x80; // KL enabled

            let pck_cert = fs::read_to_string(format!("{}/pck.pem", CERT_DIR))?;
            let root_cert = fs::read_to_string(format!("{}/root_ca.pem", CERT_DIR))?;
            let pck_chain_for_quote = format!("{}{}", pck_cert, root_cert);
            let pck_key_path = &format!("{}/pck.pkcs8.key", CERT_DIR);
            let pck_key_pair = load_private_key(pck_key_path)?;
            let rng = SystemRandom::new();
            let attestation_pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                &rng,
            )?;
            let attestation_key_pair = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                attestation_pkcs8.as_ref(),
                &rng,
            )?;
            let attestation_public_key = attestation_key_pair.public_key().as_ref();
            let mut ecdsa_attestation_key = [0u8; 64];
            ecdsa_attestation_key.copy_from_slice(&attestation_public_key[1..65]);
            let qe_auth_data = vec![0u8; 32];
            let mut qe_hash_data = [0u8; 96];
            qe_hash_data[0..64].copy_from_slice(&ecdsa_attestation_key);
            qe_hash_data[64..].copy_from_slice(&qe_auth_data);
            let qe_hash = ring::digest::digest(&ring::digest::SHA256, &qe_hash_data);
            let mut qe_report_data = create_sgx_report(false);
            qe_report_data.report_data[0..32].copy_from_slice(qe_hash.as_ref());
            let qe_report_bytes = qe_report_data.encode();
            let mut qe_report = [0u8; 384];
            qe_report[..qe_report_bytes.len()].copy_from_slice(&qe_report_bytes);
            let qe_report_signature = sign_data(&pck_key_pair, &qe_report)?;
            let mut signed_data = header.encode();
            signed_data.extend_from_slice(&report.encode());
            let ecdsa_signature = sign_data(&attestation_key_pair, &signed_data)?;
            let qe_report_data = QEReportCertificationData {
                qe_report,
                qe_report_signature,
                qe_auth_data: Data::<u16>::new(qe_auth_data.clone()),
                certification_data: CertificationData {
                    cert_type: 5,
                    body: Data::<u32>::new(pck_chain_for_quote.into_bytes()),
                },
            };
            let auth_data = AuthData::V4(AuthDataV4 {
                ecdsa_signature,
                ecdsa_attestation_key,
                certification_data: CertificationData {
                    cert_type: 5,
                    body: Data::<u32>::new(vec![]),
                },
                qe_report_data,
            });
            let quote = Quote {
                header,
                report: Report::TD10(report),
                auth_data,
            };
            Ok(quote.encode())
        }),
        collateral_modifier: Some(Box::new(|collateral| {
            if let Some(tcb_str) = collateral["tcb_info"].as_str() {
                if let Ok(mut tcb) = serde_json::from_str::<serde_json::Value>(tcb_str) {
                    tcb["version"] = json!(3);
                    tcb["id"] = json!("TDX");
                    if let Some(tcb_levels) = tcb["tcbLevels"].as_array_mut() {
                        for level in tcb_levels.iter_mut() {
                            if let Some(tcb_obj) = level["tcb"].as_object_mut() {
                                tcb_obj.insert(
                                    "tdxtcbcomponents".to_string(),
                                    json!([
                                        {"svn": 1}, {"svn": 1}, {"svn": 1}, {"svn": 1},
                                        {"svn": 1}, {"svn": 1}, {"svn": 1}, {"svn": 1},
                                        {"svn": 1}, {"svn": 1}, {"svn": 1}, {"svn": 1},
                                        {"svn": 1}, {"svn": 1}, {"svn": 1}, {"svn": 1}
                                    ]),
                                );
                            }
                        }
                    }
                    let new_tcb_info = serde_json::to_string(&tcb)?;
                    let key_path = &format!("{}/tcb_signing.pkcs8.key", CERT_DIR);
                    let key_pair = load_private_key(key_path)?;
                    let tcb_signature = sign_data(&key_pair, new_tcb_info.as_bytes())?;
                    collateral["tcb_info"] = json!(new_tcb_info);
                    collateral["tcb_info_signature"] = json!(hex::encode(tcb_signature));
                }
            }
            Ok(())
        })),
    });

    // Category 2: Debug mode
    println!("\nCategory 2: Debug mode");
    samples.push(TestSample {
        name: "debug_sgx_v3".to_string(),
        description: "SGX v3 in debug mode".to_string(),
        should_succeed: false,
        expected_error: Some("Debug mode is enabled".to_string()),
        quote_generator: Box::new(|| generate_base_quote(3, 2, true)),
        collateral_modifier: None,
    });

    samples.push(TestSample {
        name: "debug_sgx_v4".to_string(),
        description: "SGX v4 in debug mode".to_string(),
        should_succeed: false,
        expected_error: Some("Debug mode is enabled".to_string()),
        quote_generator: Box::new(|| generate_base_quote(4, 2, true)),
        collateral_modifier: None,
    });

    // Category 3: Decode errors
    println!("\nCategory 3: Decode errors");
    samples.push(TestSample {
        name: "invalid_quote_format".to_string(),
        description: "Invalid quote binary format".to_string(),
        should_succeed: false,
        // Invalid binary data causes buffer underflow
        expected_error: Some("Failed to decode quote".to_string()),
        quote_generator: Box::new(generate_invalid_quote),
        collateral_modifier: None,
    });

    samples.push(TestSample {
        name: "truncated_quote".to_string(),
        description: "Truncated quote data".to_string(),
        should_succeed: false,
        // Truncated data causes buffer underflow
        expected_error: Some("Not enough data to fill buffer".to_string()),
        quote_generator: Box::new(generate_truncated_quote),
        collateral_modifier: None,
    });

    // Category 4: Version errors
    // Note: Unsupported versions fail at decode stage with root cause "Unsupported quote version"
    println!("\nCategory 4: Version errors");
    for version in [1, 2, 6, 255] {
        samples.push(TestSample {
            name: format!("unsupported_version_{}", version),
            description: format!("Unsupported quote version {}", version),
            should_succeed: false,
            // Use the root cause error message (from Caused by chain)
            expected_error: Some("Unsupported quote version".to_string()),
            quote_generator: Box::new(move || generate_base_quote(version, 2, false)),
            collateral_modifier: None,
        });
    }

    // Category 5: Key type errors
    println!("\nCategory 5: Key type errors");
    for key_type in [0, 1, 3, 255] {
        samples.push(TestSample {
            name: format!("unsupported_key_type_{}", key_type),
            description: format!("Unsupported key type {}", key_type),
            should_succeed: false,
            expected_error: Some("Unsupported DCAP attestation key type".to_string()),
            quote_generator: Box::new(move || generate_base_quote(3, key_type, false)),
            collateral_modifier: None,
        });
    }

    // Category 6: TCB errors
    println!("\nCategory 6: TCB errors");
    samples.push(TestSample {
        name: "tcb_expired".to_string(),
        description: "Expired TCB info".to_string(),
        should_succeed: false,
        expected_error: Some("TCBInfo expired".to_string()),
        quote_generator: Box::new(|| generate_base_quote(3, 2, false)),
        collateral_modifier: Some(Box::new(|collateral| {
            let tcb_info = json!({
                "id": "SGX",
                "version": 3,
                "issueDate": "2020-01-01T00:00:00Z",
                "nextUpdate": "2020-12-31T23:59:59Z", // Expired
                "fmspc": "00906EA10000",
                "pceId": "0000",
                "tcbType": 0,
                "tcbEvaluationDataNumber": 12,
                "tcbLevels": []
            });
            collateral["tcb_info"] = json!(serde_json::to_string(&tcb_info)?);
            Ok(())
        })),
    });

    samples.push(TestSample {
        name: "invalid_tcb_json".to_string(),
        description: "Invalid TCB JSON format".to_string(),
        should_succeed: false,
        expected_error: Some("Failed to decode TcbInfo".to_string()),
        quote_generator: Box::new(|| generate_base_quote(3, 2, false)),
        collateral_modifier: Some(Box::new(|collateral| {
            collateral["tcb_info"] = json!("INVALID JSON");
            Ok(())
        })),
    });

    // Category 7: Certificate chain errors
    println!("\nCategory 7: Certificate chain errors");
    samples.push(TestSample {
        name: "short_tcb_chain".to_string(),
        description: "TCB certificate chain too short".to_string(),
        should_succeed: false,
        expected_error: Some("Certificate chain is too short for TCB Info".to_string()),
        quote_generator: Box::new(|| generate_base_quote(3, 2, false)),
        collateral_modifier: Some(Box::new(|collateral| {
            collateral["tcb_info_issuer_chain"] = json!("\n");
            Ok(())
        })),
    });

    samples.push(TestSample {
        name: "invalid_cert_format".to_string(),
        description: "Invalid certificate format in TCB chain".to_string(),
        should_succeed: false,
        expected_error: Some("Certificate chain is too short for TCB Info".to_string()),
        quote_generator: Box::new(|| generate_base_quote(3, 2, false)),
        collateral_modifier: Some(Box::new(|collateral| {
            // Use malformed certificate data (missing proper PEM headers/footers)
            let invalid_cert = "INVALID_CERTIFICATE_DATA_NOT_PROPERLY_FORMATTED";
            collateral["tcb_info_issuer_chain"] = json!(invalid_cert);
            Ok(())
        })),
    });

    // Category 8: Signature errors
    println!("\nCategory 8: Signature errors");
    samples.push(TestSample {
        name: "invalid_tcb_signature".to_string(),
        description: "Invalid TCB info signature".to_string(),
        should_succeed: false,
        expected_error: Some("Signature is invalid for tcb_info".to_string()),
        quote_generator: Box::new(|| generate_base_quote(3, 2, false)),
        collateral_modifier: Some(Box::new(|collateral| {
            collateral["tcb_info_signature"] = json!("00".repeat(64));
            Ok(())
        })),
    });

    // Category 9: FMSPC errors
    println!("\nCategory 9: FMSPC errors");
    samples.push(TestSample {
        name: "fmspc_mismatch".to_string(),
        description: "FMSPC mismatch between quote and TCB".to_string(),
        should_succeed: false,
        expected_error: Some("Fmspc mismatch".to_string()),
        quote_generator: Box::new(|| generate_base_quote(3, 2, false)),
        collateral_modifier: Some(Box::new(|collateral| {
            if let Some(tcb_str) = collateral["tcb_info"].as_str() {
                if let Ok(mut tcb) = serde_json::from_str::<serde_json::Value>(tcb_str) {
                    tcb["fmspc"] = json!("FFFFFFFFFFFF");
                    let new_tcb_info = serde_json::to_string(&tcb)?;

                    // Re-sign the modified TCB info
                    let key_path = &format!("{}/tcb_signing.pkcs8.key", CERT_DIR);
                    let key_pair = load_private_key(key_path)?;
                    let tcb_signature = sign_data(&key_pair, new_tcb_info.as_bytes())?;

                    collateral["tcb_info"] = json!(new_tcb_info);
                    collateral["tcb_info_signature"] = json!(hex::encode(tcb_signature));
                }
            }
            Ok(())
        })),
    });

    // Category 10: QE report errors
    println!("\nCategory 10: QE report errors");
    samples.push(TestSample {
        name: "qe_report_hash_mismatch".to_string(),
        description: "QE report hash mismatch".to_string(),
        should_succeed: false,
        expected_error: Some("QE report hash mismatch".to_string()),
        quote_generator: Box::new(|| {
            // Generate quote with wrong QE report hash
            let header = create_sgx_header(3, 2, 0);
            let report = create_sgx_report(false);

            let pck_cert = fs::read_to_string(format!("{}/pck.pem", CERT_DIR))?;
            let root_cert = fs::read_to_string(format!("{}/root_ca.pem", CERT_DIR))?;
            let pck_chain_for_quote = format!("{}{}", pck_cert, root_cert);

            let pck_key_path = &format!("{}/pck.pkcs8.key", CERT_DIR);
            let pck_key_pair = load_private_key(pck_key_path)?;

            let rng = SystemRandom::new();
            let attestation_pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                &rng,
            )?;
            let attestation_key_pair = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                attestation_pkcs8.as_ref(),
                &rng,
            )?;

            let attestation_public_key = attestation_key_pair.public_key().as_ref();
            let mut ecdsa_attestation_key = [0u8; 64];
            ecdsa_attestation_key.copy_from_slice(&attestation_public_key[1..65]);

            let qe_auth_data = vec![0u8; 32];

            // Create QE report with WRONG hash (use zeros instead of correct hash)
            let qe_report_data = create_sgx_report(false);
            // Don't set the correct hash - leave it as zeros
            let qe_report_bytes = qe_report_data.encode();
            let mut qe_report = [0u8; 384];
            qe_report[..qe_report_bytes.len()].copy_from_slice(&qe_report_bytes);

            let qe_report_signature = sign_data(&pck_key_pair, &qe_report)?;

            let certification_data = CertificationData {
                cert_type: 5,
                body: Data::<u32>::new(pck_chain_for_quote.into_bytes()),
            };

            let mut signed_data = header.encode();
            signed_data.extend_from_slice(&report.encode());
            let ecdsa_signature = sign_data(&attestation_key_pair, &signed_data)?;

            let auth_data = AuthData::V3(AuthDataV3 {
                ecdsa_signature,
                ecdsa_attestation_key,
                qe_report,
                qe_report_signature,
                qe_auth_data: Data::<u16>::new(qe_auth_data),
                certification_data,
            });

            let quote = Quote {
                header,
                report: Report::SgxEnclave(report),
                auth_data,
            };

            Ok(quote.encode())
        }),
        collateral_modifier: None,
    });

    samples.push(TestSample {
        name: "invalid_qe_report_signature".to_string(),
        description: "Invalid QE report signature".to_string(),
        should_succeed: false,
        expected_error: Some("Signature is invalid for qe_report in quote".to_string()),
        quote_generator: Box::new(|| {
            // Generate quote with invalid QE report signature (all zeros)
            let header = create_sgx_header(3, 2, 0);
            let report = create_sgx_report(false);

            let pck_cert = fs::read_to_string(format!("{}/pck.pem", CERT_DIR))?;
            let root_cert = fs::read_to_string(format!("{}/root_ca.pem", CERT_DIR))?;
            let pck_chain_for_quote = format!("{}{}", pck_cert, root_cert);

            let rng = SystemRandom::new();
            let attestation_pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                &rng,
            )?;
            let attestation_key_pair = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                attestation_pkcs8.as_ref(),
                &rng,
            )?;

            let attestation_public_key = attestation_key_pair.public_key().as_ref();
            let mut ecdsa_attestation_key = [0u8; 64];
            ecdsa_attestation_key.copy_from_slice(&attestation_public_key[1..65]);

            let qe_auth_data = vec![0u8; 32];

            let mut qe_hash_data = [0u8; 96];
            qe_hash_data[0..64].copy_from_slice(&ecdsa_attestation_key);
            qe_hash_data[64..].copy_from_slice(&qe_auth_data);
            let qe_hash = ring::digest::digest(&ring::digest::SHA256, &qe_hash_data);

            let mut qe_report_data = create_sgx_report(false);
            qe_report_data.report_data[0..32].copy_from_slice(qe_hash.as_ref());
            let qe_report_bytes = qe_report_data.encode();
            let mut qe_report = [0u8; 384];
            qe_report[..qe_report_bytes.len()].copy_from_slice(&qe_report_bytes);

            // Use INVALID signature (all zeros)
            let qe_report_signature = [0u8; 64];

            let certification_data = CertificationData {
                cert_type: 5,
                body: Data::<u32>::new(pck_chain_for_quote.into_bytes()),
            };

            let mut signed_data = header.encode();
            signed_data.extend_from_slice(&report.encode());
            let ecdsa_signature = sign_data(&attestation_key_pair, &signed_data)?;

            let auth_data = AuthData::V3(AuthDataV3 {
                ecdsa_signature,
                ecdsa_attestation_key,
                qe_report,
                qe_report_signature,
                qe_auth_data: Data::<u16>::new(qe_auth_data),
                certification_data,
            });

            let quote = Quote {
                header,
                report: Report::SgxEnclave(report),
                auth_data,
            };

            Ok(quote.encode())
        }),
        collateral_modifier: None,
    });

    samples.push(TestSample {
        name: "invalid_quote_signature".to_string(),
        description: "Invalid ISV enclave report signature".to_string(),
        should_succeed: false,
        expected_error: Some("ISV enclave report signature is invalid".to_string()),
        quote_generator: Box::new(|| {
            // Generate quote with invalid quote signature (all zeros)
            let header = create_sgx_header(3, 2, 0);
            let report = create_sgx_report(false);

            let pck_cert = fs::read_to_string(format!("{}/pck.pem", CERT_DIR))?;
            let root_cert = fs::read_to_string(format!("{}/root_ca.pem", CERT_DIR))?;
            let pck_chain_for_quote = format!("{}{}", pck_cert, root_cert);

            let pck_key_path = &format!("{}/pck.pkcs8.key", CERT_DIR);
            let pck_key_pair = load_private_key(pck_key_path)?;

            let rng = SystemRandom::new();
            let attestation_pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                &rng,
            )?;
            let attestation_key_pair = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                attestation_pkcs8.as_ref(),
                &rng,
            )?;

            let attestation_public_key = attestation_key_pair.public_key().as_ref();
            let mut ecdsa_attestation_key = [0u8; 64];
            ecdsa_attestation_key.copy_from_slice(&attestation_public_key[1..65]);

            let qe_auth_data = vec![0u8; 32];

            let mut qe_hash_data = [0u8; 96];
            qe_hash_data[0..64].copy_from_slice(&ecdsa_attestation_key);
            qe_hash_data[64..].copy_from_slice(&qe_auth_data);
            let qe_hash = ring::digest::digest(&ring::digest::SHA256, &qe_hash_data);

            let mut qe_report_data = create_sgx_report(false);
            qe_report_data.report_data[0..32].copy_from_slice(qe_hash.as_ref());
            let qe_report_bytes = qe_report_data.encode();
            let mut qe_report = [0u8; 384];
            qe_report[..qe_report_bytes.len()].copy_from_slice(&qe_report_bytes);

            let qe_report_signature = sign_data(&pck_key_pair, &qe_report)?;

            // Use INVALID quote signature (all zeros)
            let ecdsa_signature = [0u8; 64];

            let certification_data = CertificationData {
                cert_type: 5,
                body: Data::<u32>::new(pck_chain_for_quote.into_bytes()),
            };

            let auth_data = AuthData::V3(AuthDataV3 {
                ecdsa_signature,
                ecdsa_attestation_key,
                qe_report,
                qe_report_signature,
                qe_auth_data: Data::<u16>::new(qe_auth_data),
                certification_data,
            });

            let quote = Quote {
                header,
                report: Report::SgxEnclave(report),
                auth_data,
            };

            Ok(quote.encode())
        }),
        collateral_modifier: None,
    });

    // Category 11: QE Identity errors
    println!("\nCategory 11: QE Identity errors");

    samples.push(TestSample {
        name: "qe_identity_expired".to_string(),
        description: "Expired QE Identity".to_string(),
        should_succeed: false,
        expected_error: Some("QE Identity expired".to_string()),
        quote_generator: Box::new(|| generate_base_quote(3, 2, false)),
        collateral_modifier: Some(Box::new(|collateral| {
            // Create QE Identity with expired nextUpdate
            let qe_identity = json!({
                "id": "QE",
                "version": 2,
                "issueDate": "2020-01-01T00:00:00Z",
                "nextUpdate": "2020-01-02T00:00:00Z",  // Far in the past
                "tcbEvaluationDataNumber": 17,
                "miscselect": "00000000",
                "miscselectMask": "FFFFFFFF",
                "attributes": "00000000000000000000000000000000",
                "attributesMask": "00000000000000000000000000000000",
                "mrsigner": "0000000000000000000000000000000000000000000000000000000000000000",
                "isvprodid": 0,
                "tcbLevels": [{
                    "tcb": { "isvsvn": 0 },
                    "tcbDate": "2020-01-01T00:00:00Z",
                    "tcbStatus": "UpToDate",
                    "advisoryIDs": []
                }]
            });
            let qe_identity_json = serde_json::to_string(&qe_identity)?;

            // Sign with valid key
            let key_path = &format!("{}/tcb_signing.pkcs8.key", CERT_DIR);
            let key_pair = load_private_key(key_path)?;
            let qe_identity_signature = sign_data(&key_pair, qe_identity_json.as_bytes())?;

            collateral["qe_identity"] = json!(qe_identity_json);
            collateral["qe_identity_signature"] = json!(hex::encode(qe_identity_signature));
            Ok(())
        })),
    });

    samples.push(TestSample {
        name: "invalid_qe_identity_json".to_string(),
        description: "Invalid QE Identity JSON format".to_string(),
        should_succeed: false,
        expected_error: Some("Failed to decode QeIdentity".to_string()),
        quote_generator: Box::new(|| generate_base_quote(3, 2, false)),
        collateral_modifier: Some(Box::new(|collateral| {
            collateral["qe_identity"] = json!("not valid json {{{");
            Ok(())
        })),
    });

    samples.push(TestSample {
        name: "short_qe_identity_chain".to_string(),
        description: "QE Identity certificate chain too short".to_string(),
        should_succeed: false,
        expected_error: Some("Certificate chain is too short for QE Identity".to_string()),
        quote_generator: Box::new(|| generate_base_quote(3, 2, false)),
        collateral_modifier: Some(Box::new(|collateral| {
            collateral["qe_identity_issuer_chain"] = json!("\n");
            Ok(())
        })),
    });

    samples.push(TestSample {
        name: "invalid_qe_identity_signature".to_string(),
        description: "Invalid QE Identity signature".to_string(),
        should_succeed: false,
        expected_error: Some("Signature is invalid for qe_identity".to_string()),
        quote_generator: Box::new(|| generate_base_quote(3, 2, false)),
        collateral_modifier: Some(Box::new(|collateral| {
            collateral["qe_identity_signature"] = json!("00".repeat(64));
            Ok(())
        })),
    });

    samples.push(TestSample {
        name: "qe_mrsigner_mismatch".to_string(),
        description: "QE MRSIGNER mismatch".to_string(),
        should_succeed: false,
        expected_error: Some("QE MRSIGNER mismatch".to_string()),
        quote_generator: Box::new(|| generate_base_quote(3, 2, false)),
        collateral_modifier: Some(Box::new(|collateral| {
            // Create QE Identity with different MRSIGNER
            let qe_identity = json!({
                "id": "QE",
                "version": 2,
                "issueDate": "2024-01-01T00:00:00Z",
                "nextUpdate": "2099-12-31T23:59:59Z",
                "tcbEvaluationDataNumber": 17,
                "miscselect": "00000000",
                "miscselectMask": "FFFFFFFF",
                "attributes": "00000000000000000000000000000000",
                "attributesMask": "00000000000000000000000000000000",
                "mrsigner": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",  // Wrong MRSIGNER
                "isvprodid": 0,
                "tcbLevels": [{
                    "tcb": { "isvsvn": 0 },
                    "tcbDate": "2024-01-01T00:00:00Z",
                    "tcbStatus": "UpToDate",
                    "advisoryIDs": []
                }]
            });
            let qe_identity_json = serde_json::to_string(&qe_identity)?;

            let key_path = &format!("{}/tcb_signing.pkcs8.key", CERT_DIR);
            let key_pair = load_private_key(key_path)?;
            let qe_identity_signature = sign_data(&key_pair, qe_identity_json.as_bytes())?;

            collateral["qe_identity"] = json!(qe_identity_json);
            collateral["qe_identity_signature"] = json!(hex::encode(qe_identity_signature));
            Ok(())
        })),
    });

    samples.push(TestSample {
        name: "qe_isvprodid_mismatch".to_string(),
        description: "QE ISVPRODID mismatch".to_string(),
        should_succeed: false,
        expected_error: Some("QE ISVPRODID mismatch".to_string()),
        quote_generator: Box::new(|| generate_base_quote(3, 2, false)),
        collateral_modifier: Some(Box::new(|collateral| {
            // Create QE Identity with different ISVPRODID
            let qe_identity = json!({
                "id": "QE",
                "version": 2,
                "issueDate": "2024-01-01T00:00:00Z",
                "nextUpdate": "2099-12-31T23:59:59Z",
                "tcbEvaluationDataNumber": 17,
                "miscselect": "00000000",
                "miscselectMask": "FFFFFFFF",
                "attributes": "00000000000000000000000000000000",
                "attributesMask": "00000000000000000000000000000000",
                "mrsigner": "0000000000000000000000000000000000000000000000000000000000000000",
                "isvprodid": 999,  // Wrong ISVPRODID
                "tcbLevels": [{
                    "tcb": { "isvsvn": 0 },
                    "tcbDate": "2024-01-01T00:00:00Z",
                    "tcbStatus": "UpToDate",
                    "advisoryIDs": []
                }]
            });
            let qe_identity_json = serde_json::to_string(&qe_identity)?;

            let key_path = &format!("{}/tcb_signing.pkcs8.key", CERT_DIR);
            let key_pair = load_private_key(key_path)?;
            let qe_identity_signature = sign_data(&key_pair, qe_identity_json.as_bytes())?;

            collateral["qe_identity"] = json!(qe_identity_json);
            collateral["qe_identity_signature"] = json!(hex::encode(qe_identity_signature));
            Ok(())
        })),
    });

    samples.push(TestSample {
        name: "qe_miscselect_mismatch".to_string(),
        description: "QE MISCSELECT mismatch".to_string(),
        should_succeed: false,
        expected_error: Some("QE MISCSELECT mismatch".to_string()),
        quote_generator: Box::new(|| generate_base_quote(3, 2, false)),
        collateral_modifier: Some(Box::new(|collateral| {
            // Create QE Identity with different MISCSELECT (with full mask, so it must match exactly)
            let qe_identity = json!({
                "id": "QE",
                "version": 2,
                "issueDate": "2024-01-01T00:00:00Z",
                "nextUpdate": "2099-12-31T23:59:59Z",
                "tcbEvaluationDataNumber": 17,
                "miscselect": "FFFFFFFF",  // Wrong MISCSELECT
                "miscselectMask": "FFFFFFFF",  // Full mask
                "attributes": "00000000000000000000000000000000",
                "attributesMask": "00000000000000000000000000000000",
                "mrsigner": "0000000000000000000000000000000000000000000000000000000000000000",
                "isvprodid": 0,
                "tcbLevels": [{
                    "tcb": { "isvsvn": 0 },
                    "tcbDate": "2024-01-01T00:00:00Z",
                    "tcbStatus": "UpToDate",
                    "advisoryIDs": []
                }]
            });
            let qe_identity_json = serde_json::to_string(&qe_identity)?;

            let key_path = &format!("{}/tcb_signing.pkcs8.key", CERT_DIR);
            let key_pair = load_private_key(key_path)?;
            let qe_identity_signature = sign_data(&key_pair, qe_identity_json.as_bytes())?;

            collateral["qe_identity"] = json!(qe_identity_json);
            collateral["qe_identity_signature"] = json!(hex::encode(qe_identity_signature));
            Ok(())
        })),
    });

    samples.push(TestSample {
        name: "qe_attributes_mismatch".to_string(),
        description: "QE ATTRIBUTES mismatch".to_string(),
        should_succeed: false,
        expected_error: Some("QE ATTRIBUTES mismatch".to_string()),
        quote_generator: Box::new(|| generate_base_quote(3, 2, false)),
        collateral_modifier: Some(Box::new(|collateral| {
            // Create QE Identity with different ATTRIBUTES (with full mask, so it must match exactly)
            let qe_identity = json!({
                "id": "QE",
                "version": 2,
                "issueDate": "2024-01-01T00:00:00Z",
                "nextUpdate": "2099-12-31T23:59:59Z",
                "tcbEvaluationDataNumber": 17,
                "miscselect": "00000000",
                "miscselectMask": "FFFFFFFF",
                "attributes": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",  // Wrong ATTRIBUTES
                "attributesMask": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",  // Full mask
                "mrsigner": "0000000000000000000000000000000000000000000000000000000000000000",
                "isvprodid": 0,
                "tcbLevels": [{
                    "tcb": { "isvsvn": 0 },
                    "tcbDate": "2024-01-01T00:00:00Z",
                    "tcbStatus": "UpToDate",
                    "advisoryIDs": []
                }]
            });
            let qe_identity_json = serde_json::to_string(&qe_identity)?;

            let key_path = &format!("{}/tcb_signing.pkcs8.key", CERT_DIR);
            let key_pair = load_private_key(key_path)?;
            let qe_identity_signature = sign_data(&key_pair, qe_identity_json.as_bytes())?;

            collateral["qe_identity"] = json!(qe_identity_json);
            collateral["qe_identity_signature"] = json!(hex::encode(qe_identity_signature));
            Ok(())
        })),
    });

    // Category 12: Unknown TCB status
    println!("\nCategory 12: Unknown TCB status");

    samples.push(TestSample {
        name: "unknown_tcb_status".to_string(),
        description: "Quote with no matching TCB level (empty tcbLevels array)".to_string(),
        should_succeed: false,
        expected_error: Some("No matching TCB level found".to_string()),
        quote_generator: Box::new(|| generate_base_quote(3, 2, false)),
        collateral_modifier: Some(Box::new(|collateral| {
            // Use empty tcbLevels array - no matching level will be found
            if let Some(tcb_str) = collateral["tcb_info"].as_str() {
                if let Ok(mut tcb) = serde_json::from_str::<serde_json::Value>(tcb_str) {
                    tcb["tcbLevels"] = json!([]);  // Empty array
                    let new_tcb_info = serde_json::to_string(&tcb)?;

                    let key_path = &format!("{}/tcb_signing.pkcs8.key", CERT_DIR);
                    let key_pair = load_private_key(key_path)?;
                    let tcb_signature = sign_data(&key_pair, new_tcb_info.as_bytes())?;

                    collateral["tcb_info"] = json!(new_tcb_info);
                    collateral["tcb_info_signature"] = json!(hex::encode(tcb_signature));
                }
            }
            Ok(())
        })),
    });

    samples.push(TestSample {
        name: "revoked_platform_tcb".to_string(),
        description: "Quote with Revoked platform TCB status".to_string(),
        should_succeed: false,
        expected_error: Some("TCB status is invalid: Revoked".to_string()),
        quote_generator: Box::new(|| generate_base_quote(3, 2, false)),
        collateral_modifier: Some(Box::new(|collateral| {
            // Set platform TCB status to Revoked
            if let Some(tcb_str) = collateral["tcb_info"].as_str() {
                if let Ok(mut tcb) = serde_json::from_str::<serde_json::Value>(tcb_str) {
                    if let Some(levels) = tcb["tcbLevels"].as_array_mut() {
                        for level in levels {
                            level["tcbStatus"] = json!("Revoked");
                        }
                    }
                    let new_tcb_info = serde_json::to_string(&tcb)?;

                    let key_path = &format!("{}/tcb_signing.pkcs8.key", CERT_DIR);
                    let key_pair = load_private_key(key_path)?;
                    let tcb_signature = sign_data(&key_pair, new_tcb_info.as_bytes())?;

                    collateral["tcb_info"] = json!(new_tcb_info);
                    collateral["tcb_info_signature"] = json!(hex::encode(tcb_signature));
                }
            }
            Ok(())
        })),
    });

    samples.push(TestSample {
        name: "revoked_qe_tcb".to_string(),
        description: "Quote with Revoked QE TCB status".to_string(),
        should_succeed: false,
        expected_error: Some("TCB status is invalid: Revoked".to_string()),
        quote_generator: Box::new(|| generate_base_quote(3, 2, false)),
        collateral_modifier: Some(Box::new(|collateral| {
            // Set QE TCB status to Revoked
            if let Some(qe_str) = collateral["qe_identity"].as_str() {
                if let Ok(mut qe_identity) = serde_json::from_str::<serde_json::Value>(qe_str) {
                    if let Some(levels) = qe_identity["tcbLevels"].as_array_mut() {
                        for level in levels {
                            level["tcbStatus"] = json!("Revoked");
                        }
                    }
                    let new_qe_identity = serde_json::to_string(&qe_identity)?;

                    let key_path = &format!("{}/tcb_signing.pkcs8.key", CERT_DIR);
                    let key_pair = load_private_key(key_path)?;
                    let qe_signature = sign_data(&key_pair, new_qe_identity.as_bytes())?;

                    collateral["qe_identity"] = json!(new_qe_identity);
                    collateral["qe_identity_signature"] = json!(hex::encode(qe_signature));
                }
            }
            Ok(())
        })),
    });

    // Category 13: PCK certificate chain in collateral (cert_type 3 support)
    println!("\nCategory 13: PCK certificate chain in collateral");

    samples.push(TestSample {
        name: "cert_type_5_with_pck_chain".to_string(),
        description: "cert_type 5 quote with pck_certificate_chain in collateral".to_string(),
        should_succeed: true,
        expected_error: None,
        quote_generator: Box::new(|| generate_base_quote(3, 2, false)),
        collateral_modifier: Some(Box::new(|collateral| {
            // Add pck_certificate_chain to collateral
            let pck_cert = fs::read_to_string(format!("{}/pck.pem", CERT_DIR))?;
            let root_cert = fs::read_to_string(format!("{}/root_ca.pem", CERT_DIR))?;
            let pck_chain = format!("{}{}", pck_cert, root_cert);
            collateral["pck_certificate_chain"] = json!(pck_chain);
            Ok(())
        })),
    });

    samples.push(TestSample {
        name: "cert_type_3_with_pck_chain".to_string(),
        description: "cert_type 3 (encrypted PPID) quote with pck_certificate_chain in collateral - offline verification support".to_string(),
        should_succeed: true,  // Should succeed: collateral provides PCK cert for offline verification
        expected_error: None,
        quote_generator: Box::new(generate_cert_type_3_quote),
        collateral_modifier: Some(Box::new(|collateral| {
            // Add pck_certificate_chain to collateral (required for cert_type 3 offline verification)
            let pck_cert = fs::read_to_string(format!("{}/pck.pem", CERT_DIR))?;
            let root_cert = fs::read_to_string(format!("{}/root_ca.pem", CERT_DIR))?;
            let pck_chain = format!("{}{}", pck_cert, root_cert);
            collateral["pck_certificate_chain"] = json!(pck_chain);
            Ok(())
        })),
    });

    samples.push(TestSample {
        name: "cert_type_3_without_pck_chain".to_string(),
        description: "cert_type 3 quote without pck_certificate_chain (should fail)".to_string(),
        should_succeed: false,
        expected_error: Some("Unsupported DCAP PCK cert format".to_string()),
        quote_generator: Box::new(generate_cert_type_3_quote),
        collateral_modifier: None, // No pck_certificate_chain
    });

    // Write all samples
    println!("\n=== Writing samples to disk ===\n");
    let total = samples.len();
    for sample in samples {
        write_sample(&sample)?;
    }

    println!("\n=== Generation Complete ===");
    println!("Total samples generated: {}", total);
    println!("Location: {}", SAMPLES_DIR);

    // Generate summary
    let summary = json!({
        "total_samples": total,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "categories": [
            "Valid quotes (SGX + TDX)",
            "Debug mode",
            "Decode errors",
            "Version errors",
            "Key type errors",
            "TCB errors",
            "Certificate chain errors",
            "Signature errors",
            "FMSPC errors",
            "QE report errors",
            "QE Identity errors",
            "Unknown TCB status",
            "PCK certificate chain in collateral (cert_type 3 support)"
        ]
    });

    fs::write(
        Path::new(SAMPLES_DIR).join("summary.json"),
        serde_json::to_string_pretty(&summary)?,
    )?;

    println!("\nSummary saved to: {}/summary.json", SAMPLES_DIR);

    Ok(())
}
