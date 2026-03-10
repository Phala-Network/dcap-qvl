use super::*;
use serde_json::json;

use anyhow::{bail, Result};

/// Convert a unix timestamp (seconds) to an RFC3339 string.
/// Returns an empty string for timestamp 0 (matching Intel's behavior of omitting the field).
fn unix_to_rfc3339(secs: u64) -> String {
    chrono::DateTime::from_timestamp(secs as i64, 0)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default()
}

/// Convert `TcbStatus` to the JSON string array that Intel's Rego expects.
///
/// This matches Intel's `qv_result_tcb_status_map` in qve.cpp.
fn tcb_status_to_rego_array(status: TcbStatus) -> serde_json::Value {
    match status {
        TcbStatus::UpToDate => json!(["UpToDate"]),
        TcbStatus::SWHardeningNeeded => json!(["UpToDate", "SWHardeningNeeded"]),
        TcbStatus::ConfigurationNeeded => json!(["UpToDate", "ConfigurationNeeded"]),
        TcbStatus::ConfigurationAndSWHardeningNeeded => {
            json!(["UpToDate", "SWHardeningNeeded", "ConfigurationNeeded"])
        }
        TcbStatus::OutOfDate => json!(["OutOfDate"]),
        TcbStatus::OutOfDateConfigurationNeeded => {
            json!(["OutOfDate", "ConfigurationNeeded"])
        }
        TcbStatus::Revoked => json!(["Revoked"]),
    }
}

/// Full collateral time window, aggregated from 8 sources (matching Intel QVL):
/// TcbInfo, QeIdentity, Root CA CRL, PCK CRL, and 4 certificate chains.
///
/// `SimplePolicy` only needs `earliest_expiration_date` (computed separately
/// from 4 lightweight sources without certificate chain parsing).
pub(crate) struct CollateralTimeWindow {
    /// `min(issueDate / thisUpdate / notBefore)` across all 8 sources.
    /// Rego uses this as `collateral_earliest_issue_date` in measurements.
    pub earliest_issue_date: u64,
    /// `max(issueDate / thisUpdate / notBefore)` across all 8 sources.
    /// Rego uses this as `collateral_latest_issue_date` in measurements.
    pub latest_issue_date: u64,
    /// `min(nextUpdate / notAfter)` across all 8 sources (the "weakest link").
    /// Determines when the overall collateral expires. Rego uses this as
    /// `collateral_earliest_expiration_date`; also reused by `build_supplemental()`
    /// to avoid redundant parsing.
    pub earliest_expiration_date: u64,
}

/// Build common platform fields into a Rego measurement JSON map.
fn insert_platform_fields(
    m: &mut serde_json::Map<String, serde_json::Value>,
    data: &SupplementalData,
    tw: &CollateralTimeWindow,
) {
    // Time fields as RFC3339 strings
    let earliest_issue = unix_to_rfc3339(tw.earliest_issue_date);
    if !earliest_issue.is_empty() {
        m.insert("earliest_issue_date".into(), json!(earliest_issue));
    }
    let latest_issue = unix_to_rfc3339(tw.latest_issue_date);
    if !latest_issue.is_empty() {
        m.insert("latest_issue_date".into(), json!(latest_issue));
    }
    let earliest_exp = unix_to_rfc3339(tw.earliest_expiration_date);
    if !earliest_exp.is_empty() {
        m.insert("earliest_expiration_date".into(), json!(earliest_exp));
    }
    let tcb_date = unix_to_rfc3339(data.platform.tcb_date_tag);
    if !tcb_date.is_empty() {
        m.insert("tcb_level_date_tag".into(), json!(tcb_date));
    }

    m.insert("pck_crl_num".into(), json!(data.platform.pck_crl_num));
    m.insert("root_ca_crl_num".into(), json!(data.platform.root_ca_crl_num));
    m.insert("tcb_eval_num".into(), json!(data.tcb.eval_data_number));
    m.insert("sgx_type".into(), json!(data.platform.pck.sgx_type));

    if data.platform.pck.dynamic_platform != PckCertFlag::Undefined {
        m.insert(
            "is_dynamic_platform".into(),
            json!(data.platform.pck.dynamic_platform == PckCertFlag::True),
        );
    }
    if data.platform.pck.cached_keys != PckCertFlag::Undefined {
        m.insert(
            "cached_keys".into(),
            json!(data.platform.pck.cached_keys == PckCertFlag::True),
        );
    }
    if data.platform.pck.smt_enabled != PckCertFlag::Undefined {
        m.insert(
            "smt_enabled".into(),
            json!(data.platform.pck.smt_enabled == PckCertFlag::True),
        );
    }

    if let Some(ref provider_id) = data.platform.pck.platform_provider_id {
        m.insert("platform_provider_id".into(), json!(provider_id));
    }

    m.insert("fmspc".into(), json!(hex::encode_upper(data.platform.pck.fmspc)));
    m.insert(
        "root_key_id".into(),
        json!(hex::encode_upper(data.platform.root_key_id)),
    );
}

/// Build merged Rego measurement (single-measurement path).
pub(crate) fn build_merged_measurement(
    data: &SupplementalData,
    tw: &CollateralTimeWindow,
) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    m.insert(
        "tcb_status".into(),
        tcb_status_to_rego_array(data.tcb.status),
    );
    insert_platform_fields(&mut m, data, tw);
    if !data.tcb.advisory_ids.is_empty() {
        m.insert("advisory_ids".into(), json!(data.tcb.advisory_ids));
    }
    serde_json::Value::Object(m)
}

/// Build platform TCB measurement using **unmerged** platform status.
pub(crate) fn build_platform_measurement(
    data: &SupplementalData,
    tw: &CollateralTimeWindow,
) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    m.insert(
        "tcb_status".into(),
        tcb_status_to_rego_array(data.platform.tcb_level.tcb_status),
    );
    insert_platform_fields(&mut m, data, tw);
    if !data.platform.tcb_level.advisory_ids.is_empty() {
        m.insert(
            "advisory_ids".into(),
            json!(data.platform.tcb_level.advisory_ids),
        );
    }
    serde_json::Value::Object(m)
}

/// Build QE Identity measurement for Rego appraisal (TDX).
pub(crate) fn build_qe_measurement(
    data: &SupplementalData,
    tw: &CollateralTimeWindow,
) -> serde_json::Value {
    let mut m = serde_json::Map::new();

    m.insert(
        "tcb_status".into(),
        tcb_status_to_rego_array(data.qe.tcb_level.tcb_status),
    );

    let qe_tcb_date = chrono::DateTime::parse_from_rfc3339(&data.qe.tcb_level.tcb_date)
        .ok()
        .map(|dt| dt.timestamp() as u64)
        .unwrap_or(0);
    let qe_date_str = unix_to_rfc3339(qe_tcb_date);
    if !qe_date_str.is_empty() {
        m.insert("tcb_level_date_tag".into(), json!(qe_date_str));
    }

    let earliest_issue = unix_to_rfc3339(tw.earliest_issue_date);
    if !earliest_issue.is_empty() {
        m.insert("earliest_issue_date".into(), json!(earliest_issue));
    }
    let latest_issue = unix_to_rfc3339(tw.latest_issue_date);
    if !latest_issue.is_empty() {
        m.insert("latest_issue_date".into(), json!(latest_issue));
    }
    let earliest_exp = unix_to_rfc3339(tw.earliest_expiration_date);
    if !earliest_exp.is_empty() {
        m.insert("earliest_expiration_date".into(), json!(earliest_exp));
    }

    m.insert("tcb_eval_num".into(), json!(data.qe.tcb_eval_data_number));
    m.insert(
        "root_key_id".into(),
        json!(hex::encode_upper(data.platform.root_key_id)),
    );

    serde_json::Value::Object(m)
}

// ── Tenant measurement helpers ─────────────────────────────────────────

use crate::quote::{Report, TDReport10, TDReport15};

/// Generate SGX enclave measurement JSON from an `EnclaveReport`.
///
/// KSS fields are extracted from reserved areas matching Intel's `sgx_report_body_t` layout:
/// - `isv_ext_prod_id`: reserved1\[12..28\] (16B at offset 32)
/// - `config_id`: reserved3\[32..96\] (64B at offset 192)
/// - `config_svn`: reserved4\[0..2\] (u16 LE at offset 260)
/// - `isv_family_id`: reserved4\[44..60\] (16B at offset 304)
pub(crate) fn sgx_enclave_measurement(report: &EnclaveReport) -> serde_json::Value {
    let mut m = serde_json::Map::new();

    m.insert(
        "sgx_miscselect".into(),
        json!(hex::encode_upper(report.misc_select.to_le_bytes())),
    );
    m.insert(
        "sgx_attributes".into(),
        json!(hex::encode_upper(report.attributes)),
    );
    m.insert(
        "sgx_mrenclave".into(),
        json!(hex::encode_upper(report.mr_enclave)),
    );
    m.insert(
        "sgx_mrsigner".into(),
        json!(hex::encode_upper(report.mr_signer)),
    );
    m.insert("sgx_isvprodid".into(), json!(report.isv_prod_id));
    m.insert("sgx_isvsvn".into(), json!(report.isv_svn));
    m.insert(
        "sgx_reportdata".into(),
        json!(hex::encode_upper(report.report_data)),
    );

    // KSS fields from reserved areas (Intel sgx_report_body_t layout)
    if let Some(ext_prod_id) = report.reserved1.get(12..28) {
        m.insert(
            "sgx_isvextprodid".into(),
            json!(hex::encode_upper(ext_prod_id)),
        );
    }
    if let Some(config_id) = report.reserved3.get(32..96) {
        m.insert(
            "sgx_configid".into(),
            json!(hex::encode_upper(config_id)),
        );
    }
    if let Some(config_svn_bytes) = report.reserved4.get(0..2).and_then(|s| <[u8; 2]>::try_from(s).ok()) {
        let config_svn = u16::from_le_bytes(config_svn_bytes);
        m.insert("sgx_configsvn".into(), json!(config_svn));
    }
    if let Some(family_id) = report.reserved4.get(44..60) {
        m.insert(
            "sgx_isvfamilyid".into(),
            json!(hex::encode_upper(family_id)),
        );
    }

    serde_json::Value::Object(m)
}

/// Generate TDX TD 1.0 measurement JSON from a `TDReport10`.
fn td10_measurement(report: &TDReport10) -> serde_json::Value {
    let mut m = serde_json::Map::new();

    m.insert(
        "tdx_attributes".into(),
        json!(hex::encode_upper(report.td_attributes)),
    );
    m.insert(
        "tdx_xfam".into(),
        json!(hex::encode_upper(report.xfam)),
    );
    m.insert(
        "tdx_mrtd".into(),
        json!(hex::encode_upper(report.mr_td)),
    );
    m.insert(
        "tdx_mrconfigid".into(),
        json!(hex::encode_upper(report.mr_config_id)),
    );
    m.insert(
        "tdx_mrowner".into(),
        json!(hex::encode_upper(report.mr_owner)),
    );
    m.insert(
        "tdx_mrownerconfig".into(),
        json!(hex::encode_upper(report.mr_owner_config)),
    );
    m.insert(
        "tdx_rtmr0".into(),
        json!(hex::encode_upper(report.rt_mr0)),
    );
    m.insert(
        "tdx_rtmr1".into(),
        json!(hex::encode_upper(report.rt_mr1)),
    );
    m.insert(
        "tdx_rtmr2".into(),
        json!(hex::encode_upper(report.rt_mr2)),
    );
    m.insert(
        "tdx_rtmr3".into(),
        json!(hex::encode_upper(report.rt_mr3)),
    );
    m.insert(
        "tdx_reportdata".into(),
        json!(hex::encode_upper(report.report_data)),
    );

    serde_json::Value::Object(m)
}

/// Generate TDX TD 1.5 measurement JSON from a `TDReport15`.
fn td15_measurement(report: &TDReport15) -> serde_json::Value {
    let mut m = td10_measurement(&report.base);
    if let Some(obj) = m.as_object_mut() {
        obj.insert(
            "tdx_mrservicetd".into(),
            json!(hex::encode_upper(report.mr_service_td)),
        );
    }
    m
}

/// Generate tenant measurement JSON from a `Report`.
pub(crate) fn tenant_measurement(report: &Report) -> serde_json::Value {
    match report {
        Report::SgxEnclave(er) => sgx_enclave_measurement(er),
        Report::TD10(td) => td10_measurement(td),
        Report::TD15(td) => td15_measurement(td),
    }
}

/// Returns the tenant class_id for the given report type.
pub(crate) fn tenant_class_id(report: &Report) -> &'static str {
    match report {
        Report::SgxEnclave(_) => "bef7cb8c-31aa-42c1-854c-10db005d5c41",
        Report::TD10(_) => "a1e4ee9c-a12e-48ac-bed0-e3f89297f687",
        Report::TD15(_) => "45b734fc-aa4e-4c3d-ad28-e43d08880e68",
    }
}

/// Returns the platform class_id for the given report type and tee_type.
pub(crate) fn platform_class_id(report: &Report, tee_type: u32) -> &'static str {
    match (report, tee_type) {
        (Report::TD10(_), _) => "9eec018b-7481-4b1c-8e1a-9f7c0c8c777f",
        (Report::TD15(_), _) => "f708b97f-0fb2-4e6b-8b03-8a5bcd1221d3",
        _ => "3123ec35-8d38-4ea5-87a5-d6c48b567570", // SGX
    }
}

// ── RegoPolicySet ──────────────────────────────────────────────────────

/// A set of Rego policies for multi-measurement appraisal.
///
/// Accepts multiple policy JSON objects (one per class_id). The Rego engine
/// matches each `qvl_result` entry to its corresponding policy by `class_id`.
///
/// This provides full Intel QAL compatibility with separate evaluation of
/// platform TCB, QE identity, and tenant measurements.
///
/// # Example
///
/// ```no_run
/// use dcap_qvl::RegoPolicySet;
///
/// let platform_policy = r#"{
///     "environment": { "class_id": "3123ec35-8d38-4ea5-87a5-d6c48b567570" },
///     "reference": { "accepted_tcb_status": ["UpToDate"], "collateral_grace_period": 0 }
/// }"#;
/// let enclave_policy = r#"{
///     "environment": { "class_id": "bef7cb8c-31aa-42c1-854c-10db005d5c41" },
///     "reference": { "sgx_mrenclave": "ABCD..." }
/// }"#;
/// let policies = RegoPolicySet::new(&[platform_policy, enclave_policy]).unwrap();
/// ```
pub struct RegoPolicySet {
    engine: regorus::Engine,
    policies: Vec<serde_json::Value>,
}

impl RegoPolicySet {
    /// Create a `RegoPolicySet` from multiple Intel JSON policy strings.
    ///
    /// Uses the bundled `qal_script.rego`. Each JSON must have `environment.class_id`.
    pub fn new(policy_jsons: &[&str]) -> Result<Self> {
        Self::with_rego(policy_jsons, include_str!("../../rego/qal_script.rego"))
    }

    /// Create a `RegoPolicySet` with a custom Rego script.
    pub fn with_rego(policy_jsons: &[&str], rego_source: &str) -> Result<Self> {
        let mut engine = regorus::Engine::new();
        engine
            .add_policy("qal_script.rego".into(), rego_source.into())
            .map_err(|e| anyhow::anyhow!("Failed to load Rego policy: {e}"))?;

        let mut policies = Vec::new();
        for json_str in policy_jsons {
            let policy: serde_json::Value = serde_json::from_str(json_str)
                .map_err(|e| anyhow::anyhow!("Failed to parse policy JSON: {e}"))?;
            // Validate that class_id exists
            policy
                .get("environment")
                .and_then(|e| e.get("class_id"))
                .and_then(|c| c.as_str())
                .ok_or_else(|| anyhow::anyhow!("Policy JSON missing environment.class_id"))?;
            policies.push(policy);
        }

        Ok(Self { engine, policies })
    }

    /// Evaluate the Rego engine with the given qvl_result entries.
    pub(crate) fn eval_rego(&self, qvl_result: Vec<serde_json::Value>) -> Result<()> {
        let policy_refs: Vec<&serde_json::Value> = self.policies.iter().collect();
        eval_rego_engine(&self.engine, &policy_refs, qvl_result)
    }
}

/// Shared Rego evaluation logic used by both `RegoPolicy` and `RegoPolicySet`.
fn eval_rego_engine(
    engine: &regorus::Engine,
    policies: &[&serde_json::Value],
    qvl_result: Vec<serde_json::Value>,
) -> Result<()> {
    let mut engine = engine.clone();

    let input = json!({
        "qvl_result": qvl_result,
        "policies": {
            "policy_array": policies,
        }
    });

    let input_str = serde_json::to_string(&input)
        .map_err(|e| anyhow::anyhow!("Failed to serialize Rego input: {e}"))?;
    engine
        .set_input_json(&input_str)
        .map_err(|e| anyhow::anyhow!("Failed to set Rego input: {e}"))?;

    let result = engine
        .eval_rule("data.dcap.quote.appraisal.final_ret".into())
        .map_err(|e| anyhow::anyhow!("Rego evaluation failed: {e}"))?;

    let result_json = result
        .to_json_str()
        .map_err(|e| anyhow::anyhow!("Failed to convert Rego result: {e}"))?;

    match result_json.trim() {
        "1" => Ok(()),
        "0" => {
            let detail = engine
                .eval_rule("data.dcap.quote.appraisal.appraisal_result".into())
                .ok()
                .and_then(|v| v.to_json_str().ok());
            if let Some(detail) = detail {
                bail!("Rego appraisal failed: {detail}");
            }
            bail!("Rego appraisal failed (result = 0)");
        }
        "-1" => bail!("No policy matched the report class_id"),
        other => bail!("Unexpected Rego appraisal result: {other}"),
    }
}

/// Policy implementation that evaluates Intel's `qal_script.rego` via the
/// [regorus](https://github.com/microsoft/regorus) Rego interpreter.
///
/// This provides bit-exact compatibility with Intel's Quote Appraisal Library (QAL).
/// Users provide a JSON policy in Intel's format (the `reference` object from a
/// Quote Appraisal Policy), and the Rego script evaluates it against the
/// [`SupplementalData`] converted to Intel's measurement JSON format.
///
/// # Example
///
/// ```no_run
/// use dcap_qvl::RegoPolicy;
///
/// let policy_json = r#"{
///     "environment": {
///         "class_id": "3123ec35-8d38-4ea5-87a5-d6c48b567570",
///         "description": "Strict SGX platform TCB policy"
///     },
///     "reference": {
///         "accepted_tcb_status": ["UpToDate"],
///         "collateral_grace_period": 0
///     }
/// }"#;
/// let policy = RegoPolicy::new(policy_json).expect("invalid policy");
/// ```
pub struct RegoPolicy {
    engine: regorus::Engine,
    policy_json: serde_json::Value,
    class_id: String,
}

impl RegoPolicy {
    /// Create a `RegoPolicy` from an Intel JSON policy string.
    ///
    /// Uses the bundled `qal_script.rego` (from Intel's DCAP source).
    /// The JSON must contain `environment.class_id` to identify the policy type.
    pub fn new(policy_json: &str) -> Result<Self> {
        Self::with_rego(policy_json, include_str!("../../rego/qal_script.rego"))
    }

    /// Create a `RegoPolicy` with a custom Rego script.
    ///
    /// Use this to provide an updated or modified version of `qal_script.rego`.
    pub fn with_rego(policy_json: &str, rego_source: &str) -> Result<Self> {
        let mut engine = regorus::Engine::new();
        engine
            .add_policy("qal_script.rego".into(), rego_source.into())
            .map_err(|e| anyhow::anyhow!("Failed to load Rego policy: {e}"))?;

        let policy: serde_json::Value = serde_json::from_str(policy_json)
            .map_err(|e| anyhow::anyhow!("Failed to parse policy JSON: {e}"))?;

        let class_id = policy
            .get("environment")
            .and_then(|e| e.get("class_id"))
            .and_then(|c| c.as_str())
            .ok_or_else(|| anyhow::anyhow!("Policy JSON missing environment.class_id"))?
            .to_string();

        Ok(Self {
            engine,
            policy_json: policy,
            class_id,
        })
    }
}

impl RegoPolicy {
    /// Evaluate this single-measurement Rego policy against supplemental data + time window.
    pub(crate) fn eval(
        &self,
        data: &SupplementalData,
        tw: &CollateralTimeWindow,
    ) -> Result<()> {
        let measurement = build_merged_measurement(data, tw);
        let qvl_result = vec![json!({
            "environment": { "class_id": &self.class_id },
            "measurement": measurement,
        })];
        eval_rego_engine(&self.engine, &[&self.policy_json], qvl_result)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::policy::{PckCertFlag, PckIdentity, PlatformInfo, QeInfo, TcbVerdict};
    use crate::tcb_info::TcbStatus::*;

    const SGX_PLATFORM_CLASS_ID: &str = "3123ec35-8d38-4ea5-87a5-d6c48b567570";

    fn make_test_supplemental(tcb_status: TcbStatus) -> SupplementalData {
        use crate::qe_identity::{QeTcb, QeTcbLevel};
        use crate::tcb_info::{Tcb, TcbComponents, TcbLevel};

        SupplementalData {
            tee_type: 0,
            tcb: TcbVerdict {
                status: tcb_status,
                advisory_ids: vec![],
                eval_data_number: 17,
                earliest_expiration: 1_703_000_000,
            },
            platform: PlatformInfo {
                tcb_level: TcbLevel {
                    tcb: Tcb {
                        sgx_components: vec![TcbComponents { svn: 0 }; 16],
                        tdx_components: vec![],
                        pce_svn: 13,
                    },
                    tcb_date: "2023-07-22T00:00:00Z".to_string(),
                    tcb_status,
                    advisory_ids: vec![],
                },
                tcb_date_tag: 1_690_000_000,
                pck: PckIdentity {
                    ppid: vec![0u8; 16],
                    cpu_svn: [0u8; 16],
                    pce_svn: 13,
                    pce_id: 0,
                    fmspc: [0u8; 6],
                    sgx_type: 0,
                    platform_instance_id: None,
                    dynamic_platform: PckCertFlag::Undefined,
                    cached_keys: PckCertFlag::Undefined,
                    smt_enabled: PckCertFlag::Undefined,
                    platform_provider_id: None,
                },
                root_key_id: [0u8; 48],
                pck_crl_num: 1,
                root_ca_crl_num: 1,
            },
            qe: QeInfo {
                tcb_level: QeTcbLevel {
                    tcb: QeTcb { isvsvn: 8 },
                    tcb_date: "2024-03-13T00:00:00Z".to_string(),
                    tcb_status: UpToDate,
                    advisory_ids: vec![],
                },
                report: crate::quote::EnclaveReport {
                    cpu_svn: [0u8; 16],
                    misc_select: 0,
                    reserved1: [0u8; 28],
                    attributes: [0u8; 16],
                    mr_enclave: [0u8; 32],
                    reserved2: [0u8; 32],
                    mr_signer: [0u8; 32],
                    reserved3: [0u8; 96],
                    isv_prod_id: 1,
                    isv_svn: 8,
                    reserved4: [0u8; 60],
                    report_data: [0u8; 64],
                },
                tcb_eval_data_number: 17,
            },
        }
    }

    /// Create a test time window with future dates (Rego uses real wall clock).
    fn make_test_time_window() -> CollateralTimeWindow {
        CollateralTimeWindow {
            earliest_issue_date: 1_900_000_000,
            latest_issue_date: 1_900_100_000,
            earliest_expiration_date: 2_000_000_000,
        }
    }

    /// Create test supplemental data with future expiration for Rego.
    fn make_rego_supplemental(status: TcbStatus) -> SupplementalData {
        let mut data = make_test_supplemental(status);
        data.tcb.earliest_expiration = 2_000_000_000;
        data
    }

    fn policy_json(reference: &str) -> String {
        format!(
            r#"{{
                "environment": {{
                    "class_id": "{SGX_PLATFORM_CLASS_ID}",
                    "description": "Test policy"
                }},
                "reference": {reference}
            }}"#
        )
    }

    #[test]
    fn rego_strict_accepts_up_to_date() {
        let data = make_rego_supplemental(UpToDate);
        let tw = make_test_time_window();
        let json = policy_json(
            r#"{"accepted_tcb_status": ["UpToDate"], "collateral_grace_period": 0}"#,
        );
        let policy = RegoPolicy::new(&json).unwrap();
        let result = policy.eval(&data, &tw);
        assert!(
            result.is_ok(),
            "expected Ok, got: {:?}",
            result.unwrap_err()
        );
    }

    #[test]
    fn rego_strict_rejects_out_of_date() {
        let data = make_rego_supplemental(OutOfDate);
        let tw = make_test_time_window();
        let json = policy_json(
            r#"{"accepted_tcb_status": ["UpToDate"], "collateral_grace_period": 0}"#,
        );
        let policy = RegoPolicy::new(&json).unwrap();
        let err = policy.eval(&data, &tw).unwrap_err().to_string();
        assert!(
            err.contains("appraisal failed"),
            "expected appraisal failure, got: {err}"
        );
    }

    #[test]
    fn rego_permissive_accepts_out_of_date() {
        let data = make_rego_supplemental(OutOfDate);
        let tw = make_test_time_window();
        let json = policy_json(
            r#"{"accepted_tcb_status": ["UpToDate", "OutOfDate"], "collateral_grace_period": 0}"#,
        );
        let policy = RegoPolicy::new(&json).unwrap();
        let result = policy.eval(&data, &tw);
        assert!(
            result.is_ok(),
            "expected Ok, got: {:?}",
            result.unwrap_err()
        );
    }

    #[test]
    fn rego_rejects_advisory() {
        let mut data = make_rego_supplemental(UpToDate);
        data.tcb.advisory_ids = vec!["INTEL-SA-00334".into()];
        let tw = make_test_time_window();
        let json = policy_json(
            r#"{
                "accepted_tcb_status": ["UpToDate"],
                "collateral_grace_period": 0,
                "rejected_advisory_ids": ["INTEL-SA-00334"]
            }"#,
        );
        let policy = RegoPolicy::new(&json).unwrap();
        let err = policy.eval(&data, &tw).unwrap_err().to_string();
        assert!(
            err.contains("appraisal failed"),
            "expected advisory rejection, got: {err}"
        );
    }

    #[test]
    fn rego_platform_grace_period_accepts() {
        let mut data = make_rego_supplemental(OutOfDate);
        data.platform.tcb_date_tag = 1_690_000_000;
        let tw = make_test_time_window();
        let json = policy_json(
            r#"{
                "accepted_tcb_status": ["UpToDate", "OutOfDate"],
                "collateral_grace_period": 0,
                "platform_grace_period": 999999999
            }"#,
        );
        let policy = RegoPolicy::new(&json).unwrap();
        let result = policy.eval(&data, &tw);
        assert!(
            result.is_ok(),
            "expected Ok, got: {:?}",
            result.unwrap_err()
        );
    }

    #[test]
    fn rego_expiration_check_rejects_expired_collateral() {
        let data = make_rego_supplemental(UpToDate);
        let tw = CollateralTimeWindow {
            earliest_issue_date: 1_700_000_000,
            latest_issue_date: 1_700_100_000,
            earliest_expiration_date: 1_703_000_000,
        };
        let json = policy_json(
            r#"{"accepted_tcb_status": ["UpToDate"], "collateral_grace_period": 0}"#,
        );
        let policy = RegoPolicy::new(&json).unwrap();
        let err = policy.eval(&data, &tw).unwrap_err().to_string();
        assert!(
            err.contains("appraisal failed"),
            "expected expiration failure, got: {err}"
        );
    }

    #[test]
    fn rego_no_collateral_grace_skips_expiration_check() {
        let data = make_rego_supplemental(UpToDate);
        let tw = CollateralTimeWindow {
            earliest_issue_date: 1_700_000_000,
            latest_issue_date: 1_700_100_000,
            earliest_expiration_date: 1_703_000_000,
        };
        let json = policy_json(r#"{"accepted_tcb_status": ["UpToDate"]}"#);
        let policy = RegoPolicy::new(&json).unwrap();
        let result = policy.eval(&data, &tw);
        assert!(
            result.is_ok(),
            "expected Ok (no expiration check), got: {:?}",
            result.unwrap_err()
        );
    }

    #[test]
    fn rego_missing_class_id_errors() {
        let json = r#"{"reference": {"accepted_tcb_status": ["UpToDate"]}}"#;
        assert!(RegoPolicy::new(json).is_err());
    }

    #[test]
    fn rego_to_measurement_tcb_status_mapping() {
        let data = make_test_supplemental(ConfigurationAndSWHardeningNeeded);
        let tw = make_test_time_window();
        let m = build_merged_measurement(&data, &tw);
        let statuses = m.get("tcb_status").unwrap().as_array().unwrap();
        assert_eq!(statuses.len(), 3);
        assert_eq!(statuses[0], "UpToDate");
        assert_eq!(statuses[1], "SWHardeningNeeded");
        assert_eq!(statuses[2], "ConfigurationNeeded");
    }

    #[test]
    fn rego_to_measurement_omits_undefined_flags() {
        let data = make_test_supplemental(UpToDate);
        assert_eq!(data.platform.pck.dynamic_platform, PckCertFlag::Undefined);
        let tw = make_test_time_window();
        let m = build_merged_measurement(&data, &tw);
        assert!(m.get("is_dynamic_platform").is_none());
        assert!(m.get("cached_keys").is_none());
        assert!(m.get("smt_enabled").is_none());
    }

    #[test]
    fn rego_to_measurement_includes_true_flags() {
        let mut data = make_test_supplemental(UpToDate);
        data.platform.pck.dynamic_platform = PckCertFlag::True;
        data.platform.pck.cached_keys = PckCertFlag::False;
        data.platform.pck.smt_enabled = PckCertFlag::True;
        let tw = make_test_time_window();
        let m = build_merged_measurement(&data, &tw);
        assert_eq!(m.get("is_dynamic_platform").unwrap(), true);
        assert_eq!(m.get("cached_keys").unwrap(), false);
        assert_eq!(m.get("smt_enabled").unwrap(), true);
    }

    #[test]
    fn rego_platform_measurement_uses_unmerged_status() {
        let mut data = make_test_supplemental(UpToDate);
        data.platform.tcb_level.tcb_status = OutOfDate;
        data.platform.tcb_level.advisory_ids = vec!["INTEL-SA-00001".into()];
        let tw = make_test_time_window();
        let m = build_platform_measurement(&data, &tw);
        let statuses = m.get("tcb_status").unwrap().as_array().unwrap();
        assert!(statuses.contains(&serde_json::json!("OutOfDate")));
        let advisories = m.get("advisory_ids").unwrap().as_array().unwrap();
        assert_eq!(advisories, &[serde_json::json!("INTEL-SA-00001")]);
    }

    #[test]
    fn rego_qe_measurement_fields() {
        let data = make_rego_supplemental(UpToDate);
        let tw = make_test_time_window();
        let m = build_qe_measurement(&data, &tw);
        assert!(m.get("tcb_status").is_some());
        assert_eq!(m.get("tcb_eval_num").unwrap(), 17);
        assert!(m.get("root_key_id").is_some());
        assert!(m.get("earliest_issue_date").is_some());
        assert!(m.get("latest_issue_date").is_some());
        assert!(m.get("earliest_expiration_date").is_some());
        assert!(m.get("tcb_level_date_tag").is_some());
    }

    #[test]
    fn rego_sgx_enclave_measurement_fields() {
        use crate::quote::EnclaveReport;

        let mut report = EnclaveReport {
            cpu_svn: [0u8; 16],
            misc_select: 0x12345678,
            reserved1: [0u8; 28],
            attributes: [0xAA; 16],
            mr_enclave: [0xBB; 32],
            reserved2: [0u8; 32],
            mr_signer: [0xCC; 32],
            reserved3: [0u8; 96],
            isv_prod_id: 42,
            isv_svn: 7,
            reserved4: [0u8; 60],
            report_data: [0xDD; 64],
        };
        report.reserved1[12..28].copy_from_slice(&[0x11; 16]);
        report.reserved3[32..96].copy_from_slice(&[0x22; 64]);
        report.reserved4[0..2].copy_from_slice(&42u16.to_le_bytes());
        report.reserved4[44..60].copy_from_slice(&[0x33; 16]);

        let m = sgx_enclave_measurement(&report);
        assert!(m.get("sgx_mrenclave").is_some());
        assert!(m.get("sgx_mrsigner").is_some());
        assert_eq!(m.get("sgx_isvprodid").unwrap(), 42);
        assert_eq!(m.get("sgx_isvsvn").unwrap(), 7);
        assert!(m.get("sgx_reportdata").is_some());
        assert!(m.get("sgx_configid").is_some());
        assert_eq!(m.get("sgx_configsvn").unwrap(), 42);
        assert!(m.get("sgx_isvextprodid").is_some());
        assert!(m.get("sgx_isvfamilyid").is_some());
    }

    #[test]
    fn rego_policy_set_sgx_platform_accepts() {
        let data = make_rego_supplemental(UpToDate);
        let tw = make_test_time_window();
        let platform_json = format!(
            r#"{{
                "environment": {{ "class_id": "{SGX_PLATFORM_CLASS_ID}" }},
                "reference": {{ "accepted_tcb_status": ["UpToDate"], "collateral_grace_period": 0 }}
            }}"#
        );
        let policies = RegoPolicySet::new(&[&platform_json]).unwrap();
        let qvl_result = vec![serde_json::json!({
            "environment": { "class_id": SGX_PLATFORM_CLASS_ID },
            "measurement": build_platform_measurement(&data, &tw),
        })];
        assert!(
            policies.eval_rego(qvl_result).is_ok(),
            "expected Ok, got: {:?}",
            {
                let qvl_result2 = vec![serde_json::json!({
                    "environment": { "class_id": SGX_PLATFORM_CLASS_ID },
                    "measurement": build_platform_measurement(&data, &tw),
                })];
                policies.eval_rego(qvl_result2).unwrap_err()
            }
        );
    }

    #[test]
    fn rego_policy_set_class_id_mismatch_fails() {
        let data = make_rego_supplemental(UpToDate);
        let tw = make_test_time_window();
        let tdx_class_id = "9eec018b-7481-4b1c-8e1a-9f7c0c8c777f";
        let policy_json = format!(
            r#"{{
                "environment": {{ "class_id": "{tdx_class_id}" }},
                "reference": {{ "accepted_tcb_status": ["UpToDate"], "collateral_grace_period": 0 }}
            }}"#
        );
        let policies = RegoPolicySet::new(&[&policy_json]).unwrap();
        let qvl_result = vec![serde_json::json!({
            "environment": { "class_id": SGX_PLATFORM_CLASS_ID },
            "measurement": build_platform_measurement(&data, &tw),
        })];
        let err = policies.eval_rego(qvl_result).unwrap_err().to_string();
        assert!(
            err.contains("appraisal failed"),
            "expected appraisal failure on class_id mismatch, got: {err}"
        );
    }
}
