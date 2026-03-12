use super::*;
use serde_json::json;

use crate::utils::parse_rfc3339_unix_secs;
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

/// Build common platform fields into a Rego measurement JSON map.
fn insert_platform_fields(
    m: &mut serde_json::Map<String, serde_json::Value>,
    data: &SupplementalData,
) {
    // Time fields as RFC3339 strings (from SupplementalData's collateral time window)
    let earliest_issue = unix_to_rfc3339(data.earliest_issue_date);
    if !earliest_issue.is_empty() {
        m.insert("earliest_issue_date".into(), json!(earliest_issue));
    }
    let latest_issue = unix_to_rfc3339(data.latest_issue_date);
    if !latest_issue.is_empty() {
        m.insert("latest_issue_date".into(), json!(latest_issue));
    }
    let earliest_exp = unix_to_rfc3339(data.earliest_expiration_date);
    if !earliest_exp.is_empty() {
        m.insert("earliest_expiration_date".into(), json!(earliest_exp));
    }
    let tcb_date = unix_to_rfc3339(data.platform.tcb_date_tag);
    if !tcb_date.is_empty() {
        m.insert("tcb_level_date_tag".into(), json!(tcb_date));
    }

    m.insert("pck_crl_num".into(), json!(data.platform.pck_crl_num));
    m.insert(
        "root_ca_crl_num".into(),
        json!(data.platform.root_ca_crl_num),
    );
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

    m.insert(
        "fmspc".into(),
        json!(hex::encode_upper(data.platform.pck.fmspc)),
    );
    m.insert(
        "root_key_id".into(),
        json!(hex::encode_upper(data.platform.root_key_id)),
    );
}

/// Build merged Rego measurement (single-measurement path).
fn build_merged_measurement(data: &SupplementalData) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    m.insert(
        "tcb_status".into(),
        tcb_status_to_rego_array(data.tcb.status),
    );
    insert_platform_fields(&mut m, data);
    if !data.tcb.advisory_ids.is_empty() {
        m.insert("advisory_ids".into(), json!(data.tcb.advisory_ids));
    }
    serde_json::Value::Object(m)
}

/// Build platform TCB measurement using **unmerged** platform status.
fn build_platform_measurement(data: &SupplementalData) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    m.insert(
        "tcb_status".into(),
        tcb_status_to_rego_array(data.platform.tcb_level.tcb_status),
    );
    insert_platform_fields(&mut m, data);
    if !data.platform.tcb_level.advisory_ids.is_empty() {
        m.insert(
            "advisory_ids".into(),
            json!(data.platform.tcb_level.advisory_ids),
        );
    }
    serde_json::Value::Object(m)
}

/// Build QE Identity measurement for Rego appraisal (TDX).
fn build_qe_measurement(data: &SupplementalData) -> Result<serde_json::Value> {
    let mut m = serde_json::Map::new();

    m.insert(
        "tcb_status".into(),
        tcb_status_to_rego_array(data.qe.tcb_level.tcb_status),
    );

    let qe_tcb_date = parse_rfc3339_unix_secs(&data.qe.tcb_level.tcb_date)
        .map_err(|e| anyhow::anyhow!("Failed to parse QE TCB date: {e}"))?;
    let qe_date_str = unix_to_rfc3339(qe_tcb_date);
    if !qe_date_str.is_empty() {
        m.insert("tcb_level_date_tag".into(), json!(qe_date_str));
    }

    let earliest_issue = unix_to_rfc3339(data.qe_iden_earliest_issue_date);
    if !earliest_issue.is_empty() {
        m.insert("earliest_issue_date".into(), json!(earliest_issue));
    }
    let latest_issue = unix_to_rfc3339(data.qe_iden_latest_issue_date);
    if !latest_issue.is_empty() {
        m.insert("latest_issue_date".into(), json!(latest_issue));
    }
    let earliest_exp = unix_to_rfc3339(data.qe_iden_earliest_expiration_date);
    if !earliest_exp.is_empty() {
        m.insert("earliest_expiration_date".into(), json!(earliest_exp));
    }

    m.insert("tcb_eval_num".into(), json!(data.qe.tcb_eval_data_number));
    m.insert(
        "root_key_id".into(),
        json!(hex::encode_upper(data.platform.root_key_id)),
    );

    Ok(serde_json::Value::Object(m))
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
        m.insert("sgx_configid".into(), json!(hex::encode_upper(config_id)));
    }
    if let Some(config_svn_bytes) = report
        .reserved4
        .get(0..2)
        .and_then(|s| <[u8; 2]>::try_from(s).ok())
    {
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
    m.insert("tdx_xfam".into(), json!(hex::encode_upper(report.xfam)));
    m.insert("tdx_mrtd".into(), json!(hex::encode_upper(report.mr_td)));
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
    m.insert("tdx_rtmr0".into(), json!(hex::encode_upper(report.rt_mr0)));
    m.insert("tdx_rtmr1".into(), json!(hex::encode_upper(report.rt_mr1)));
    m.insert("tdx_rtmr2".into(), json!(hex::encode_upper(report.rt_mr2)));
    m.insert("tdx_rtmr3".into(), json!(hex::encode_upper(report.rt_mr3)));
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
        register_rand_intn(&mut engine)?;
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
}

/// Register `rand.intn` extension on a regorus engine.
///
/// OPA's `rand.intn(str, n)` returns a random integer in `[0, n)`.
/// The `str` parameter is a **memoization key** (not a PRNG seed): same `(str, n)` pair
/// within one query evaluation always returns the same result. The actual random number
/// comes from a separate RNG, not derived from the string.
///
/// Cache key is `"{str}-{n}"` matching OPA's implementation.
///
/// Ref: OPA docs — "For any given argument pair (str, n), the output will be consistent
/// throughout a query evaluation."
/// <https://www.openpolicyagent.org/docs/latest/policy-reference/#rand>
///
/// Ref: OPA source — `key := randIntCachingKey(fmt.Sprintf("%s-%d", strOp, n))`
/// <https://github.com/open-policy-agent/opa/blob/0265c7cc/v1/topdown/numbers.go#L180>
fn register_rand_intn(engine: &mut regorus::Engine) -> Result<()> {
    let mut cache = std::collections::HashMap::<String, i64>::new();
    engine
        .add_extension(
            "rand.intn".to_string(),
            2,
            Box::new(move |params: Vec<regorus::Value>| {
                let seed = params
                    .first()
                    .ok_or_else(|| anyhow::anyhow!("rand.intn: missing first argument"))?
                    .as_string()
                    .map_err(|_| anyhow::anyhow!("rand.intn: first argument must be string"))?
                    .to_string();

                let n = params
                    .get(1)
                    .ok_or_else(|| anyhow::anyhow!("rand.intn: missing second argument"))?
                    .as_i64()
                    .map_err(|_| anyhow::anyhow!("rand.intn: second argument must be integer"))?;

                if n == 0 {
                    return Ok(regorus::Value::from(0i64));
                }

                // OPA uses abs(n) for negative values
                let n = n.unsigned_abs();

                // Cache key = "{seed}-{n}", matching OPA's `fmt.Sprintf("%s-%d", strOp, n)`
                // Note: OPA caches with abs'd n, so "-5" and "5" share the same key.
                let key = alloc::format!("{seed}-{n}");

                if let Some(&cached) = cache.get(&key) {
                    return Ok(regorus::Value::from(cached));
                }

                let mut buf = [0u8; 8];
                getrandom::getrandom(&mut buf)
                    .map_err(|e| anyhow::anyhow!("rand.intn: RNG failed: {e}"))?;
                let random_val = (u64::from_le_bytes(buf).checked_rem(n).unwrap_or(0)) as i64;
                cache.insert(key, random_val);
                Ok(regorus::Value::from(random_val))
            }),
        )
        .map_err(|e| anyhow::anyhow!("Failed to register rand.intn: {e}"))
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
        .eval_rule("data.dcap.quote.appraisal.final_appraisal_result".into())
        .map_err(|e| anyhow::anyhow!("Rego evaluation failed: {e}"))?;

    let result_json = result
        .to_json_str()
        .map_err(|e| anyhow::anyhow!("Failed to convert Rego result: {e}"))?;

    // final_appraisal_result is a Rego set → JSON array of objects
    let result_value: serde_json::Value = serde_json::from_str(&result_json)
        .map_err(|e| anyhow::anyhow!("Failed to parse final_appraisal_result JSON: {e}"))?;

    let arr = result_value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("final_appraisal_result is not an array"))?;

    let entry = arr
        .first()
        .ok_or_else(|| anyhow::anyhow!("final_appraisal_result is empty"))?;

    let overall = entry
        .get("overall_appraisal_result")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| {
            anyhow::anyhow!("final_appraisal_result missing overall_appraisal_result")
        })?;

    match overall {
        1 => Ok(()),
        0 => {
            let detail = entry.get("appraised_reports");
            if let Some(detail) = detail {
                bail!("Rego appraisal failed: {detail}");
            }
            bail!("Rego appraisal failed (result = 0)");
        }
        -1 => bail!("No policy matched the report class_id"),
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
        register_rand_intn(&mut engine)?;
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

impl Policy for RegoPolicy {
    fn validate(&self, data: &SupplementalData) -> Result<()> {
        let measurement = build_merged_measurement(data);
        let qvl_result = vec![json!({
            "environment": { "class_id": &self.class_id },
            "measurement": measurement,
        })];
        eval_rego_engine(&self.engine, &[&self.policy_json], qvl_result)
    }
}

impl Policy for RegoPolicySet {
    fn validate(&self, data: &SupplementalData) -> Result<()> {
        let qvl_result = to_rego_qvl_result(data)?;
        let policy_refs: Vec<&serde_json::Value> = self.policies.iter().collect();
        eval_rego_engine(&self.engine, &policy_refs, qvl_result)
    }
}

/// Generate Intel-format `qvl_result` array for Rego appraisal from [`SupplementalData`].
///
/// SGX quotes produce 2 entries (platform + enclave).
/// TDX quotes produce 3 entries (platform + QE identity + TD).
fn to_rego_qvl_result(data: &SupplementalData) -> Result<Vec<serde_json::Value>> {
    use crate::quote::Report;

    let mut result = Vec::new();

    // 1. Platform TCB measurement
    let platform_cid = platform_class_id(&data.report, data.tee_type);
    result.push(json!({
        "environment": { "class_id": platform_cid },
        "measurement": build_platform_measurement(data),
    }));

    // 2. QE Identity measurement (TDX only)
    if matches!(data.report, Report::TD10(_) | Report::TD15(_)) {
        result.push(json!({
            "environment": { "class_id": "3769258c-75e6-4bc7-8d72-d2b0e224cad2" },
            "measurement": build_qe_measurement(data)?,
        }));
    }

    // 3. Tenant measurement (enclave or TD report)
    let tenant_cid = tenant_class_id(&data.report);
    let mut tenant_m = tenant_measurement(&data.report);
    // For SGX enclave, add sgx_ce_attributes from the QE report
    if let Report::SgxEnclave(_) = &data.report {
        if let Some(obj) = tenant_m.as_object_mut() {
            obj.insert(
                "sgx_ce_attributes".into(),
                json!(hex::encode_upper(data.qe.report.attributes)),
            );
        }
    }
    result.push(json!({
        "environment": { "class_id": tenant_cid },
        "measurement": tenant_m,
    }));

    Ok(result)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::manual_range_contains
)]
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
            report: crate::quote::Report::SgxEnclave(crate::quote::EnclaveReport {
                cpu_svn: [0u8; 16],
                misc_select: 0,
                reserved1: [0u8; 28],
                attributes: [0u8; 16],
                mr_enclave: [0u8; 32],
                reserved2: [0u8; 32],
                mr_signer: [0u8; 32],
                reserved3: [0u8; 96],
                isv_prod_id: 0,
                isv_svn: 0,
                reserved4: [0u8; 60],
                report_data: [0u8; 64],
            }),
            earliest_issue_date: 1_690_000_000,
            latest_issue_date: 1_690_100_000,
            earliest_expiration_date: 1_703_000_000,
            qe_iden_earliest_issue_date: 1_690_000_000,
            qe_iden_latest_issue_date: 1_690_100_000,
            qe_iden_earliest_expiration_date: 1_703_000_000,
        }
    }

    /// Create test supplemental data with future dates for Rego (uses real wall clock).
    fn make_rego_supplemental(status: TcbStatus) -> SupplementalData {
        let mut data = make_test_supplemental(status);
        data.earliest_issue_date = 1_900_000_000;
        data.latest_issue_date = 1_900_100_000;
        data.earliest_expiration_date = 2_000_000_000;
        data.qe_iden_earliest_issue_date = 1_900_000_000;
        data.qe_iden_latest_issue_date = 1_900_100_000;
        data.qe_iden_earliest_expiration_date = 2_000_000_000;
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
        let json =
            policy_json(r#"{"accepted_tcb_status": ["UpToDate"], "collateral_grace_period": 0}"#);
        let policy = RegoPolicy::new(&json).unwrap();
        let result = policy.validate(&data);
        assert!(
            result.is_ok(),
            "expected Ok, got: {:?}",
            result.unwrap_err()
        );
    }

    #[test]
    fn rego_strict_rejects_out_of_date() {
        let data = make_rego_supplemental(OutOfDate);
        let json =
            policy_json(r#"{"accepted_tcb_status": ["UpToDate"], "collateral_grace_period": 0}"#);
        let policy = RegoPolicy::new(&json).unwrap();
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(
            err.contains("appraisal failed"),
            "expected appraisal failure, got: {err}"
        );
    }

    #[test]
    fn rego_permissive_accepts_out_of_date() {
        let data = make_rego_supplemental(OutOfDate);
        let json = policy_json(
            r#"{"accepted_tcb_status": ["UpToDate", "OutOfDate"], "collateral_grace_period": 0}"#,
        );
        let policy = RegoPolicy::new(&json).unwrap();
        let result = policy.validate(&data);
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
        let json = policy_json(
            r#"{
                "accepted_tcb_status": ["UpToDate"],
                "collateral_grace_period": 0,
                "rejected_advisory_ids": ["INTEL-SA-00334"]
            }"#,
        );
        let policy = RegoPolicy::new(&json).unwrap();
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(
            err.contains("appraisal failed"),
            "expected advisory rejection, got: {err}"
        );
    }

    #[test]
    fn rego_platform_grace_period_accepts() {
        let mut data = make_rego_supplemental(OutOfDate);
        data.platform.tcb_date_tag = 1_690_000_000;
        let json = policy_json(
            r#"{
                "accepted_tcb_status": ["UpToDate", "OutOfDate"],
                "collateral_grace_period": 0,
                "platform_grace_period": 999999999
            }"#,
        );
        let policy = RegoPolicy::new(&json).unwrap();
        let result = policy.validate(&data);
        assert!(
            result.is_ok(),
            "expected Ok, got: {:?}",
            result.unwrap_err()
        );
    }

    #[test]
    fn rego_expiration_check_rejects_expired_collateral() {
        let mut data = make_rego_supplemental(UpToDate);
        // Override with past dates — collateral expired
        data.earliest_issue_date = 1_700_000_000;
        data.latest_issue_date = 1_700_100_000;
        data.earliest_expiration_date = 1_703_000_000;
        let json =
            policy_json(r#"{"accepted_tcb_status": ["UpToDate"], "collateral_grace_period": 0}"#);
        let policy = RegoPolicy::new(&json).unwrap();
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(
            err.contains("appraisal failed"),
            "expected expiration failure, got: {err}"
        );
    }

    #[test]
    fn rego_no_collateral_grace_skips_expiration_check() {
        let mut data = make_rego_supplemental(UpToDate);
        // Override with past dates — but no grace period in policy means no check
        data.earliest_issue_date = 1_700_000_000;
        data.latest_issue_date = 1_700_100_000;
        data.earliest_expiration_date = 1_703_000_000;
        let json = policy_json(r#"{"accepted_tcb_status": ["UpToDate"]}"#);
        let policy = RegoPolicy::new(&json).unwrap();
        let result = policy.validate(&data);
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
        let m = build_merged_measurement(&data);
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
        let m = build_merged_measurement(&data);
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
        let m = build_merged_measurement(&data);
        assert_eq!(m.get("is_dynamic_platform").unwrap(), true);
        assert_eq!(m.get("cached_keys").unwrap(), false);
        assert_eq!(m.get("smt_enabled").unwrap(), true);
    }

    #[test]
    fn rego_platform_measurement_uses_unmerged_status() {
        let mut data = make_test_supplemental(UpToDate);
        data.platform.tcb_level.tcb_status = OutOfDate;
        data.platform.tcb_level.advisory_ids = vec!["INTEL-SA-00001".into()];
        let m = build_platform_measurement(&data);
        let statuses = m.get("tcb_status").unwrap().as_array().unwrap();
        assert!(statuses.contains(&serde_json::json!("OutOfDate")));
        let advisories = m.get("advisory_ids").unwrap().as_array().unwrap();
        assert_eq!(advisories, &[serde_json::json!("INTEL-SA-00001")]);
    }

    #[test]
    fn rego_qe_measurement_fields() {
        let data = make_rego_supplemental(UpToDate);
        let m = build_qe_measurement(&data).unwrap();
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
        let platform_json = format!(
            r#"{{
                "environment": {{ "class_id": "{SGX_PLATFORM_CLASS_ID}" }},
                "reference": {{ "accepted_tcb_status": ["UpToDate"], "collateral_grace_period": 0 }}
            }}"#
        );
        let policies = RegoPolicySet::new(&[&platform_json]).unwrap();
        let result = policies.validate(&data);
        assert!(
            result.is_ok(),
            "expected Ok, got: {:?}",
            result.unwrap_err()
        );
    }

    #[test]
    fn rego_final_appraisal_result_has_expected_fields() {
        // Verify that eval uses final_appraisal_result (not final_ret) by checking
        // the Rego engine can produce the full appraisal output with nonce/timestamp.
        let data = make_rego_supplemental(UpToDate);
        let json =
            policy_json(r#"{"accepted_tcb_status": ["UpToDate"], "collateral_grace_period": 0}"#);

        let mut engine = regorus::Engine::new();
        register_rand_intn(&mut engine).unwrap();
        engine
            .add_policy(
                "qal_script.rego".into(),
                include_str!("../../rego/qal_script.rego").into(),
            )
            .unwrap();

        let policy_value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let measurement = build_merged_measurement(&data);
        let class_id = policy_value["environment"]["class_id"].as_str().unwrap();
        let qvl_result = vec![json!({
            "environment": { "class_id": class_id },
            "measurement": measurement,
        })];
        let input = json!({
            "qvl_result": qvl_result,
            "policies": { "policy_array": [&policy_value] },
        });
        engine
            .set_input_json(&serde_json::to_string(&input).unwrap())
            .unwrap();

        let result = engine
            .eval_rule("data.dcap.quote.appraisal.final_appraisal_result".into())
            .unwrap();
        let result_json: serde_json::Value =
            serde_json::from_str(&result.to_json_str().unwrap()).unwrap();
        let arr = result_json.as_array().unwrap();
        assert_eq!(arr.len(), 1, "expected exactly one appraisal result");
        let entry = &arr[0];
        assert_eq!(entry["overall_appraisal_result"], 1);
        assert!(entry.get("nonce").is_some(), "missing nonce from rand.intn");
        assert!(
            entry.get("appraisal_check_date").is_some(),
            "missing appraisal_check_date from time.now_ns"
        );
        assert!(
            entry.get("appraised_reports").is_some(),
            "missing appraised_reports"
        );
        // nonce should be a non-negative integer < 10^15
        let nonce = entry["nonce"].as_i64().unwrap();
        assert!(
            nonce >= 0 && nonce < 1_000_000_000_000_000,
            "nonce out of range: {nonce}"
        );
    }

    #[test]
    fn rego_rand_intn_memoization() {
        // Same (seed, n) pair within one engine evaluation → same result.
        let mut engine = regorus::Engine::new();
        register_rand_intn(&mut engine).unwrap();
        engine
            .add_policy(
                "test.rego".into(),
                r#"package test
                   import future.keywords.if
                   a := rand.intn("memo_test", 1000000000)
                   b := rand.intn("memo_test", 1000000000)
                   same if { a == b }
                "#
                .into(),
            )
            .unwrap();
        engine.set_input_json("{}").unwrap();

        let same = engine
            .eval_rule("data.test.same".into())
            .unwrap()
            .to_json_str()
            .unwrap();
        assert_eq!(
            same.trim(),
            "true",
            "rand.intn memoization failed: same seed should return same value"
        );
    }

    #[test]
    fn rego_qe_measurement_uses_qe_iden_dates() {
        let mut data = make_rego_supplemental(UpToDate);
        // Set QE-specific dates different from global dates
        data.qe_iden_earliest_issue_date = 1_850_000_000;
        data.qe_iden_latest_issue_date = 1_850_100_000;
        data.qe_iden_earliest_expiration_date = 1_950_000_000;
        let m = build_qe_measurement(&data).unwrap();
        // QE measurement should use qe_iden_* dates, not the global ones
        let earliest = m.get("earliest_issue_date").unwrap().as_str().unwrap();
        let expected = "2028-08-16T"; // 1_850_000_000 = 2028-08-16T00:53:20Z
        assert!(
            earliest.starts_with(expected),
            "QE measurement should use qe_iden_earliest_issue_date, got: {earliest}"
        );
    }

    #[test]
    fn rego_policy_set_class_id_mismatch_fails() {
        let data = make_rego_supplemental(UpToDate);
        let tdx_class_id = "9eec018b-7481-4b1c-8e1a-9f7c0c8c777f";
        let policy_json = format!(
            r#"{{
                "environment": {{ "class_id": "{tdx_class_id}" }},
                "reference": {{ "accepted_tcb_status": ["UpToDate"], "collateral_grace_period": 0 }}
            }}"#
        );
        let policies = RegoPolicySet::new(&[&policy_json]).unwrap();
        let err = policies.validate(&data).unwrap_err().to_string();
        assert!(
            err.contains("appraisal failed"),
            "expected appraisal failure on class_id mismatch, got: {err}"
        );
    }
}
