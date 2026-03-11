# Policy Validation

After cryptographic verification, `dcap-qvl` supports a **policy validation** phase that checks the platform's TCB (Trusted Computing Base) status, advisory IDs, collateral freshness, and platform configuration flags.

## Two-Phase Verification

```
verify()  ──►  QuoteVerificationResult  ──►  validate(policy)  ──►  VerifiedReport
  │              │                              │
  │              ├─ supplemental()              ├─ SimplePolicy (built-in)
  │              │  (lazy, on demand)           ├─ RegoPolicy (Intel Rego script)
  │              │                              └─ impl Policy (custom)
  │              └─ into_report_unchecked()
  │                 (skip policy)
  crypto only      inspect data                 enforce rules
```

- **`verify()`** — performs cryptographic verification only (signature, certificate chain, CRL, QE identity). Returns `QuoteVerificationResult`.
- **`supplemental()`** — lazily builds `SupplementalData` with TCB status, advisory IDs, platform flags, etc.
- **`validate(policy)`** — applies a `Policy` to the supplemental data. Returns `VerifiedReport` on success.
- **`into_report_unchecked()`** — skips policy validation entirely (use when you handle validation externally).

## SimplePolicy

The built-in policy with 9 checks from Intel's Appraisal framework. Strict by default — only `UpToDate` status, no grace period, no advisory tolerance.

### Basic Usage

```rust
use dcap_qvl::verify::{QuoteVerifier, ring};
use dcap_qvl::SimplePolicy;

let verifier = QuoteVerifier::new_prod(ring::backend());
let result = verifier.verify(&quote, collateral, now)?;

// Strict: only UpToDate, collateral must not be expired
let report = result.validate(&SimplePolicy::strict(now))?;
```

### Builder Methods

```rust
use dcap_qvl::{SimplePolicy, TcbStatus};
use core::time::Duration;

let policy = SimplePolicy::strict(now)
    // Accept additional TCB statuses
    .allow_status(TcbStatus::SWHardeningNeeded)
    .allow_status(TcbStatus::ConfigurationNeeded)
    // Accept specific advisory IDs (case-insensitive)
    .accept_advisory("INTEL-SA-00334")
    .accept_advisory("INTEL-SA-00615")
    // Collateral freshness: accept expired collateral within grace window
    .collateral_grace_period(Duration::from_secs(30 * 24 * 3600)) // 30 days
    // Minimum TCB evaluation data number
    .min_tcb_eval_data_number(17)
    // Platform flags (default: reject True)
    .allow_dynamic_platform(true)
    .allow_cached_keys(true)
    .allow_smt(true)
    // SGX type whitelist (default: skip check)
    .accepted_sgx_types(&[0, 1]); // Standard + Scalable
```

### The 9 Checks

| # | Check | Default | Builder |
|---|-------|---------|---------|
| 1 | **TCB status whitelist** | Only `UpToDate` | `.allow_status(...)` |
| 2 | **Advisory ID whitelist** | Empty set (reject any) | `.accept_advisory(...)` |
| 3 | **Collateral expiration** | `earliest_expiration >= now` | `.collateral_grace_period(Duration)` |
| 4 | **Platform TCB freshness** | Only for OutOfDate statuses | `.platform_grace_period(Duration)` |
| 4b | **QE TCB freshness** | Only for QE `OutOfDate` | `.qe_grace_period(Duration)` |
| 5 | **Min TCB eval data number** | Skip | `.min_tcb_eval_data_number(n)` |
| 6 | **Dynamic platform flag** | Reject `True` | `.allow_dynamic_platform(true)` |
| 7 | **Cached keys flag** | Reject `True` | `.allow_cached_keys(true)` |
| 8 | **SMT flag** | Reject `True` | `.allow_smt(true)` |
| 9 | **SGX type whitelist** | Skip | `.accepted_sgx_types(&[0, 1, 2])` |

### Grace Period Behavior

**Collateral grace** (`collateral_grace_period`): Extends the collateral expiration window. If `earliest_expiration + grace >= now`, the quote is accepted. Does **not** skip advisory checks — stale collateral doesn't invalidate advisory data.

**Platform grace** (`platform_grace_period`): Applies only to the **platform** TCB level. For `OutOfDate` / `OutOfDateConfigurationNeeded`, checks `platform.tcb_date_tag + grace >= now`. For pure `OutOfDate`, only the **platform** advisories are skipped during the grace window. For `OutOfDateConfigurationNeeded`, platform advisories are still checked.

**QE grace** (`qe_grace_period`): Applies only to the **QE** TCB level. For QE `OutOfDate`, checks `qe.tcb_level.tcb_date + grace >= now`. QE advisories are skipped only while this QE grace is active.

`collateral_grace_period` is **mutually exclusive** with the TCB grace windows — setting it together with `platform_grace_period` or `qe_grace_period` causes a validation error.

### Platform Flags (Three-State)

Platform flags (`dynamic_platform`, `cached_keys`, `smt_enabled`) use `PckCertFlag` with three values:

| Value | Meaning | Default behavior |
|-------|---------|-----------------|
| `True` | Flag is set | **Rejected** |
| `False` | Flag is explicitly unset | Accepted |
| `Undefined` | Not present (Processor CA certs) | Accepted |

Only `True` is rejected by default. `False` and `Undefined` always pass.

## Custom Policy

For logic that `SimplePolicy` cannot express, implement the `Policy` trait directly:

```rust
use dcap_qvl::{Policy, SupplementalData, TcbStatus};
use anyhow::{bail, Result};

struct MyPolicy {
    now: u64,
    grace_secs: u64,
}

impl Policy for MyPolicy {
    fn validate(&self, data: &SupplementalData) -> Result<()> {
        let in_grace = data.platform.tcb_date_tag
            .saturating_add(self.grace_secs) >= self.now;

        // Conditional logic based on grace window
        if !in_grace && data.tcb.status != TcbStatus::UpToDate {
            bail!("Only UpToDate accepted outside grace period");
        }

        // Check specific advisories even during grace
        for id in &data.tcb.advisory_ids {
            if id == "INTEL-SA-00220" {
                bail!("Critical advisory {id} always rejected");
            }
        }

        Ok(())
    }
}
```

## RegoPolicy (feature: `rego`)

Runs Intel's official `qal_script.rego` via the `regorus` Rego interpreter. Accepts a JSON policy string matching Intel's format:

```rust
use dcap_qvl::RegoPolicy;

let policy_json = r#"{
    "environment": {
        "class_id": "3123ec35-8d38-4ea5-87a5-d6c48b567570"
    },
    "reference": {
        "accepted_tcb_status": ["UpToDate", "SWHardeningNeeded"],
        "collateral_grace_period": 7776000
    }
}"#;
let policy = RegoPolicy::new(policy_json)?;
let report = result.validate(&policy)?;
```

`RegoPolicySet` supports multiple JSON policies for multi-measurement appraisal (one per `class_id`), matching Intel QAL's full functionality. Both `RegoPolicy` and `RegoPolicySet` implement the `Policy` trait, so they work with the standard `validate()` method.

### Python

```python
import dcap_qvl

policy_json = r'''{
  "environment": {
    "class_id": "3123ec35-8d38-4ea5-87a5-d6c48b567570"
  },
  "reference": {
    "accepted_tcb_status": ["UpToDate"],
    "collateral_grace_period": 0
  }
}'''

policy = dcap_qvl.RegoPolicy(policy_json)
report = result.validate(policy)
```

### JS / WASM

```js
import init, { QuoteVerifier, RegoPolicy, RegoPolicySet } from "@phala/dcap-qvl-web";

await init();

const verifier = new QuoteVerifier();
const result = verifier.verify(quoteBytes, collateral, now);

const policy = new RegoPolicy(policyJson);
const report = result.validate_rego(policy);

const policySet = new RegoPolicySet([platformPolicyJson, tenantPolicyJson]);
const result2 = verifier.verify(quoteBytes, collateral, now);
const report2 = result2.validate_rego_set(policySet);
```

See [Intel's DCAP Appraisal documentation](https://github.com/intel/SGXDataCenterAttestationPrimitives) for the Rego policy JSON format.
