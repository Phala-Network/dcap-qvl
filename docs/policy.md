# Policy Validation

After cryptographic verification, `dcap-qvl` supports a **policy validation** phase that checks the platform's TCB (Trusted Computing Base) status, advisory IDs, collateral freshness, and platform configuration flags.

## Claims API

```
verify_with_policy(QuotePolicy) ────────────────► QuoteClaims

The serializable `QuoteClaims` value is the boundary between DCAP verification
and application policy. A downstream service can combine claims from SGX, TDX,
or other TEE verifiers and evaluate them with its own policy engine.
```

- **`verify_with_policy()`** — uses the explicit verification time for cryptographic checks, applies the policy, and returns detailed `QuoteClaims`.
- **`QuotePolicy::claims_only(now)`** — supplies trusted time while leaving business-policy appraisal to a downstream engine.
- **`verify()`** — remains the backwards-compatible one-shot API returning `VerifiedReport`.

## QuotePolicy

The built-in policy with 10 checks inspired by Intel's Appraisal framework. Strict by default — only `UpToDate` status, no TCB grace period, no advisory blacklist.

### Basic Usage

```rust
use dcap_qvl::verify::QuoteVerifier;
use dcap_qvl::QuotePolicy;

let verifier = QuoteVerifier::new_prod();
// Strict: only UpToDate, collateral must not be expired
let claims = verifier.verify_with_policy(
    &quote, collateral, now, &QuotePolicy::strict(now),
)?;
```

### Builder Methods

```rust
use dcap_qvl::{QuotePolicy, TcbStatus};
use core::time::Duration;

let policy = QuotePolicy::strict(now)
    // Accept additional TCB statuses
    .allow_status(TcbStatus::SWHardeningNeeded)
    .allow_status(TcbStatus::ConfigurationNeeded)
    // OutOfDate must be both allowed and within the platform grace window
    .allow_status(TcbStatus::OutOfDate)
    .platform_grace_period(Duration::from_secs(30 * 24 * 3600))
    // Reject specific advisory IDs (case-insensitive)
    .reject_advisory("INTEL-SA-00334")
    .reject_advisory("INTEL-SA-00615")
    .reject_advisories(&["INTEL-SA-00809", "INTEL-SA-00820"])
    // Minimum TCB evaluation data number
    .min_tcb_eval_data_number(17)
    // Platform flags (default: reject True)
    .allow_dynamic_platform(true)
    .allow_cached_keys(true)
    .allow_smt(true)
    // SGX type whitelist (default: skip check)
    .accepted_sgx_types(&[0, 1]); // Standard + Scalable
```

### The 10 Checks

| # | Check | Default | Builder |
|---|-------|---------|---------|
| 1 | **TCB status whitelist** | Only `UpToDate` | `.allow_status(...)` |
| 2 | **Advisory ID blacklist** | Empty set (allow all) | `.reject_advisory(...)` |
| 3 | **Collateral expiration** | `earliest_expiration >= now` | Not configurable |
| 4 | **Platform TCB freshness** | Only for OutOfDate statuses | `.platform_grace_period(Duration)` |
| 4b | **QE TCB freshness** | Only for QE `OutOfDate` | `.qe_grace_period(Duration)` |
| 5 | **Min TCB eval data number** | Skip | `.min_tcb_eval_data_number(n)` |
| 6 | **Dynamic platform flag** | Reject `True` | `.allow_dynamic_platform(true)` |
| 7 | **Cached keys flag** | Reject `True` | `.allow_cached_keys(true)` |
| 8 | **SMT flag** | Reject `True` | `.allow_smt(true)` |
| 9 | **SGX type whitelist** | Skip | `.accepted_sgx_types(&[0, 1, 2])` |

### Grace Period Behavior

Expired collateral is always rejected by the cryptographic verification pipeline. There is no collateral expiration grace period.

**Platform grace** (`platform_grace_period`): Applies only to the **platform** TCB level. For `OutOfDate` / `OutOfDateConfigurationNeeded`, checks `platform.tcb_date_tag + grace >= now`. The corresponding status must also be explicitly enabled with `allow_status`; setting either option alone does not accept an out-of-date platform.

**QE grace** (`qe_grace_period`): Applies only to the **QE** TCB level. For QE `OutOfDate`, checks `qe.tcb_level.tcb_date + grace >= now`. Because the merged verdict is also out of date, the corresponding merged status must be enabled with `allow_status`.

Advisory blacklists are enforced regardless of whether a platform or QE is inside a grace window.

### Platform Flags (Three-State)

Platform flags (`dynamic_platform`, `cached_keys`, `smt_enabled`) use `PckCertFlag` with three values:

| Value | Meaning | Default behavior |
|-------|---------|-----------------|
| `True` | Flag is set | **Rejected** |
| `False` | Flag is explicitly unset | Accepted |
| `Undefined` | Not present (Processor CA certs) | Accepted |

Only `True` is rejected by default. `False` and `Undefined` always pass.

## Custom Policy

For logic that `QuotePolicy` cannot express, implement the `Policy` trait directly:

```rust
use dcap_qvl::{Policy, QuoteClaims, TcbStatus};
use anyhow::{bail, Result};

struct MyPolicy {
    now: u64,
    grace_secs: u64,
}

impl Policy for MyPolicy {
    fn validate(&self, data: &QuoteClaims) -> Result<()> {
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

## Downstream policy engines

`dcap-qvl` intentionally does not embed a Rego runtime. Export claims as JSON
and pass them to the application-wide policy layer:

```rust
let claims = verifier.verify_with_policy(
    &quote, collateral, now, &QuotePolicy::claims_only(now),
)?;
let input_json = serde_json::to_value(&claims)?;
// Evaluate `input_json` with the application's policy engine.
```

This keeps cryptographic quote verification independent from business policy and
allows one policy engine to consume normalized claims from multiple TEE platforms.
The top-level `claims_version` field versions the serialized schema.
