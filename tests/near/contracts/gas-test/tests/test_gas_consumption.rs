use std::sync::Arc;

use near_api::{AccountId, Contract, NetworkConfig, Signer};
use near_gas::NearGas;
use near_sdk::serde_json::json;

mod constants;
mod utils;

use constants::*;
use utils::*;

async fn measure(
    network_config: &NetworkConfig,
    contract_id: &AccountId,
    signer_id: &AccountId,
    signer: &Arc<Signer>,
    method: &str,
) -> Result<NearGas, Box<dyn std::error::Error + Send + Sync>> {
    let result = Contract(contract_id.clone())
        .call_function(
            method,
            json!({
                "quote_hex": TEST_QUOTE_HEX,
                "collateral": TEST_QUOTE_COLLATERAL
            }),
        )
        .transaction()
        .gas(NearGas::from_tgas(300))
        .with_signer(signer_id.clone(), signer.clone())
        .send_to(network_config)
        .await?;
    let gas = result.total_gas_burnt;
    result
        .into_result()
        .map_err(|e| format!("{method} should succeed: {e:?}"))?;
    println!(
        "{method}: {:.1} TGas ({} gas)",
        gas.as_gas() as f64 / 1e12,
        gas.as_gas()
    );
    Ok(gas)
}

#[tokio::test]
async fn test_gas_consumption() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let sandbox = near_sandbox::Sandbox::start_sandbox().await?;
    let network_config = create_network_config(&sandbox);
    let (genesis_account_id, genesis_signer) = setup_genesis_account();

    let contract_id =
        deploy_contract(&network_config, &genesis_account_id, &genesis_signer).await?;

    let (alice_id, alice_signer) = create_account_with_secret_key(
        &network_config,
        &genesis_account_id,
        &genesis_signer,
        "alice",
        10,
        TEST_SECRET_KEY,
    )
    .await?;

    let verify = measure(
        &network_config,
        &contract_id,
        &alice_id,
        &alice_signer,
        "verify",
    )
    .await?;
    let with_policy = measure(
        &network_config,
        &contract_id,
        &alice_id,
        &alice_signer,
        "verify_with_policy",
    )
    .await?;

    assert!(
        verify <= MAX_VERIFY_GAS,
        "verify gas regressed: {verify} > {MAX_VERIFY_GAS}"
    );
    let overhead = with_policy.saturating_sub(verify);
    assert!(
        overhead <= MAX_CLAIMS_OVERHEAD_GAS,
        "claims gas overhead regressed: {overhead} > {MAX_CLAIMS_OVERHEAD_GAS}"
    );
    Ok(())
}
