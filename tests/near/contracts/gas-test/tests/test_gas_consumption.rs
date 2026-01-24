use near_api::Contract;
use near_gas::NearGas;
use near_sdk::serde_json::json;

mod constants;
mod utils;

use constants::*;
use utils::*;

#[tokio::test]
async fn test_gas_consumption() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("\n=== Starting Gas Consumption Test ===\n");

    let sandbox = near_sandbox::Sandbox::start_sandbox().await?;
    let network_config = create_network_config(&sandbox);
    let (genesis_account_id, genesis_signer) = setup_genesis_account();

    let contract_id =
        deploy_contract(&network_config, &genesis_account_id, &genesis_signer).await?;

    // Create Alice account with her secret key
    let (alice_id, alice_signer) = create_account_with_secret_key(
        &network_config,
        &genesis_account_id,
        &genesis_signer,
        "alice",
        10,
        TEST_SECRET_KEY,
    )
    .await?;

    // Get public key from the signer for display
    let alice_public_key = alice_signer.get_public_key().await?.to_string();

    println!("Testing with Alice's attestation data...");
    println!("Using public key: {alice_public_key}\n");

    // Test: dcap-qvl::verify::verify() gas consumption
    println!("--- Gas Consumption Test: dcap-qvl::verify::verify() ---");
    let result = Contract(contract_id.clone())
        .call_function(
            "verify_attestation",
            json!({
                "quote_hex": TEST_QUOTE_HEX,
                "collateral": TEST_QUOTE_COLLATERAL
            }),
        )
        .transaction()
        .gas(NearGas::from_tgas(300))
        .with_signer(alice_id.clone(), alice_signer.clone())
        .send_to(&network_config)
        .await?;

    // Access gas burnt from ExecutionResult (available even if execution failed)
    let gas_consumed = result.total_gas_burnt;

    // Print diagnostic info before checking result
    println!("Gas burnt: {} gas units", gas_consumed.as_gas());

    // Check if execution succeeded
    let _execution_outcome = result.into_result().map_err(|e| {
        eprintln!("Execution failed. Full error: {e:#?}");
        format!("Verification should succeed: {e:?}")
    })?;
    println!("Result: Success");
    println!(
        "Gas consumed: {} TGas",
        gas_consumed.as_gas() / 1_000_000_000_000
    );
    println!("Gas consumed: {} gas units", gas_consumed.as_gas());

    println!("\n=== Gas Consumption Test Complete ===\n");

    Ok(())
}
