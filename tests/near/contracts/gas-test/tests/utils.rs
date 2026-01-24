use near_api::signer;
use near_api::{Account, AccountId, Contract, NearToken, NetworkConfig, RPCEndpoint, Signer};
use near_sandbox::{GenesisAccount, Sandbox};
use std::sync::Arc;

// Path to the built contract WASM, relative to the test file
// The WASM is built to target/near/{package_name}/{package_name}.wasm
// where package_name has hyphens converted to underscores
const CONTRACT_WASM: &str =
    "../../../../../../target/near/gas_test/gas_test.wasm";

/// Creates a network configuration for connecting to the sandbox.
/// Creates a network configuration for connecting to the sandbox.
///
/// # Arguments
///
/// * `sandbox` - The running sandbox instance
///
/// # Returns
///
/// A `NetworkConfig` configured for the sandbox RPC endpoint.
///
/// # Panics
///
/// Panics if `sandbox.rpc_addr` cannot be parsed as a valid socket address.
#[must_use]
pub fn create_network_config(sandbox: &Sandbox) -> NetworkConfig {
    NetworkConfig {
        network_name: "sandbox".to_string(),
        rpc_endpoints: vec![RPCEndpoint::new(sandbox.rpc_addr.parse().unwrap())],
        ..NetworkConfig::testnet()
    }
}

/// Retrieves the genesis account credentials from the sandbox.
///
/// The genesis account has the initial NEAR balance and is used to
/// fund other accounts and deploy contracts.
///
/// # Returns
///
/// A tuple of (`account_id`, `signer`) for the genesis account.
///
/// # Panics
///
/// Panics if the genesis account ID cannot be parsed as a valid `AccountId`,
/// or if the private key cannot be parsed or used to create a signer.
#[must_use]
pub fn setup_genesis_account() -> (AccountId, Arc<Signer>) {
    let genesis_account_default = GenesisAccount::default();
    let genesis_account_id: AccountId = genesis_account_default
        .account_id
        .to_string()
        .parse()
        .unwrap();
    let genesis_signer: Arc<Signer> =
        Signer::from_secret_key(genesis_account_default.private_key.parse().unwrap()).unwrap();

    (genesis_account_id, genesis_signer)
}

pub async fn deploy_contract(
    network_config: &NetworkConfig,
    genesis_account_id: &AccountId,
    genesis_signer: &Arc<Signer>,
) -> Result<AccountId, Box<dyn std::error::Error + Send + Sync>> {
    let contract_id: AccountId = format!("dcap-qvl-gas-test.{genesis_account_id}").parse()?;
    let contract_secret_key = signer::generate_secret_key()?;

    let _ = Account::create_account(contract_id.clone())
        .fund_myself(genesis_account_id.clone(), NearToken::from_near(100))
        .with_public_key(contract_secret_key.public_key())
        .with_signer(genesis_signer.clone())
        .send_to(network_config)
        .await?;

    let wasm_bytes = std::fs::read(CONTRACT_WASM)?;
    let contract_signer: Arc<Signer> = Signer::from_secret_key(contract_secret_key)?;

    println!("Deploying contract...");
    Contract::deploy(contract_id.clone())
        .use_code(wasm_bytes)
        .without_init_call()
        .with_signer(contract_signer)
        .send_to(network_config)
        .await?
        .into_result()
        .map_err(|e| format!("Contract deploy failed: {e:?}"))?;

    Ok(contract_id)
}

pub async fn create_account_with_secret_key(
    network_config: &NetworkConfig,
    genesis_account_id: &AccountId,
    genesis_signer: &Arc<Signer>,
    prefix: &str,
    balance: u128,
    secret_key_str: &str,
) -> Result<(AccountId, Arc<Signer>), Box<dyn std::error::Error + Send + Sync>> {
    let account_id: AccountId = format!("{prefix}.{genesis_account_id}").parse()?;

    // Parse secret key and create signer
    let account_signer: Arc<Signer> = Signer::from_secret_key(
        secret_key_str
            .parse()
            .map_err(|e| format!("Failed to parse secret key: {e}"))?,
    )?;

    // Get public key for account creation
    let public_key = account_signer.get_public_key().await?;

    let _ = Account::create_account(account_id.clone())
        .fund_myself(genesis_account_id.clone(), NearToken::from_near(balance))
        .with_public_key(public_key)
        .with_signer(genesis_signer.clone())
        .send_to(network_config)
        .await?;

    Ok((account_id, account_signer))
}
