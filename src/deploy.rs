use anyhow::Result;
use log::debug;
use std::sync::Arc;
use crate::alkanes::AlkanesManager;
use crate::wallet::WalletManager;
use crate::alkanes::types::ContractDeployParams;

pub struct ContractDeployer {
    alkanes_manager: AlkanesManager,
}

impl ContractDeployer {
    pub fn new(rpc_client: Arc<crate::rpc::RpcClient>, wallet_manager: Arc<WalletManager>) -> Self {
        Self {
            alkanes_manager: AlkanesManager::new(rpc_client, wallet_manager),
        }
    }

    pub async fn deploy(&self, wasm_file: &str, calldata: Vec<String>, auto_confirm: bool) -> Result<()> {
        debug!("Deploying contract from {} with calldata: {:?}", wasm_file, calldata);

        let params = ContractDeployParams {
            wasm_file: wasm_file.to_string(),
            calldata,
            fee_rate: None,
            auto_confirm,
        };

        // Deploy the contract
        let result = self.alkanes_manager.contract.deploy_contract(params).await?;

        println!("alkane_id: {}:{}", result.contract_id.block, result.contract_id.tx);

        Ok(())
    }
}