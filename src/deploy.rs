use anyhow::Result;
use std::sync::Arc;
use crate::alkanes::AlkanesManager;
use crate::wallet::WalletManager;
use crate::alkanes::types::ContractDeployParams;

pub struct AmmDeployer {
    alkanes_manager: AlkanesManager,
}

impl AmmDeployer {
    pub fn new(rpc_client: Arc<crate::rpc::RpcClient>, wallet_manager: Arc<WalletManager>) -> Self {
        Self {
            alkanes_manager: AlkanesManager::new(rpc_client, wallet_manager),
        }
    }

    pub async fn deploy(&self) -> Result<()> {
        println!("Deploying AMM contract...");

        let params = ContractDeployParams {
            wasm_file: "out/alkanes.wasm".to_string(),
            calldata: vec![],
            fee_rate: None,
        };

        // Deploy the contract
        let result = self.alkanes_manager.contract.deploy_contract(params).await?;

        println!("✅ AMM contract deployed successfully!");
        println!("🔗 Transaction ID: {}", result.txid);
        println!("💰 Fee: {}", result.fee);
        println!("🏷️  Alkane ID: {}:{}", result.contract_id.block, result.contract_id.tx);

        Ok(())
    }
}