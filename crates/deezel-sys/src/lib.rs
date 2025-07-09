//! Deezel System Library
//!
//! This library provides the system-level implementation of the deezel CLI,
//! acting as a bridge between the command-line interface and the deezel-common
//! library. It is designed to be used as a library by system crates that
//! utilize alkanes on the backend.

use anyhow::{anyhow, Context};
use deezel_common::{Result, DeezelError};
use async_trait::async_trait;
use deezel_common::provider::ConcreteProvider;
use deezel_common::traits::*;
use deezel_common::commands::*;

pub mod utils;
use utils::*;

pub struct SystemDeezel {
    provider: ConcreteProvider,
}

impl SystemDeezel {
    pub async fn new(args: &Args) -> anyhow::Result<Self> {
        // Determine network parameters based on provider and magic flags
        let network_params = if let Some(_magic) = args.magic.as_ref() {
            // For now, default to regtest when magic is provided
            // TODO: Implement proper magic parsing
            deezel_common::network::NetworkParams::regtest()
        } else {
            match args.provider.as_str() {
                "mainnet" => deezel_common::network::NetworkParams::mainnet(),
                "testnet" => deezel_common::network::NetworkParams::testnet(),
                "signet" => deezel_common::network::NetworkParams::signet(),
                "regtest" => deezel_common::network::NetworkParams::regtest(),
                _ => deezel_common::network::NetworkParams::regtest(), // Default to regtest
            }
        };

        // Generate network-specific wallet file path
        let wallet_file = if let Some(ref path) = args.wallet_file {
            expand_tilde(path)?
        } else {
            let network_name = match network_params.network {
                bitcoin::Network::Bitcoin => "mainnet",
                bitcoin::Network::Testnet => "testnet",
                bitcoin::Network::Signet => "signet",
                bitcoin::Network::Regtest => "regtest",
                _ => "custom",
            };
            // Default to GPG-encrypted .asc extension
            expand_tilde(&format!("~/.deezel/{}.json.asc", network_name))?
        };
        
        // Create wallet directory if it doesn't exist
        if let Some(parent) = std::path::Path::new(&wallet_file).parent() {
            std::fs::create_dir_all(parent)
                .context("Failed to create wallet directory")?;
        }

        // CRITICAL FIX: Always use unified Sandshrew endpoint for ALL RPC operations
        let sandshrew_rpc_url = args.sandshrew_rpc_url.clone()
            .unwrap_or_else(|| get_rpc_url(&args.provider));
        
        // Create provider with unified endpoint
        let provider = ConcreteProvider::new(
            sandshrew_rpc_url.clone(),  // Use Sandshrew for Bitcoin RPC calls
            sandshrew_rpc_url.clone(),  // Use Sandshrew for Metashrew RPC calls
            args.provider.clone(),
            Some(std::path::PathBuf::from(&wallet_file)),
        ).await?;

        // Initialize provider
        provider.initialize().await?;

        Ok(Self { provider })
    }
}

#[async_trait(?Send)]
impl System for SystemDeezel {
    fn provider(&self) -> &dyn DeezelProvider {
        &self.provider
    }
}

// Implement the individual system traits
#[async_trait(?Send)]
impl SystemWallet for SystemDeezel {
   async fn execute_wallet_command(&self, command: WalletCommands) -> deezel_common::Result<()> {
       let provider = &self.provider;
       let res: anyhow::Result<()> = match command {
            WalletCommands::Create { mnemonic } => {
                let wallet_config = WalletConfig {
                    wallet_path: "default".to_string(),
                    network: provider.get_network(),
                    bitcoin_rpc_url: "".to_string(),
                    metashrew_rpc_url: "".to_string(),
                    network_params: None,
                };
                
                println!("🔐 Creating wallet...");
                let wallet_info = provider.create_wallet(wallet_config, mnemonic, None).await?;
                
                println!("✅ Wallet created successfully!");
                if let Some(mnemonic) = wallet_info.mnemonic {
                    println!("🔑 Mnemonic: {}", mnemonic);
                    println!("⚠️  IMPORTANT: Save this mnemonic phrase in a secure location!");
                }
                
                println!("🏠 First address: {}", wallet_info.address);
                Ok(())
            },
           WalletCommands::Restore { mnemonic } => {
               let wallet_config = WalletConfig {
                   wallet_path: "default".to_string(),
                   network: provider.get_network(),
                   bitcoin_rpc_url: "".to_string(),
                   metashrew_rpc_url: "".to_string(),
                   network_params: None,
               };
               
               println!("🔐 Restoring wallet from mnemonic...");
               let wallet_info = provider.create_wallet(wallet_config, Some(mnemonic), None).await?;
               
               println!("✅ Wallet restored successfully!");
               println!("🏠 First address: {}", wallet_info.address);
               Ok(())
           },
           WalletCommands::Info => {
               let address = WalletProvider::get_address(provider).await?;
               let balance = WalletProvider::get_balance(provider).await?;
               let network = provider.get_network();
               
               println!("💼 Wallet Information");
               println!("═══════════════════");
               println!("🏠 Address: {}", address);
               println!("💰 Balance: {} sats", balance.confirmed + balance.trusted_pending + balance.untrusted_pending);
               println!("🌐 Network: {:?}", network);
               Ok(())
           },
           WalletCommands::Balance { raw } => {
               let balance = WalletProvider::get_balance(provider).await?;
               
               if raw {
                   let balance_json = serde_json::json!({
                       "confirmed": balance.confirmed,
                       "trusted_pending": balance.trusted_pending,
                       "untrusted_pending": balance.untrusted_pending,
                       "total": balance.confirmed + balance.trusted_pending + balance.untrusted_pending
                   });
                   println!("{}", serde_json::to_string_pretty(&balance_json)?);
               } else {
                   println!("💰 Wallet Balance");
                   println!("═══════════════");
                   println!("✅ Confirmed: {} sats", balance.confirmed);
                   println!("⏳ Trusted pending: {} sats", balance.trusted_pending);
                   println!("❓ Untrusted pending: {} sats", balance.untrusted_pending);
                   println!("📊 Total: {} sats", balance.confirmed + balance.trusted_pending + balance.untrusted_pending);
               }
               Ok(())
           },
           WalletCommands::Addresses { count, raw } => {
               let addresses = provider.get_addresses(count).await?;
               
               if raw {
                   // Convert to serializable format
                   let serializable_addresses: Vec<serde_json::Value> = addresses.iter().map(|addr| {
                       serde_json::json!({
                           "address": addr.address,
                           "script_type": addr.script_type,
                           "derivation_path": addr.derivation_path,
                           "index": addr.index
                       })
                   }).collect();
                   println!("{}", serde_json::to_string_pretty(&serializable_addresses)?);
               } else {
                   println!("🏠 Wallet Addresses");
                   println!("═════════════════");
                   for addr in addresses {
                       println!("{}. {} ({})", addr.index, addr.address, addr.script_type);
                       println!("   Path: {}", addr.derivation_path);
                   }
               }
               Ok(())
           },
           WalletCommands::Send { address, amount, fee_rate, send_all, from, change, yes } => {
               // Resolve address identifiers
               let resolved_address = resolve_address_identifiers(&address, provider).await?;
               let resolved_from = if let Some(from_addr) = from {
                   Some(resolve_address_identifiers(&from_addr, provider).await?)
               } else {
                   None
               };
               let resolved_change = if let Some(change_addr) = change {
                   Some(resolve_address_identifiers(&change_addr, provider).await?)
               } else {
                   None
               };
               
               let send_params = SendParams {
                   address: resolved_address,
                   amount,
                   fee_rate,
                   send_all,
                   from_address: resolved_from,
                   change_address: resolved_change,
                   auto_confirm: yes,
               };
               
               match provider.send(send_params).await {
                   Ok(txid) => {
                       println!("✅ Transaction sent successfully!");
                       println!("🔗 Transaction ID: {}", txid);
                   },
                   Err(e) => {
                       println!("❌ Failed to send transaction: {}", e);
                       return Err(e.into());
                   }
               }
               Ok(())
           },
           WalletCommands::SendAll { address, fee_rate, yes } => {
               // Resolve address identifiers
               let resolved_address = resolve_address_identifiers(&address, provider).await?;
               
               let send_params = SendParams {
                   address: resolved_address,
                   amount: 0, // Will be ignored since send_all is true
                   fee_rate,
                   send_all: true,
                   from_address: None,
                   change_address: None,
                   auto_confirm: yes,
               };
               
               match provider.send(send_params).await {
                   Ok(txid) => {
                       println!("✅ All funds sent successfully!");
                       println!("🔗 Transaction ID: {}", txid);
                   },
                   Err(e) => {
                       println!("❌ Failed to send all funds: {}", e);
                       return Err(e.into());
                   }
               }
               Ok(())
           },
           WalletCommands::CreateTx { address, amount, fee_rate, send_all, yes } => {
               // Resolve address identifiers
               let resolved_address = resolve_address_identifiers(&address, provider).await?;
               
               let create_params = SendParams {
                   address: resolved_address,
                   amount,
                   fee_rate,
                   send_all,
                   from_address: None,
                   change_address: None,
                   auto_confirm: yes,
               };
               
               match provider.create_transaction(create_params).await {
                   Ok(tx_hex) => {
                       println!("✅ Transaction created successfully!");
                       println!("📄 Transaction hex: {}", tx_hex);
                   },
                   Err(e) => {
                       println!("❌ Failed to create transaction: {}", e);
                       return Err(e.into());
                   }
               }
               Ok(())
           },
           WalletCommands::SignTx { tx_hex } => {
               match provider.sign_transaction(tx_hex).await {
                   Ok(signed_hex) => {
                       println!("✅ Transaction signed successfully!");
                       println!("📄 Signed transaction hex: {}", signed_hex);
                   },
                   Err(e) => {
                       println!("❌ Failed to sign transaction: {}", e);
                       return Err(e.into());
                   }
               }
               Ok(())
           },
           WalletCommands::BroadcastTx { tx_hex, yes } => {
               if !yes {
                   println!("⚠️  About to broadcast transaction: {}", tx_hex);
                   println!("Do you want to continue? (y/N)");
                   
                   let mut input = String::new();
                   std::io::stdin().read_line(&mut input)?;
                   
                   if !input.trim().to_lowercase().starts_with('y') {
                       println!("❌ Transaction broadcast cancelled");
                       return Ok(());
                   }
               }
               
               match provider.broadcast(&tx_hex).await {
                   Ok(txid) => {
                       println!("✅ Transaction broadcast successfully!");
                       println!("🔗 Transaction ID: {}", txid);
                   },
                   Err(e) => {
                       println!("❌ Failed to broadcast transaction: {}", e);
                       return Err(e.into());
                   }
               }
               Ok(())
           },
           WalletCommands::Utxos { raw, include_frozen, addresses } => {
               let address_list = if let Some(addr_str) = addresses {
                   let resolved_addresses = resolve_address_identifiers(&addr_str, provider).await?;
                   Some(resolved_addresses.split(',').map(|s| s.trim().to_string()).collect())
               } else {
                   None
               };
               
               let utxos = provider.get_utxos(include_frozen, address_list).await?;
               
               if raw {
                   // Convert to serializable format
                   let serializable_utxos: Vec<serde_json::Value> = utxos.iter().map(|utxo| {
                       serde_json::json!({
                           "txid": utxo.txid,
                           "vout": utxo.vout,
                           "amount": utxo.amount,
                           "address": utxo.address,
                           "confirmations": utxo.confirmations,
                           "frozen": utxo.frozen,
                           "freeze_reason": utxo.freeze_reason,
                           "block_height": utxo.block_height,
                           "has_inscriptions": utxo.has_inscriptions,
                           "has_runes": utxo.has_runes,
                           "has_alkanes": utxo.has_alkanes,
                           "is_coinbase": utxo.is_coinbase
                       })
                   }).collect();
                   println!("{}", serde_json::to_string_pretty(&serializable_utxos)?);
               } else {
                   println!("💰 Wallet UTXOs");
                   println!("═══════════════");
                   
                   if utxos.is_empty() {
                       println!("No UTXOs found");
                   } else {
                       let total_amount: u64 = utxos.iter().map(|u| u.amount).sum();
                       println!("📊 Total: {} UTXOs, {} sats\n", utxos.len(), total_amount);
                       
                       for (i, utxo) in utxos.iter().enumerate() {
                           println!("{}. 🔗 {}:{}", i + 1, utxo.txid, utxo.vout);
                           println!("   💰 Amount: {} sats", utxo.amount);
                           println!("   🏠 Address: {}", utxo.address);
                           println!("   ✅ Confirmations: {}", utxo.confirmations);
                           
                           if let Some(block_height) = utxo.block_height {
                               println!("   📦 Block: {}", block_height);
                           }
                           
                           // Show special properties
                           let mut properties = Vec::new();
                           if utxo.is_coinbase {
                               properties.push("coinbase");
                           }
                           if utxo.has_inscriptions {
                               properties.push("inscriptions");
                           }
                           if utxo.has_runes {
                               properties.push("runes");
                           }
                           if utxo.has_alkanes {
                               properties.push("alkanes");
                           }
                           if !properties.is_empty() {
                               println!("   🏷️  Properties: {}", properties.join(", "));
                           }
                           
                           if utxo.frozen {
                               println!("   ❄️  Status: FROZEN");
                               if let Some(reason) = &utxo.freeze_reason {
                                   println!("   📝 Reason: {}", reason);
                               }
                           } else {
                               println!("   ✅ Status: spendable");
                           }
                           
                           if i < utxos.len() - 1 {
                               println!();
                           }
                       }
                   }
               }
               Ok(())
           },
           WalletCommands::FreezeUtxo { utxo, reason } => {
               provider.freeze_utxo(utxo.clone(), reason).await?;
               println!("❄️  UTXO {} frozen successfully", utxo);
               Ok(())
           },
           WalletCommands::UnfreezeUtxo { utxo } => {
               provider.unfreeze_utxo(utxo.clone()).await?;
               println!("✅ UTXO {} unfrozen successfully", utxo);
               Ok(())
           },
           WalletCommands::History { count, raw, address } => {
               let resolved_address = if let Some(addr) = address {
                   Some(resolve_address_identifiers(&addr, provider).await?)
               } else {
                   None
               };
               
               let history = provider.get_history(count, resolved_address).await?;
               
               if raw {
                   // Convert to serializable format
                   let serializable_history: Vec<serde_json::Value> = history.iter().map(|tx| {
                       serde_json::json!({
                           "txid": tx.txid,
                           "block_height": tx.block_height,
                           "block_time": tx.block_time,
                           "confirmed": tx.confirmed,
                           "fee": tx.fee
                       })
                   }).collect();
                   println!("{}", serde_json::to_string_pretty(&serializable_history)?);
               } else {
                   println!("📜 Transaction History");
                   println!("═══════════════════");
                   
                   if history.is_empty() {
                       println!("No transactions found");
                   } else {
                       for (i, tx) in history.iter().enumerate() {
                           println!("{}. 🔗 TXID: {}", i + 1, tx.txid);
                           if let Some(fee) = tx.fee {
                               println!("   💰 Fee: {} sats", fee);
                           }
                           println!("   ✅ Confirmed: {}", tx.confirmed);
                           
                           if i < history.len() - 1 {
                               println!();
                           }
                       }
                   }
               }
               Ok(())
           },
           WalletCommands::TxDetails { txid, raw } => {
               let details = EsploraProvider::get_tx(provider, &txid).await?;
               
               if raw {
                   println!("{}", serde_json::to_string_pretty(&details)?);
               } else {
                   println!("📄 Transaction Details");
                   println!("════════════════════");
                   println!("🔗 TXID: {}", txid);
                   println!("{}", serde_json::to_string_pretty(&details)?);
               }
               Ok(())
           },
           WalletCommands::EstimateFee { target } => {
               let estimate = provider.estimate_fee(target).await?;
               println!("💰 Fee Estimate");
               println!("═══════════════");
               println!("🎯 Target: {} blocks", target);
               println!("💸 Fee rate: {} sat/vB", estimate.fee_rate);
               Ok(())
           },
           WalletCommands::FeeRates => {
               let rates = provider.get_fee_rates().await?;
               println!("💸 Current Fee Rates");
               println!("═══════════════════");
               println!("🚀 Fast: {} sat/vB", rates.fast);
               println!("🚶 Medium: {} sat/vB", rates.medium);
               println!("🐌 Slow: {} sat/vB", rates.slow);
               Ok(())
           },
           WalletCommands::Sync => {
               provider.sync().await?;
               println!("✅ Wallet synchronized with blockchain");
               Ok(())
           },
           WalletCommands::Backup => {
               let backup = provider.backup().await?;
               println!("💾 Wallet Backup");
               println!("═══════════════");
               println!("{}", backup);
               Ok(())
           },
           WalletCommands::ListIdentifiers => {
               let identifiers = provider.list_identifiers().await?;
               println!("🏷️  Address Identifiers");
               println!("═════════════════════");
               for identifier in identifiers {
                   println!("  {}", identifier);
               }
               Ok(())
           },
       };
       res.map_err(|e| DeezelError::Wallet(e.to_string()))
   }

    async fn execute_walletinfo_command(&self, raw: bool) -> deezel_common::Result<()> {
       let provider = &self.provider;
       let address = WalletProvider::get_address(provider).await.map_err(|e| DeezelError::Wallet(e.to_string()))?;
       let balance = WalletProvider::get_balance(provider).await.map_err(|e| DeezelError::Wallet(e.to_string()))?;
       let network = provider.get_network();
       
       if raw {
           let info = serde_json::json!({
               "address": address,
               "balance": balance.confirmed + balance.trusted_pending + balance.untrusted_pending,
               "network": format!("{:?}", network),
           });
           println!("{}", serde_json::to_string_pretty(&info).unwrap());
       } else {
           println!("💼 Wallet Information");
           println!("═══════════════════");
           println!("🏠 Address: {}", address);
           println!("💰 Balance: {} sats", balance.confirmed + balance.trusted_pending + balance.untrusted_pending);
           println!("🌐 Network: {:?}", network);
       }
       
       Ok(())
   }
}

#[async_trait(?Send)]
impl SystemBitcoind for SystemDeezel {
   async fn execute_bitcoind_command(&self, command: BitcoindCommands) -> deezel_common::Result<()> {
       let provider = &self.provider;
       let res: anyhow::Result<()> = match command {
            BitcoindCommands::Getblockcount => {
                let count = provider.get_block_count().await?;
                println!("{}", count);
                Ok(())
            },
           BitcoindCommands::Generatetoaddress { nblocks, address } => {
               // Resolve address identifiers if needed
               let resolved_address = resolve_address_identifiers(&address, provider).await?;
               
               let result = provider.generate_to_address(nblocks, &resolved_address).await?;
               println!("Generated {} blocks to address {}", nblocks, resolved_address);
               if let Some(block_hashes) = result.as_array() {
                   println!("Block hashes:");
                   for (i, hash) in block_hashes.iter().enumerate() {
                       if let Some(hash_str) = hash.as_str() {
                           println!("  {}: {}", i + 1, hash_str);
                       }
                   }
               }
               Ok(())
           },
       };
       res.map_err(|e| DeezelError::Wallet(e.to_string()))
   }
}

#[async_trait(?Send)]
impl SystemMetashrew for SystemDeezel {
   async fn execute_metashrew_command(&self, command: MetashrewCommands) -> deezel_common::Result<()> {
       let provider = &self.provider;
       let res: anyhow::Result<()> = match command {
            MetashrewCommands::Height => {
                let height = provider.get_metashrew_height().await?;
                println!("{}", height);
                Ok(())
            },
       };
       res.map_err(|e| DeezelError::Wallet(e.to_string()))
   }
}

#[async_trait(?Send)]
impl SystemAlkanes for SystemDeezel {
   async fn execute_alkanes_command(&self, command: AlkanesCommands) -> deezel_common::Result<()> {
       let provider = &self.provider;
       let res: anyhow::Result<()> = match command {
            AlkanesCommands::Execute { inputs, to, change, fee_rate, envelope, protostones, raw, trace, mine, yes, rebar } => {
                log::info!("🚀 Starting alkanes execute command with enhanced protostones encoding");
                
                // Resolve addresses in the 'to' field
                let resolved_to = resolve_address_identifiers(&to, provider).await?;
                
                // Resolve change address if provided
                let resolved_change = if let Some(change_addr) = change {
                    Some(resolve_address_identifiers(&change_addr, provider).await?)
                } else {
                    None
                };
                
                // Load envelope data if provided
                let envelope_data = if let Some(ref envelope_file) = envelope {
                    let expanded_path = expand_tilde(envelope_file)?;
                    let data = std::fs::read(&expanded_path)
                        .with_context(|| format!("Failed to read envelope file: {}", expanded_path))?;
                    log::info!("📦 Loaded envelope data: {} bytes", data.len());
                    Some(data)
                } else {
                    None
                };
                
                // Parse input requirements and protostones using deezel-common functions
                let input_requirements = if let Some(inputs_str) = &inputs {
                    use deezel_common::alkanes::execute::parse_input_requirements;
                    let parsed = parse_input_requirements(inputs_str)
                        .map_err(|e| anyhow!("Failed to parse input requirements: {}", e))?;
                    
                    // Convert from alkanes::execute types to traits types
                    parsed.into_iter().map(|req| {
                        match req {
                            deezel_common::alkanes::execute::InputRequirement::Bitcoin { amount } => {
                                deezel_common::traits::InputRequirement {
                                    requirement_type: deezel_common::traits::InputRequirementType::Bitcoin,
                                    amount,
                                    alkane_id: None,
                                }
                            },
                            deezel_common::alkanes::execute::InputRequirement::Alkanes { block, tx, amount } => {
                                deezel_common::traits::InputRequirement {
                                    requirement_type: deezel_common::traits::InputRequirementType::Alkanes,
                                    amount,
                                    alkane_id: Some(deezel_common::traits::AlkaneId { block, tx }),
                                }
                            },
                        }
                    }).collect()
                } else {
                    Vec::new()
                };
                
                let protostone_specs = {
                    use deezel_common::alkanes::execute::parse_protostones;
                    let parsed = parse_protostones(&protostones)
                        .map_err(|e| anyhow!("Failed to parse protostones: {}", e))?;
                    
                    // Convert from alkanes::execute types to traits types
                    parsed.into_iter().map(|_spec| {
                        deezel_common::traits::ProtostoneSpec {
                            name: "protostone".to_string(), // Default name
                            data: Vec::new(), // Default empty data
                            encoding: deezel_common::traits::ProtostoneEncoding::Raw, // Default encoding
                        }
                    }).collect()
                };
                
                // Split resolved_to into individual addresses
                let to_addresses: Vec<String> = resolved_to.split(',').map(|s| s.trim().to_string()).collect();
                
                // Create enhanced execute parameters with Rebar support
                let execute_params = deezel_common::traits::EnhancedExecuteParams {
                    fee_rate,
                    to_addresses,
                    change_address: resolved_change.clone(),
                    input_requirements: Some(input_requirements),
                    protostones: protostone_specs,
                    envelope_data,
                    raw_output: raw,
                    trace_enabled: trace,
                    mine_enabled: mine,
                    auto_confirm: yes,
                    rebar_enabled: rebar,
                };
                
                // For now, use the provider's alkanes execute method
                // TODO: Implement proper enhanced alkanes execution
                let alkanes_params = deezel_common::traits::AlkanesExecuteParams {
                    inputs: inputs.clone(),
                    to: resolved_to,
                    change: resolved_change,
                    fee_rate: execute_params.fee_rate,
                    envelope: envelope.map(|_| "envelope_file".to_string()), // Placeholder since we have the data
                    protostones: protostones.clone(),
                    trace: execute_params.trace_enabled,
                    mine: execute_params.mine_enabled,
                    auto_confirm: execute_params.auto_confirm,
                    rebar: execute_params.rebar_enabled,
                };
                
                match provider.execute(alkanes_params).await {
                    Ok(result) => {
                        if raw {
                            // Create a serializable version of the result
                            let serializable_result = serde_json::json!({
                                "commit_txid": result.commit_txid,
                                "reveal_txid": result.reveal_txid,
                                "commit_fee": result.commit_fee,
                                "reveal_fee": result.reveal_fee,
                                "inputs_used": result.inputs_used,
                                "outputs_created": result.outputs_created,
                                "traces": result.traces
                            });
                            println!("{}", serde_json::to_string_pretty(&serializable_result)?);
                        } else {
                            // For now, just print the result in a human-readable format
                            println!("✅ Alkanes execution completed successfully!");
                            if let Some(commit_txid) = &result.commit_txid {
                                println!("🔗 Commit TXID: {}", commit_txid);
                            }
                            println!("🔗 Reveal TXID: {}", result.reveal_txid);
                            if let Some(commit_fee) = result.commit_fee {
                                println!("💰 Commit Fee: {} sats", commit_fee);
                            }
                            println!("💰 Reveal Fee: {} sats", result.reveal_fee);
                        }
                    },
                    Err(e) => {
                        if raw {
                            eprintln!("Error: {}", e);
                        } else {
                            println!("❌ Alkanes execution failed: {}", e);
                            
                            // Check if this is a fee validation error and provide helpful context
                            let error_msg = e.to_string();
                            if error_msg.contains("absurdly high fee rate") || error_msg.contains("fee validation failed") {
                                println!("\n💡 This appears to be a fee calculation issue.");
                                println!("🔧 The fee validation system has detected an unusually high fee rate.");
                                println!("📋 This is likely due to large envelope witness data affecting transaction size calculations.");
                                println!("🛠️  Try adjusting the fee rate or check the envelope data size.");
                            }
                        }
                        return Err(e.into());
                    }
                }
                Ok(())
            },
           AlkanesCommands::Balance { address, raw } => {
               let balance_result = provider.get_alkanes_balance(address.as_deref()).await?;
               
               if raw {
                   println!("{}", serde_json::to_string_pretty(&balance_result)?);
               } else {
                   println!("🪙 Alkanes Balances");
                   println!("═══════════════════");
                   println!("{}", serde_json::to_string_pretty(&balance_result)?);
               }
               Ok(())
           },
           AlkanesCommands::TokenInfo { alkane_id, raw } => {
               // For now, return a placeholder - this would need to be implemented in the provider
               let token_info = serde_json::json!({"alkane_id": alkane_id, "status": "not_implemented"});
               
               if raw {
                   println!("{}", serde_json::to_string_pretty(&token_info)?);
               } else {
                   println!("🏷️  Alkanes Token Information");
                   println!("═══════════════════════════");
                   println!("🔗 Alkane ID: {}", alkane_id);
                   println!("📋 Token Info: {}", serde_json::to_string_pretty(&token_info)?);
               }
               Ok(())
           },
           AlkanesCommands::Trace { outpoint, raw } => {
               let (txid, vout) = parse_outpoint(&outpoint)?;
               let trace_result = provider.trace_transaction(&txid, vout, None, None).await?;
               
               if raw {
                   println!("{}", serde_json::to_string_pretty(&trace_result)?);
               } else {
                   println!("📊 Alkanes Transaction Trace");
                   println!("═══════════════════════════");
                   println!("{}", serde_json::to_string_pretty(&trace_result)?);
               }
               Ok(())
           },
           AlkanesCommands::Inspect { target, raw, disasm, fuzz, fuzz_ranges, meta, codehash } => {
               let config = deezel_common::traits::AlkanesInspectConfig {
                   disasm,
                   fuzz,
                   fuzz_ranges,
                   meta,
                   codehash,
               };
               
               let result = provider.inspect(&target, config).await?;
               
               if raw {
                   // Convert to serializable format
                   let serializable_result = serde_json::json!({
                       "alkane_id": {
                           "block": result.alkane_id.block,
                           "tx": result.alkane_id.tx
                       },
                       "bytecode_length": result.bytecode_length,
                       "disassembly": result.disassembly,
                       "metadata": result.metadata,
                       "codehash": result.codehash,
                       "fuzzing_results": result.fuzzing_results
                   });
                   println!("{}", serde_json::to_string_pretty(&serializable_result)?);
               } else {
                   println!("🔍 Alkanes Contract Inspection");
                   println!("═══════════════════════════");
                   println!("🏷️  Alkane ID: {:?}", result.alkane_id);
                   println!("📏 Bytecode length: {} bytes", result.bytecode_length);
                   
                   if let Some(disassembly) = result.disassembly {
                       println!("\n📜 Disassembly:");
                       println!("{}", disassembly);
                   }
                   
                   if let Some(metadata) = result.metadata {
                       println!("\n📋 Metadata:");
                       println!("{}", serde_json::to_string_pretty(&metadata)?);
                   }
                   
                   if let Some(codehash) = result.codehash {
                       println!("\n🔐 Code Hash: {}", codehash);
                   }
                   
                   if let Some(fuzzing_results) = result.fuzzing_results {
                       println!("\n🧪 Fuzzing Results:");
                       println!("{}", serde_json::to_string_pretty(&fuzzing_results)?);
                   }
               }
               Ok(())
           },
           AlkanesCommands::Getbytecode { alkane_id, raw } => {
               let bytecode = AlkanesProvider::get_bytecode(provider, &alkane_id).await?;
               
               if raw {
                   let json_result = serde_json::json!({
                       "alkane_id": alkane_id,
                       "bytecode": bytecode
                   });
                   println!("{}", serde_json::to_string_pretty(&json_result)?);
               } else {
                   println!("🔍 Alkanes Contract Bytecode");
                   println!("═══════════════════════════");
                   println!("🏷️  Alkane ID: {}", alkane_id);
                   
                   if bytecode.is_empty() || bytecode == "0x" {
                       println!("❌ No bytecode found for this contract");
                   } else {
                       // Remove 0x prefix if present for display
                       let clean_bytecode = bytecode.strip_prefix("0x").unwrap_or(&bytecode);
                       
                       println!("💾 Bytecode:");
                       println!("   Length: {} bytes", clean_bytecode.len() / 2);
                       println!("   Hex: {}", bytecode);
                       
                       // Show first few bytes for quick inspection
                       if clean_bytecode.len() >= 8 {
                           println!("   First 4 bytes: {}", &clean_bytecode[..8]);
                       }
                   }
               }
               Ok(())
           },
           AlkanesCommands::Simulate { contract_id, params, raw } => {
               let result = provider.simulate(&contract_id, params.as_deref()).await?;
               
               if raw {
                   println!("{}", serde_json::to_string_pretty(&result)?);
               } else {
                   println!("🧪 Alkanes Contract Simulation");
                   println!("═══════════════════════════");
                   println!("🔗 Contract ID: {}", contract_id);
                   println!("📊 Result: {}", serde_json::to_string_pretty(&result)?);
               }
               Ok(())
           },
       };
       res.map_err(|e| DeezelError::Wallet(e.to_string()))
   }
}

#[async_trait(?Send)]
impl SystemRunestone for SystemDeezel {
   async fn execute_runestone_command(&self, command: RunestoneCommands) -> deezel_common::Result<()> {
       let provider = &self.provider;
       let res: anyhow::Result<()> = match command {
            RunestoneCommands::Decode { tx_hex, raw } => {
                let tx = decode_transaction_hex(&tx_hex)?;
                analyze_runestone_tx(&tx, raw, provider).await?;
                Ok(())
            },
           RunestoneCommands::Analyze { txid, raw } => {
               let tx_hex = provider.get_transaction_hex(&txid).await?;
               let tx = decode_transaction_hex(&tx_hex)?;
               analyze_runestone_tx(&tx, raw, provider).await?;
               Ok(())
           },
       };
       res.map_err(|e| DeezelError::Wallet(e.to_string()))
   }
}

#[async_trait(?Send)]
impl SystemProtorunes for SystemDeezel {
   async fn execute_protorunes_command(&self, command: ProtorunesCommands) -> deezel_common::Result<()> {
       let provider = &self.provider;
       let res: anyhow::Result<()> = match command {
            ProtorunesCommands::ByAddress { address, raw } => {
                let result = provider.get_protorunes_by_address(&address).await?;
                
                if raw {
                    println!("{}", serde_json::to_string_pretty(&result)?);
                } else {
                    println!("🪙 Protorunes for address: {}", address);
                    println!("═══════════════════════════════════════");
                    println!("{}", serde_json::to_string_pretty(&result)?);
                }
                Ok(())
            },
           ProtorunesCommands::ByOutpoint { txid, vout, raw } => {
               let result = provider.get_protorunes_by_outpoint(&txid, vout).await?;
               
               if raw {
                   println!("{}", serde_json::to_string_pretty(&result)?);
               } else {
                   println!("🪙 Protorunes for outpoint: {}:{}", txid, vout);
                   println!("═══════════════════════════════════════");
                   println!("{}", serde_json::to_string_pretty(&result)?);
               }
               Ok(())
           },
       };
       res.map_err(|e| DeezelError::Wallet(e.to_string()))
   }
}

#[async_trait(?Send)]
impl SystemMonitor for SystemDeezel {
   async fn execute_monitor_command(&self, command: MonitorCommands) -> deezel_common::Result<()> {
       let provider = &self.provider;
       let res: anyhow::Result<()> = match command {
            MonitorCommands::Blocks { start, raw: _ } => {
                let start_height = start.unwrap_or({
                    // Get current height as default
                    0 // Placeholder - would need async context
                });
                
                println!("🔍 Monitoring blocks starting from height: {}", start_height);
                provider.monitor_blocks(start).await?;
                println!("✅ Block monitoring completed");
                Ok(())
            },
       };
       res.map_err(|e| DeezelError::Wallet(e.to_string()))
   }
}

#[async_trait(?Send)]
impl SystemEsplora for SystemDeezel {
   async fn execute_esplora_command(&self, command: EsploraCommands) -> deezel_common::Result<()> {
       let provider = &self.provider;
       let res: anyhow::Result<()> = match command {
            EsploraCommands::BlocksTipHash => {
                let hash = provider.get_blocks_tip_hash().await?;
                println!("{}", hash);
                Ok(())
            },
           EsploraCommands::BlocksTipHeight => {
               let height = provider.get_blocks_tip_height().await?;
               println!("{}", height);
               Ok(())
           },
           EsploraCommands::Blocks { start_height } => {
               let result = provider.get_blocks(start_height).await?;
               println!("{}", serde_json::to_string_pretty(&result)?);
               Ok(())
           },
           EsploraCommands::BlockHeight { height } => {
               let hash = provider.get_block_by_height(height).await?;
               println!("{}", hash);
               Ok(())
           },
           EsploraCommands::Block { hash } => {
               let block = EsploraProvider::get_block(provider, &hash).await?;
               println!("{}", serde_json::to_string_pretty(&block)?);
               Ok(())
           },
           EsploraCommands::BlockStatus { hash } => {
               let status = provider.get_block_status(&hash).await?;
               println!("{}", serde_json::to_string_pretty(&status)?);
               Ok(())
           },
           EsploraCommands::BlockTxids { hash } => {
               let txids = provider.get_block_txids(&hash).await?;
               println!("{}", serde_json::to_string_pretty(&txids)?);
               Ok(())
           },
           EsploraCommands::BlockHeader { hash } => {
               let header = provider.get_block_header(&hash).await?;
               println!("{}", header);
               Ok(())
           },
           EsploraCommands::BlockRaw { hash } => {
               let raw = provider.get_block_raw(&hash).await?;
               println!("{}", raw);
               Ok(())
           },
           EsploraCommands::BlockTxid { hash, index } => {
               let txid = provider.get_block_txid(&hash, index).await?;
               println!("{}", txid);
               Ok(())
           },
           EsploraCommands::BlockTxs { hash, start_index } => {
               let txs = provider.get_block_txs(&hash, start_index).await?;
               println!("{}", serde_json::to_string_pretty(&txs)?);
               Ok(())
           },
           EsploraCommands::Address { params } => {
               // Handle address resolution if needed
               let resolved_params = resolve_address_identifiers(&params, provider).await?;
               let result = EsploraProvider::get_address(provider, &resolved_params).await?;
               println!("{}", serde_json::to_string_pretty(&result)?);
               Ok(())
           },
           EsploraCommands::AddressTxs { params } => {
               // Handle address resolution if needed
               let resolved_params = resolve_address_identifiers(&params, provider).await?;
               let result = provider.get_address_txs(&resolved_params).await?;
               println!("{}", serde_json::to_string_pretty(&result)?);
               Ok(())
           },
           EsploraCommands::AddressTxsChain { params } => {
               // Handle address resolution for the first part (address:last_seen_txid)
               let parts: Vec<&str> = params.split(':').collect();
               let resolved_params = if parts.len() >= 2 {
                   let address_part = parts[0];
                   let resolved_address = resolve_address_identifiers(address_part, provider).await?;
                   if parts.len() == 2 {
                       format!("{}:{}", resolved_address, parts[1])
                   } else {
                       format!("{}:{}", resolved_address, parts[1..].join(":"))
                   }
               } else {
                   resolve_address_identifiers(&params, provider).await?
               };
               let result = provider.get_address_txs_chain(&resolved_params, None).await?;
               println!("{}", serde_json::to_string_pretty(&result)?);
               Ok(())
           },
           EsploraCommands::AddressTxsMempool { address } => {
               let resolved_address = resolve_address_identifiers(&address, provider).await?;
               let result = provider.get_address_txs_mempool(&resolved_address).await?;
               println!("{}", serde_json::to_string_pretty(&result)?);
               Ok(())
           },
           EsploraCommands::AddressUtxo { address } => {
               let resolved_address = resolve_address_identifiers(&address, provider).await?;
               let result = provider.get_address_utxo(&resolved_address).await?;
               println!("{}", serde_json::to_string_pretty(&result)?);
               Ok(())
           },
           
           EsploraCommands::AddressPrefix { prefix } => {
               let result = provider.get_address_prefix(&prefix).await?;
               println!("{}", serde_json::to_string_pretty(&result)?);
               Ok(())
           },
           EsploraCommands::Tx { txid } => {
               let tx = provider.get_tx(&txid).await?;
               println!("{}", serde_json::to_string_pretty(&tx)?);
               Ok(())
           },
           EsploraCommands::TxHex { txid } => {
               let hex = provider.get_tx_hex(&txid).await?;
               println!("{}", hex);
               Ok(())
           },
           EsploraCommands::TxRaw { txid } => {
               let raw = provider.get_tx_raw(&txid).await?;
               println!("{}", raw);
               Ok(())
           },
           EsploraCommands::TxStatus { txid } => {
               let status = provider.get_tx_status(&txid).await?;
               println!("{}", serde_json::to_string_pretty(&status)?);
               Ok(())
           },
           EsploraCommands::TxMerkleProof { txid } => {
               let proof = provider.get_tx_merkle_proof(&txid).await?;
               println!("{}", serde_json::to_string_pretty(&proof)?);
               Ok(())
           },
           EsploraCommands::TxMerkleblockProof { txid } => {
               let proof = provider.get_tx_merkleblock_proof(&txid).await?;
               println!("{}", proof);
               Ok(())
           },
           EsploraCommands::TxOutspend { txid, index } => {
               let outspend = provider.get_tx_outspend(&txid, index).await?;
               println!("{}", serde_json::to_string_pretty(&outspend)?);
               Ok(())
           },
           EsploraCommands::TxOutspends { txid } => {
               let outspends = provider.get_tx_outspends(&txid).await?;
               println!("{}", serde_json::to_string_pretty(&outspends)?);
               Ok(())
           },
           EsploraCommands::Broadcast { tx_hex } => {
               let txid = provider.broadcast(&tx_hex).await?;
               println!("✅ Transaction broadcast successfully!");
               println!("🔗 Transaction ID: {}", txid);
               Ok(())
           },
           EsploraCommands::PostTx { tx_hex } => {
               let txid = provider.broadcast(&tx_hex).await?;
               println!("✅ Transaction posted successfully!");
               println!("🔗 Transaction ID: {}", txid);
               Ok(())
           },
           EsploraCommands::Mempool => {
               let mempool = provider.get_mempool().await?;
               println!("{}", serde_json::to_string_pretty(&mempool)?);
               Ok(())
           },
           EsploraCommands::MempoolTxids => {
               let txids = provider.get_mempool_txids().await?;
               println!("{}", serde_json::to_string_pretty(&txids)?);
               Ok(())
           },
           EsploraCommands::MempoolRecent => {
               let recent = provider.get_mempool_recent().await?;
               println!("{}", serde_json::to_string_pretty(&recent)?);
               Ok(())
           },
           EsploraCommands::FeeEstimates => {
               let estimates = provider.get_fee_estimates().await?;
               println!("{}", serde_json::to_string_pretty(&estimates)?);
               Ok(())
           },
       };
       res.map_err(|e| DeezelError::Wallet(e.to_string()))
   }
}


/// Expand tilde (~) in file paths to home directory
fn expand_tilde(path: &str) -> Result<String> {
    if path.starts_with("~/") {
        let home = std::env::var("HOME")
            .context("HOME environment variable not set")?;
        Ok(path.replacen("~", &home, 1))
    } else {
        Ok(path.to_string())
    }
}

/// Get RPC URL for a given provider
fn get_rpc_url(provider: &str) -> String {
    match provider {
        "mainnet" => "http://bitcoinrpc:bitcoinrpc@localhost:8332".to_string(),
        "testnet" => "http://bitcoinrpc:bitcoinrpc@localhost:18332".to_string(),
        "signet" => "http://bitcoinrpc:bitcoinrpc@localhost:38332".to_string(),
        "regtest" => "http://bitcoinrpc:bitcoinrpc@localhost:18443".to_string(),
        _ => "http://bitcoinrpc:bitcoinrpc@localhost:8080".to_string(), // Default to Sandshrew
    }
}