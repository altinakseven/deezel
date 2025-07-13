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
use std::io::Read;

pub mod utils;
pub mod pgp;
pub mod keystore;
pub mod bitcoind;
use utils::*;
use pgp::DeezelPgpProvider;
use keystore::{KeystoreManager, KeystoreCreateParams};

pub struct SystemDeezel {
    provider: ConcreteProvider,
    pgp_provider: DeezelPgpProvider,
    keystore_manager: KeystoreManager,
    args: Args,
}

impl SystemDeezel {
    pub async fn new(args: &Args) -> anyhow::Result<Self> {
        // Determine network parameters based on provider and magic flags
        let network_params = if let Some(magic_str) = args.magic.as_ref() {
            // Parse custom magic bytes
            match deezel_common::network::NetworkParams::from_magic_str(magic_str) {
                Ok((p2pkh_prefix, p2sh_prefix, bech32_hrp)) => {
                    // Use the base network from provider and apply custom magic bytes
                    let base_network = match args.provider.as_str() {
                        "mainnet" => bitcoin::Network::Bitcoin,
                        "testnet" => bitcoin::Network::Testnet,
                        "signet" => bitcoin::Network::Signet,
                        "regtest" => bitcoin::Network::Regtest,
                        _ => bitcoin::Network::Regtest,
                    };
                    deezel_common::network::NetworkParams::with_custom_magic(
                        base_network,
                        p2pkh_prefix,
                        p2sh_prefix,
                        bech32_hrp,
                    )
                },
                Err(e) => {
                    eprintln!("⚠️  Invalid magic bytes format: {}", e);
                    eprintln!("💡 Expected format: p2pkh_prefix,p2sh_prefix,bech32_hrp (e.g., '0x00,0x05,bc')");
                    return Err(anyhow!("Invalid magic bytes: {}", e));
                }
            }
        } else {
            // Use predefined network parameters
            match deezel_common::network::NetworkParams::from_network_str(&args.provider) {
                Ok(params) => params,
                Err(_) => {
                    eprintln!("⚠️  Unknown network: {}", args.provider);
                    eprintln!("💡 Supported networks: {}", deezel_common::network::NetworkParams::supported_networks().join(", "));
                    deezel_common::network::NetworkParams::regtest() // Default fallback
                }
            }
        };

        // FIXED: Use user-specified wallet file path or generate default
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
            // Default to keystore.json extension (not .asc since we handle encryption internally)
            expand_tilde(&format!("~/.deezel/{}.keystore.json", network_name))?
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
        let mut provider = ConcreteProvider::new(
            sandshrew_rpc_url.clone(),  // Use Sandshrew for Bitcoin RPC calls
            sandshrew_rpc_url.clone(),  // Use Sandshrew for Metashrew RPC calls
            args.esplora_url.clone(),   // Pass the new Esplora URL
            args.provider.clone(),
            Some(std::path::PathBuf::from(&wallet_file)),
        ).await?;

        if let Some(passphrase) = &args.passphrase {
            provider.set_passphrase(Some(passphrase.clone()));
        }

        // Initialize provider
        provider.initialize().await?;

        // Create PGP provider
        let pgp_provider = DeezelPgpProvider::new();

        // Create keystore manager
        let keystore_manager = KeystoreManager::new();

        Ok(Self {
            provider,
            pgp_provider,
            keystore_manager,
            args: args.clone(),
        })
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
        let mut provider = self.provider.clone(); // Clone to allow mutation for unlocking

        // Conditionally load wallet based on command requirements
        if command.requires_signing() {
            // For signing commands, ensure the full wallet is loaded, prompting for passphrase if needed
            if let deezel_common::provider::WalletState::Locked(_) = provider.get_wallet_state() {
                let passphrase = if let Some(ref pass) = self.args.passphrase {
                    pass.clone()
                } else {
                    KeystoreManager::prompt_for_passphrase("Enter passphrase to unlock keystore for signing", false)
                        .map_err(|e| DeezelError::Wallet(format!("Failed to get passphrase: {}", e)))?
                };
                provider.unlock_wallet(&passphrase).await?;
            } else if let deezel_common::provider::WalletState::None = provider.get_wallet_state() {
                 return Err(DeezelError::Wallet("No wallet found. Please create or specify a wallet file.".to_string()));
            }
        }

       let res: anyhow::Result<()> = match command {
           WalletCommands::Create { mnemonic } => {
               println!("🔐 Creating wallet with PGP-encrypted keystore...");
               
               // FIXED: Get passphrase securely from user input or CLI argument
               let passphrase = if let Some(ref pass) = self.args.passphrase {
                   pass.clone()
               } else {
                   // Prompt for passphrase securely using TUI
                   KeystoreManager::prompt_for_passphrase("Enter passphrase for keystore encryption", true)?
               };
               
               // Create keystore parameters
               let keystore_params = KeystoreCreateParams {
                   mnemonic: mnemonic.clone(),
                   passphrase: passphrase.clone(),
                   network: provider.get_network(),
                   address_count: 5, // This parameter is now unused but kept for compatibility
               };
               
               // Create the keystore
               let (keystore, mnemonic_phrase) = self.keystore_manager.create_keystore(keystore_params).await?;
               
               // FIXED: Use the wallet file path from provider (which respects --wallet-file argument)
               let wallet_file = provider.get_wallet_path()
                   .ok_or_else(|| anyhow!("No wallet file path configured"))?
                   .to_string_lossy()
                   .to_string();
               
               // Save keystore to file
               self.keystore_manager.save_keystore(&keystore, &wallet_file).await?;
                
                // Get first P2WPKH address for display using dynamic derivation
                let default_addresses = KeystoreManager::get_default_addresses(&self.keystore_manager, &keystore, provider.get_network())?;
                let first_p2wpkh = default_addresses.iter()
                    .find(|addr| addr.script_type == "p2wpkh" && addr.index == 0)
                    .map(|addr| addr.address.clone())
                    .unwrap_or_else(|| "No P2WPKH address generated".to_string());
                
                // Get network name for display
                let network_name = match provider.get_network() {
                    bitcoin::Network::Bitcoin => "mainnet",
                    bitcoin::Network::Testnet => "testnet",
                    bitcoin::Network::Signet => "signet",
                    bitcoin::Network::Regtest => "regtest",
                    _ => "custom",
                };
                
                println!("✅ Wallet keystore created successfully!");
                println!("📁 Keystore saved to: {}", wallet_file);
                println!("🔑 Mnemonic: {}", mnemonic_phrase);
                println!("⚠️  IMPORTANT: Save this mnemonic phrase in a secure location!");
                println!("🏠 First {} P2WPKH address: {}", network_name, first_p2wpkh);
                println!("🔐 Keystore is encrypted with PGP using your passphrase");
                
                // Show keystore info
                let info = self.keystore_manager.get_keystore_info(&keystore);
                println!("🔑 Master Public Key: {}", info.master_public_key);
                println!("🔍 Master Fingerprint: {}", info.master_fingerprint);
                println!("📅 Created: {}", info.created_at);
                println!("🏷️  Version: {}", info.version);
                
                println!("\n💡 Use 'deezel wallet addresses' to see all address types");
                println!("💡 Use 'deezel wallet addresses p2tr:0-10' for specific ranges");
                
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
                // Use the wallet file path from provider
                let wallet_file = provider.get_wallet_path()
                    .ok_or_else(|| anyhow!("No wallet file path configured"))?
                    .to_string_lossy()
                    .to_string();

                if !std::path::Path::new(&wallet_file).exists() {
                    println!("❌ No keystore found. Please create a wallet first using 'deezel wallet create'");
                    return Ok(());
                }

                // Load keystore metadata without requiring passphrase
                let keystore_metadata = self.keystore_manager.load_keystore_metadata_from_file(&wallet_file).await?;
                let info = self.keystore_manager.get_keystore_info(&keystore_metadata);
                let network = provider.get_network();

                println!("💼 Wallet Information (Locked)");
                println!("═════════════════════════════");
                println!("🔑 Master Public Key: {}", info.master_public_key);
                println!("🔍 Master Fingerprint: {}", info.master_fingerprint);
                println!("📅 Created: {}", chrono::DateTime::from_timestamp(info.created_at as i64, 0).map(|dt| dt.to_rfc2822()).unwrap_or_else(|| "Invalid date".to_string()));
                println!("🏷️  Version: {}", info.version);
                println!("🌐 Network: {:?}", network);

                // Display first 5 addresses of each type
                println!("\n📋 Default Addresses (derived from public key):");
                let default_addresses = self.keystore_manager.get_default_addresses_from_metadata(&keystore_metadata, network, None)?;
                
                let mut grouped_addresses: std::collections::HashMap<String, Vec<&deezel_common::traits::KeystoreAddress>> = std::collections::HashMap::new();
                for addr in &default_addresses {
                    grouped_addresses.entry(addr.script_type.clone()).or_default().push(addr);
                }

                for (script_type, addrs) in grouped_addresses {
                    println!("\n  {}:", script_type.to_uppercase());
                    for addr in addrs {
                        println!("    {}. {} (index: {})", addr.index, addr.address, addr.index);
                    }
                }

                println!("\n💡 To see balances or send transactions, unlock the wallet by providing the --passphrase argument or by running a command that requires signing (e.g., 'wallet send').");

                Ok(())
            },
           WalletCommands::Balance { raw, addresses } => {
                let address_list = if let Some(addr_str) = addresses {
                    Some(resolve_addresses(&addr_str, &provider).await?)
                } else {
                    None
                };

               let balance = WalletProvider::get_balance(&provider, address_list).await?;
               
               if raw {
                   println!("{}", serde_json::to_string_pretty(&balance)?);
               } else {
                   println!("💰 Wallet Balance");
                   println!("═══════════════");
                   println!("✅ Confirmed: {} sats", balance.confirmed);
                   println!("⏳ Pending:   {} sats", balance.pending);
                   println!("📊 Total:     {} sats", (balance.confirmed as i64 + balance.pending));
               }
               Ok(())
           },
           WalletCommands::Addresses { ranges, hd_path, network, all_networks, magic, raw } => {
                // FIXED: Use the wallet file path from provider (which respects --wallet-file argument)
                let wallet_file = provider.get_wallet_path()
                    .ok_or_else(|| anyhow!("No wallet file path configured"))?
                    .to_string_lossy()
                    .to_string();
                
                // Check if keystore exists
                if !std::path::Path::new(&wallet_file).exists() {
                    println!("❌ No keystore found. Please create a wallet first using 'deezel wallet create'");
                    return Ok(());
                }
                
                // ENHANCED: Load keystore metadata without requiring passphrase (addresses command only needs master public key)
                let keystore_metadata = self.keystore_manager.load_keystore_metadata_from_file(&wallet_file).await?;
                
                // Determine which networks to show addresses for
                let networks_to_show = if all_networks {
                    // Show addresses for all supported networks
                    vec![
                        bitcoin::Network::Bitcoin,
                        bitcoin::Network::Testnet,
                        bitcoin::Network::Signet,
                        bitcoin::Network::Regtest,
                    ]
                } else if let Some(ref network_name) = network {
                    // Show addresses for specific network
                    match deezel_common::network::NetworkParams::from_network_str(&network_name) {
                        Ok(params) => vec![params.network],
                        Err(e) => {
                            println!("❌ Invalid network '{}': {}", network_name, e);
                            println!("💡 Supported networks: {}", deezel_common::network::NetworkParams::supported_networks().join(", "));
                            return Ok(());
                        }
                    }
                } else {
                    // Default: show addresses for current provider network
                    vec![provider.get_network()]
                };
                
                // Handle custom magic bytes if provided, OR use global magic bytes from args
                let custom_network_params = if let Some(ref magic_str) = magic {
                    // Local --magic flag takes precedence
                    match deezel_common::network::NetworkParams::from_magic_str(&magic_str) {
                        Ok((p2pkh_prefix, p2sh_prefix, bech32_hrp)) => {
                            Some(deezel_common::network::NetworkParams::with_custom_magic(
                                provider.get_network(),
                                p2pkh_prefix,
                                p2sh_prefix,
                                bech32_hrp,
                            ))
                        },
                        Err(e) => {
                            println!("❌ Invalid magic bytes format: {}", e);
                            return Ok(());
                        }
                    }
                } else if let Some(ref global_magic_str) = self.args.magic {
                    // Use global -p flag magic bytes if no local --magic specified
                    match deezel_common::network::NetworkParams::from_magic_str(&global_magic_str) {
                        Ok((p2pkh_prefix, p2sh_prefix, bech32_hrp)) => {
                            Some(deezel_common::network::NetworkParams::with_custom_magic(
                                provider.get_network(),
                                p2pkh_prefix,
                                p2sh_prefix,
                                bech32_hrp,
                            ))
                        },
                        Err(_) => {
                            // If global magic parsing fails, try to get network params from provider string
                            match deezel_common::network::NetworkParams::from_network_str(&self.args.provider) {
                                Ok(params) => Some(params),
                                Err(_) => None,
                            }
                        }
                    }
                } else if self.args.provider != "regtest" {
                    // Use network params from provider if it's not the default regtest
                    match deezel_common::network::NetworkParams::from_network_str(&self.args.provider) {
                        Ok(params) => Some(params),
                        Err(_) => None,
                    }
                } else {
                    None
                };
                
                let mut all_addresses = Vec::new();
                
                for network in networks_to_show {
                    let network_name = match network {
                        bitcoin::Network::Bitcoin => "mainnet",
                        bitcoin::Network::Testnet => "testnet",
                        bitcoin::Network::Signet => "signet",
                        bitcoin::Network::Regtest => "regtest",
                        _ => "custom",
                    };
                    
                    let addresses = if let Some(range_specs) = &ranges {
                        // Parse and derive addresses for specified ranges
                        let mut network_addresses = Vec::new();
                        
                        for range_spec in range_specs {
                            let (script_type, start_index, count) = KeystoreManager::parse_address_range(&self.keystore_manager, &range_spec)?;
                            let script_types = [script_type.as_str()];
                            let derived = KeystoreManager::derive_addresses_from_metadata(&self.keystore_manager, &keystore_metadata, network, &script_types, start_index, count, custom_network_params.as_ref())?;
                            network_addresses.extend(derived);
                        }
                        
                        network_addresses
                    } else {
                        // Default behavior: show first 5 addresses of each type for current network
                        KeystoreManager::get_default_addresses_from_metadata(&self.keystore_manager, &keystore_metadata, network, custom_network_params.as_ref())?
                    };
                    
                    // Add network information to each address
                    for mut addr in addresses {
                        addr.network = Some(network_name.to_string());
                        all_addresses.push(addr);
                    }
                }
                
                if raw {
                    // Convert to serializable format
                    let serializable_addresses: Vec<serde_json::Value> = all_addresses.iter().map(|addr| {
                        serde_json::json!({
                            "address": addr.address,
                            "script_type": addr.script_type,
                            "derivation_path": addr.derivation_path,
                            "index": addr.index,
                            "network": addr.network
                        })
                    }).collect();
                    println!("{}", serde_json::to_string_pretty(&serializable_addresses)?);
                } else {
                    if all_networks {
                        println!("🏠 Wallet Addresses (All Networks)");
                    } else if let Some(network_name) = &network {
                        println!("🏠 Wallet Addresses ({})", network_name);
                    } else {
                        let current_network_name = match provider.get_network() {
                            bitcoin::Network::Bitcoin => "mainnet",
                            bitcoin::Network::Testnet => "testnet",
                            bitcoin::Network::Signet => "signet",
                            bitcoin::Network::Regtest => "regtest",
                            _ => "custom",
                        };
                        println!("🏠 Wallet Addresses ({})", current_network_name);
                    }
                    println!("═════════════════════════════");
                    
                    // Display network magic bytes when a specific network is selected
                    if let Some(ref network_name) = network {
                        if let Ok(network_params) = deezel_common::network::NetworkParams::from_network_str(network_name) {
                            println!("🔮 Network Magic Bytes:");
                            println!("   Bech32 HRP: {}", network_params.bech32_prefix);
                            println!("   P2PKH Prefix: 0x{:02x}", network_params.p2pkh_prefix);
                            println!("   P2SH Prefix: 0x{:02x}", network_params.p2sh_prefix);
                            println!("   Format: {}:{:02x}:{:02x}", network_params.bech32_prefix, network_params.p2pkh_prefix, network_params.p2sh_prefix);
                            println!();
                        }
                    }
                    
                    if let Some(ref hd_path_custom) = hd_path {
                        println!("🛤️  Custom HD Path: {}", hd_path_custom);
                        println!();
                    }
                    
                    if let Some(ref magic_str) = magic {
                        println!("🔮 Custom Magic Bytes: {}", magic_str);
                        println!();
                    }
                    
                    // Group addresses by network and script type for better display
                    let mut grouped_addresses: std::collections::HashMap<String, std::collections::HashMap<String, Vec<&deezel_common::traits::KeystoreAddress>>> = std::collections::HashMap::new();
                    for addr in &all_addresses {
                        let network_key = addr.network.as_ref().unwrap_or(&"unknown".to_string()).clone();
                        grouped_addresses.entry(network_key).or_insert_with(std::collections::HashMap::new)
                            .entry(addr.script_type.clone()).or_insert_with(Vec::new).push(addr);
                    }
                    
                    for (network_name, script_types) in grouped_addresses {
                        if all_networks {
                            println!("🌐 Network: {}", network_name.to_uppercase());
                            println!("─────────────────────");
                        }
                        
                        for (script_type, addrs) in script_types {
                            println!("📋 {} Addresses:", script_type.to_uppercase());
                            for addr in addrs {
                                println!("  {}. {} (index: {})", addr.index, addr.address, addr.index);
                                println!("     Path: {}", addr.derivation_path);
                            }
                            println!();
                        }
                        
                        if all_networks {
                            println!();
                        }
                    }
                }
                Ok(())
            },
           WalletCommands::Send { address, amount, fee_rate, send_all, from, change, yes } => {
               // Resolve address identifiers
               let resolved_address = resolve_address_identifiers(&address, &provider).await?;
               let resolved_from = if let Some(from_addr) = from {
                   Some(resolve_address_identifiers(&from_addr, &provider).await?)
               } else {
                   None
               };
               let resolved_change = if let Some(change_addr) = change {
                   Some(resolve_address_identifiers(&change_addr, &provider).await?)
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
               let resolved_address = resolve_address_identifiers(&address, &provider).await?;
               
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
               let resolved_address = resolve_address_identifiers(&address, &provider).await?;
               
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
                   let resolved_addresses = resolve_address_identifiers(&addr_str, &provider).await?;
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
                   Some(resolve_address_identifiers(&addr, &provider).await?)
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
               let details = EsploraProvider::get_tx(&provider, &txid).await?;
               
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
       let balance = WalletProvider::get_balance(provider, None).await.map_err(|e| DeezelError::Wallet(e.to_string()))?;
       let network = provider.get_network();
       
       if raw {
           let info = serde_json::json!({
               "address": address,
               "balance": balance.confirmed as i64 + balance.pending,
               "network": format!("{:?}", network),
           });
           println!("{}", serde_json::to_string_pretty(&info).unwrap());
       } else {
           println!("💼 Wallet Information");
           println!("═══════════════════");
           println!("🏠 Address: {}", address);
           println!("💰 Balance: {} sats", balance.confirmed as i64 + balance.pending);
           println!("🌐 Network: {:?}", network);
       }
       
       Ok(())
   }
}

/// Resolves a comma-separated string of addresses and identifiers into a list of concrete addresses.
async fn resolve_addresses(
    addr_str: &str,
    provider: &ConcreteProvider,
) -> anyhow::Result<Vec<String>> {
    let mut resolved_addresses = Vec::new();
    let keystore = provider.get_keystore().ok_or_else(|| anyhow!("Keystore not loaded"))?;

    for part in addr_str.split(',') {
        let trimmed_part = part.trim();
        if trimmed_part.starts_with("[self:") {
            // It's an identifier with a range, e.g., [self:p2tr:0-10]
            let inner = trimmed_part.strip_prefix("[self:").and_then(|s| s.strip_suffix("]")).ok_or_else(|| anyhow!("Invalid identifier format: {}", trimmed_part))?;
            let (script_type, start, count) = KeystoreManager::parse_address_range(&KeystoreManager::new(), inner)?;
            let derived = KeystoreManager::derive_addresses(&KeystoreManager::new(), keystore, provider.get_network(), &[&script_type], start, count)?;
            resolved_addresses.extend(derived.into_iter().map(|a| a.address));
        } else if trimmed_part.starts_with("self:") {
            // It's a single identifier, e.g., self:p2tr:50
            let inner = trimmed_part.strip_prefix("self:").ok_or_else(|| anyhow!("Invalid identifier format: {}", trimmed_part))?;
             let (script_type, start, count) = KeystoreManager::parse_address_range(&KeystoreManager::new(), inner)?;
             if count != 1 {
                 return Err(anyhow!("Single identifier format should not contain a range: {}", trimmed_part));
             }
            let derived = KeystoreManager::derive_addresses(&KeystoreManager::new(), keystore, provider.get_network(), &[&script_type], start, count)?;
            if let Some(addr) = derived.into_iter().next() {
                resolved_addresses.push(addr.address);
            }
        } else {
            // It's a concrete address
            resolved_addresses.push(trimmed_part.to_string());
        }
    }
    Ok(resolved_addresses)
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
               let trace_result = provider.trace_outpoint_json(&txid, vout).await?;
               
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
               let tx_hex = EsploraProvider::get_tx_hex(provider, &txid).await?;
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
            EsploraCommands::BlocksTipHash { raw } => {
                let hash = provider.get_blocks_tip_hash().await?;
                if raw {
                    println!("{}", serde_json::to_string(&hash)?);
                } else {
                    println!("⛓️ Tip Hash: {}", hash);
                }
                Ok(())
            },
            EsploraCommands::BlocksTipHeight { raw } => {
                let height = provider.get_blocks_tip_height().await?;
                if raw {
                    println!("{}", serde_json::to_string(&height)?);
                } else {
                    println!("📈 Tip Height: {}", height);
                }
                Ok(())
            },
            EsploraCommands::Blocks { start_height, raw } => {
                let result = provider.get_blocks(start_height).await?;
                if raw {
                    println!("{}", serde_json::to_string(&result)?);
                } else {
                    println!("📦 Blocks:\n{}", serde_json::to_string_pretty(&result)?);
                }
                Ok(())
            },
            EsploraCommands::BlockHeight { height, raw } => {
                let hash = provider.get_block_by_height(height).await?;
                if raw {
                    println!("{}", serde_json::to_string(&hash)?);
                } else {
                    println!("🔗 Block Hash at {}: {}", height, hash);
                }
                Ok(())
            },
            EsploraCommands::Block { hash, raw } => {
                let block = EsploraProvider::get_block(provider, &hash).await?;
                if raw {
                    println!("{}", serde_json::to_string(&block)?);
                } else {
                    println!("📦 Block {}:\n{}", hash, serde_json::to_string_pretty(&block)?);
                }
                Ok(())
            },
            EsploraCommands::BlockStatus { hash, raw } => {
                let status = provider.get_block_status(&hash).await?;
                if raw {
                    println!("{}", serde_json::to_string(&status)?);
                } else {
                    println!("ℹ️ Block Status {}:\n{}", hash, serde_json::to_string_pretty(&status)?);
                }
                Ok(())
            },
            EsploraCommands::BlockTxids { hash, raw } => {
                let txids = EsploraProvider::get_block_txids(provider, &hash).await?;
                if raw {
                    println!("{}", serde_json::to_string(&txids)?);
                } else {
                    println!("📄 Block Txids {}:\n{}", hash, serde_json::to_string_pretty(&txids)?);
                }
                Ok(())
            },
            EsploraCommands::BlockHeader { hash, raw } => {
                let header = EsploraProvider::get_block_header(provider, &hash).await?;
                if raw {
                    println!("{}", serde_json::to_string(&header)?);
                } else {
                    println!("📄 Block Header {}: {}", hash, header);
                }
                Ok(())
            },
            EsploraCommands::BlockRaw { hash, raw } => {
                let raw_block = provider.get_block_raw(&hash).await?;
                if raw {
                    println!("{}", serde_json::to_string(&raw_block)?);
                } else {
                    println!("📦 Raw Block {}: {}", hash, raw_block);
                }
                Ok(())
            },
            EsploraCommands::BlockTxid { hash, index, raw } => {
                let txid = provider.get_block_txid(&hash, index).await?;
                if raw {
                    println!("{}", serde_json::to_string(&txid)?);
                } else {
                    println!("📄 Txid at index {} in block {}: {}", index, hash, txid);
                }
                Ok(())
            },
            EsploraCommands::BlockTxs { hash, start_index, raw } => {
                let txs = provider.get_block_txs(&hash, start_index).await?;
                if raw {
                    println!("{}", serde_json::to_string(&txs)?);
                } else {
                    println!("📄 Transactions in block {}:\n{}", hash, serde_json::to_string_pretty(&txs)?);
                }
                Ok(())
            },
            EsploraCommands::Address { params, raw } => {
                let resolved_params = resolve_address_identifiers(&params, provider).await?;
                let result = EsploraProvider::get_address(provider, &resolved_params).await?;
                if raw {
                    println!("{}", serde_json::to_string(&result)?);
                } else {
                    println!("🏠 Address {}:\n{}", params, serde_json::to_string_pretty(&result)?);
                }
                Ok(())
            },
            EsploraCommands::AddressTxs { params, raw } => {
                let resolved_params = resolve_address_identifiers(&params, provider).await?;
                let result = provider.get_address_txs(&resolved_params).await?;
                if raw {
                    println!("{}", serde_json::to_string(&result)?);
                } else {
                    println!("📄 Transactions for address {}:\n{}", params, serde_json::to_string_pretty(&result)?);
                }
                Ok(())
            },
            EsploraCommands::AddressTxsChain { params, raw } => {
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
                if raw {
                    println!("{}", serde_json::to_string(&result)?);
                } else {
                    println!("⛓️ Chain transactions for address {}:\n{}", params, serde_json::to_string_pretty(&result)?);
                }
                Ok(())
            },
            EsploraCommands::AddressTxsMempool { address, raw } => {
                let resolved_address = resolve_address_identifiers(&address, provider).await?;
                let result = provider.get_address_txs_mempool(&resolved_address).await?;
                if raw {
                    println!("{}", serde_json::to_string(&result)?);
                } else {
                    println!("⏳ Mempool transactions for address {}:\n{}", address, serde_json::to_string_pretty(&result)?);
                }
                Ok(())
            },
            EsploraCommands::AddressUtxo { address, raw } => {
                let resolved_address = resolve_address_identifiers(&address, provider).await?;
                let result = provider.get_address_utxo(&resolved_address).await?;
                if raw {
                    println!("{}", serde_json::to_string(&result)?);
                } else {
                    println!("💰 UTXOs for address {}:\n{}", address, serde_json::to_string_pretty(&result)?);
                }
                Ok(())
            },
            EsploraCommands::AddressPrefix { prefix, raw } => {
                let result = provider.get_address_prefix(&prefix).await?;
                if raw {
                    println!("{}", serde_json::to_string(&result)?);
                } else {
                    println!("🔍 Addresses with prefix '{}':\n{}", prefix, serde_json::to_string_pretty(&result)?);
                }
                Ok(())
            },
            EsploraCommands::Tx { txid, raw } => {
                let tx = provider.get_tx(&txid).await?;
                if raw {
                    println!("{}", serde_json::to_string(&tx)?);
                } else {
                    println!("📄 Transaction {}:\n{}", txid, serde_json::to_string_pretty(&tx)?);
                }
                Ok(())
            },
            EsploraCommands::TxHex { txid, raw } => {
                let hex = provider.get_tx_hex(&txid).await?;
                if raw {
                    println!("{}", serde_json::to_string(&hex)?);
                } else {
                    println!("📄 Hex for tx {}: {}", txid, hex);
                }
                Ok(())
            },
            EsploraCommands::TxRaw { txid, raw } => {
                let raw_tx = provider.get_tx_raw(&txid).await?;
                if raw {
                    println!("{}", serde_json::to_string(&raw_tx)?);
                } else {
                    println!("📄 Raw tx {}: {}", txid, raw_tx);
                }
                Ok(())
            },
            EsploraCommands::TxStatus { txid, raw } => {
                let status = provider.get_tx_status(&txid).await?;
                if raw {
                    println!("{}", serde_json::to_string(&status)?);
                } else {
                    println!("ℹ️ Status for tx {}:\n{}", txid, serde_json::to_string_pretty(&status)?);
                }
                Ok(())
            },
            EsploraCommands::TxMerkleProof { txid, raw } => {
                let proof = provider.get_tx_merkle_proof(&txid).await?;
                if raw {
                    println!("{}", serde_json::to_string(&proof)?);
                } else {
                    println!("🧾 Merkle proof for tx {}:\n{}", txid, serde_json::to_string_pretty(&proof)?);
                }
                Ok(())
            },
            EsploraCommands::TxMerkleblockProof { txid, raw } => {
                let proof = provider.get_tx_merkleblock_proof(&txid).await?;
                if raw {
                    println!("{}", serde_json::to_string(&proof)?);
                } else {
                    println!("🧾 Merkleblock proof for tx {}: {}", txid, proof);
                }
                Ok(())
            },
            EsploraCommands::TxOutspend { txid, index, raw } => {
                let outspend = provider.get_tx_outspend(&txid, index).await?;
                if raw {
                    println!("{}", serde_json::to_string(&outspend)?);
                } else {
                    println!("💸 Outspend for tx {}, vout {}:\n{}", txid, index, serde_json::to_string_pretty(&outspend)?);
                }
                Ok(())
            },
            EsploraCommands::TxOutspends { txid, raw } => {
                let outspends = provider.get_tx_outspends(&txid).await?;
                if raw {
                    println!("{}", serde_json::to_string(&outspends)?);
                } else {
                    println!("💸 Outspends for tx {}:\n{}", txid, serde_json::to_string_pretty(&outspends)?);
                }
                Ok(())
            },
            EsploraCommands::Broadcast { tx_hex, raw: _ } => {
                let txid = provider.broadcast(&tx_hex).await?;
                println!("✅ Transaction broadcast successfully!");
                println!("🔗 Transaction ID: {}", txid);
                Ok(())
            },
            EsploraCommands::PostTx { tx_hex, raw: _ } => {
                let txid = provider.broadcast(&tx_hex).await?;
                println!("✅ Transaction posted successfully!");
                println!("🔗 Transaction ID: {}", txid);
                Ok(())
            },
            EsploraCommands::Mempool { raw } => {
                let mempool = provider.get_mempool().await?;
                if raw {
                    println!("{}", serde_json::to_string(&mempool)?);
                } else {
                    println!("⏳ Mempool Info:\n{}", serde_json::to_string_pretty(&mempool)?);
                }
                Ok(())
            },
            EsploraCommands::MempoolTxids { raw } => {
                let txids = provider.get_mempool_txids().await?;
                if raw {
                    println!("{}", serde_json::to_string(&txids)?);
                } else {
                    println!("📄 Mempool Txids:\n{}", serde_json::to_string_pretty(&txids)?);
                }
                Ok(())
            },
            EsploraCommands::MempoolRecent { raw } => {
                let recent = provider.get_mempool_recent().await?;
                if raw {
                    println!("{}", serde_json::to_string(&recent)?);
                } else {
                    println!("📄 Recent Mempool Txs:\n{}", serde_json::to_string_pretty(&recent)?);
                }
                Ok(())
            },
            EsploraCommands::FeeEstimates { raw } => {
                let estimates = provider.get_fee_estimates().await?;
                if raw {
                    println!("{}", serde_json::to_string(&estimates)?);
                } else {
                    println!("💰 Fee Estimates:\n{}", serde_json::to_string_pretty(&estimates)?);
                }
                Ok(())
            },
        };
        res.map_err(|e| DeezelError::Wallet(e.to_string()))
    }
}

#[async_trait(?Send)]
impl SystemPgp for SystemDeezel {
   async fn execute_pgp_command(&self, command: deezel_common::commands::PgpCommands) -> deezel_common::Result<()> {
       let pgp_provider = &self.pgp_provider;
       let res: anyhow::Result<()> = match command {
            deezel_common::commands::PgpCommands::GenerateKey { user_id, passphrase, raw } => {
                println!("🔐 Generating PGP key pair...");
                let keypair = pgp_provider.generate_keypair(&user_id, passphrase.as_deref()).await?;
                
                if raw {
                    let keypair_json = serde_json::json!({
                        "fingerprint": keypair.fingerprint,
                        "key_id": keypair.key_id,
                        "user_ids": keypair.public_key.user_ids,
                        "creation_time": keypair.public_key.creation_time,
                        "algorithm": keypair.public_key.algorithm
                    });
                    println!("{}", serde_json::to_string_pretty(&keypair_json)?);
                } else {
                    println!("✅ PGP key pair generated successfully!");
                    println!("🔑 Fingerprint: {}", keypair.fingerprint);
                    println!("🆔 Key ID: {}", keypair.key_id);
                    println!("👤 User ID: {}", keypair.public_key.user_ids.join(", "));
                    println!("📅 Created: {}", keypair.public_key.creation_time);
                }
                Ok(())
            },
            deezel_common::commands::PgpCommands::ImportKey { key_file, raw } => {
                let key_data = if key_file == "-" {
                    // Read from stdin
                    let mut buffer = String::new();
                    std::io::stdin().read_to_string(&mut buffer)?;
                    buffer
                } else {
                    // Read from file
                    let expanded_path = expand_tilde(&key_file)?;
                    std::fs::read_to_string(&expanded_path)
                        .with_context(|| format!("Failed to read key file: {}", expanded_path))?
                };
                
                println!("📥 Importing PGP key...");
                let key = pgp_provider.import_key(&key_data).await?;
                
                if raw {
                    let key_json = serde_json::json!({
                        "fingerprint": key.fingerprint,
                        "key_id": key.key_id,
                        "user_ids": key.user_ids,
                        "is_private": key.is_private,
                        "creation_time": key.creation_time,
                        "algorithm": key.algorithm
                    });
                    println!("{}", serde_json::to_string_pretty(&key_json)?);
                } else {
                    println!("✅ PGP key imported successfully!");
                    println!("🔑 Fingerprint: {}", key.fingerprint);
                    println!("🆔 Key ID: {}", key.key_id);
                    println!("👤 User IDs: {}", key.user_ids.join(", "));
                    println!("🔒 Type: {}", if key.is_private { "Private" } else { "Public" });
                }
                Ok(())
            },
            deezel_common::commands::PgpCommands::ExportKey { identifier, private, output, raw: _ } => {
                // For now, this is a placeholder since we don't have key storage
                println!("📤 Export key functionality not yet implemented");
                println!("🔍 Would export key: {}", identifier);
                println!("🔒 Include private: {}", private);
                if let Some(output_file) = output {
                    println!("📁 Output to: {}", output_file);
                }
                Ok(())
            },
            deezel_common::commands::PgpCommands::ListKeys { private, public, raw } => {
                println!("📋 Listing PGP keys...");
                let keys = pgp_provider.list_pgp_keys().await?;
                
                let filtered_keys: Vec<_> = keys.iter().filter(|key| {
                    if private && public {
                        true // Show all keys
                    } else if private {
                        key.is_private
                    } else if public {
                        !key.is_private
                    } else {
                        true // Show all keys by default
                    }
                }).collect();
                
                if raw {
                    println!("{}", serde_json::to_string_pretty(&filtered_keys)?);
                } else {
                    if filtered_keys.is_empty() {
                        println!("No keys found");
                    } else {
                        println!("Found {} key(s):", filtered_keys.len());
                        for (i, key) in filtered_keys.iter().enumerate() {
                            println!("{}. 🔑 {}", i + 1, key.fingerprint);
                            println!("   🆔 Key ID: {}", key.key_id);
                            println!("   👤 User IDs: {}", key.user_ids.join(", "));
                            println!("   🔒 Type: {}", if key.is_private { "Private" } else { "Public" });
                            println!("   📅 Created: {}", key.creation_time);
                            if let Some(exp) = key.expiration_time {
                                println!("   ⏰ Expires: {}", exp);
                            }
                            if i < filtered_keys.len() - 1 {
                                println!();
                            }
                        }
                    }
                }
                Ok(())
            },
            deezel_common::commands::PgpCommands::DeleteKey { identifier, yes } => {
                if !yes {
                    println!("⚠️  About to delete key: {}", identifier);
                    println!("Do you want to continue? (y/N)");
                    
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input)?;
                    
                    if !input.trim().to_lowercase().starts_with('y') {
                        println!("❌ Key deletion cancelled");
                        return Ok(());
                    }
                }
                
                pgp_provider.delete_key(&identifier).await?;
                println!("✅ Key deleted successfully: {}", identifier);
                Ok(())
            },
            deezel_common::commands::PgpCommands::Encrypt { input, output, recipients, armor, sign, sign_key: _, passphrase: _ } => {
                println!("🔐 PGP encrypt functionality not yet fully implemented");
                println!("📥 Input: {}", input);
                if let Some(output_file) = output {
                    println!("📤 Output: {}", output_file);
                }
                println!("👥 Recipients: {}", recipients);
                println!("🛡️  Armor: {}", armor);
                println!("✍️  Sign: {}", sign);
                Ok(())
            },
            deezel_common::commands::PgpCommands::Decrypt { input, output, key, passphrase: _, verify, signer: _ } => {
                println!("🔓 PGP decrypt functionality not yet fully implemented");
                println!("📥 Input: {}", input);
                if let Some(output_file) = output {
                    println!("📤 Output: {}", output_file);
                }
                println!("🔑 Key: {}", key);
                println!("✅ Verify: {}", verify);
                Ok(())
            },
            deezel_common::commands::PgpCommands::Sign { input, output, key, passphrase: _, armor, detached } => {
                println!("✍️  PGP sign functionality not yet fully implemented");
                println!("📥 Input: {}", input);
                if let Some(output_file) = output {
                    println!("📤 Output: {}", output_file);
                }
                println!("🔑 Key: {}", key);
                println!("🛡️  Armor: {}", armor);
                println!("📎 Detached: {}", detached);
                Ok(())
            },
            deezel_common::commands::PgpCommands::Verify { input, signature, key, raw: _ } => {
                println!("✅ PGP verify functionality not yet fully implemented");
                println!("📥 Input: {}", input);
                if let Some(sig_file) = signature {
                    println!("📝 Signature: {}", sig_file);
                }
                println!("🔑 Key: {}", key);
                Ok(())
            },
            deezel_common::commands::PgpCommands::ChangePassphrase { identifier, old_passphrase: _, new_passphrase: _ } => {
                println!("🔐 Change passphrase functionality not yet fully implemented");
                println!("🔑 Key: {}", identifier);
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