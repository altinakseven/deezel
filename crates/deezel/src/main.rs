//! DEEZEL CLI - A thin wrapper around the deezel-sys library
//!
//! This crate is responsible for parsing command-line arguments and delegating
//! the actual work to the deezel-sys library. This keeps the CLI crate
//! lightweight and focused on its primary role as a user interface.

use anyhow::Result;
use clap::Parser;
use deezel_common::keystore::Keystore;
use deezel_sys::{SystemDeezel, SystemOrd};
use deezel_common::traits::*;
use futures::future::join_all;
use std::path::Path;

mod commands;
mod pretty_print;
use commands::{Alkanes, AlkanesExecute, Commands, DeezelCommands, Protorunes, Runestone};
use deezel_common::alkanes;
use pretty_print::*;


#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // Parse command-line arguments
    let mut args = DeezelCommands::parse();

    // Initialize logger
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .init();

    // Handle keystore logic
    if let Some(keystore_path) = &args.keystore {
        let keystore = Keystore::from_file(Path::new(keystore_path))?;
        let passphrase = rpassword::prompt_password("Enter passphrase: ")?;
        let mnemonic = keystore.decrypt_mnemonic(&passphrase)?;

        // Create a temporary wallet with the decrypted mnemonic
        let temp_wallet_dir = tempfile::tempdir()?;
        let temp_wallet_path = temp_wallet_dir.path().join("temp_wallet.json");
        
        let mut temp_args = args.clone();
        temp_args.keystore = Some(temp_wallet_path.to_str().unwrap().to_string());
        
        let mut temp_provider = SystemDeezel::new(&deezel_common::commands::Args::from(&temp_args)).await?;
        temp_provider.execute_wallet_command(deezel_common::commands::WalletCommands::Create {
            passphrase: Some(passphrase.clone()),
            mnemonic: Some(mnemonic),
        }).await?;
        
        args.keystore = Some(temp_wallet_path.to_str().unwrap().to_string());
    }

    // Create a new SystemDeezel instance
    let mut system = SystemDeezel::new(&deezel_common::commands::Args::from(&args)).await?;

    // Execute the command
    execute_command(&mut system, args.command).await
}

async fn execute_command<T: System + SystemOrd>(system: &mut T, command: Commands) -> Result<()> {
    match command {
        Commands::Bitcoind(cmd) => system.execute_bitcoind_command(cmd.into()).await.map_err(|e| e.into()),
        Commands::Wallet(cmd) => system.execute_wallet_command(cmd.into()).await.map_err(|e| e.into()),
        Commands::Alkanes(cmd) => execute_alkanes_command(system, cmd).await,
        Commands::Runestone(cmd) => system.execute_runestone_command(cmd.into()).await.map_err(|e| e.into()),
        Commands::Protorunes(cmd) => execute_protorunes_command(system.provider(), cmd).await,
        Commands::Ord(cmd) => system.execute_ord_command(cmd.into()).await.map_err(|e| e.into()),
    }
}

async fn execute_alkanes_command<T: System>(system: &mut T, command: Alkanes) -> Result<()> {
    match command {
        Alkanes::Execute(exec_args) => {
            let params = to_enhanced_execute_params(exec_args)?;
            let mut executor = alkanes::execute::EnhancedAlkanesExecutor::new(system.provider_mut());
            let mut state = executor.execute(params.clone()).await?;

            loop {
                state = match state {
                    alkanes::types::ExecutionState::ReadyToSign(s) => {
                        let result = executor.resume_execution(s, &params).await?;
                        println!("✅ Alkanes execution completed successfully!");
                        println!("🔗 Reveal TXID: {}", result.reveal_txid);
                        println!("💰 Reveal Fee: {} sats", result.reveal_fee);
                        if let Some(traces) = result.traces {
                            println!("🔍 Traces: {}", serde_json::to_string_pretty(&traces)?);
                        }
                        break;
                    },
                    alkanes::types::ExecutionState::ReadyToSignCommit(s) => {
                        executor.resume_commit_execution(s).await?
                    },
                    alkanes::types::ExecutionState::ReadyToSignReveal(s) => {
                        let result = executor.resume_reveal_execution(s).await?;
                        println!("✅ Alkanes execution completed successfully!");
                        if let Some(commit_txid) = result.commit_txid {
                            println!("🔗 Commit TXID: {}", commit_txid);
                        }
                        println!("🔗 Reveal TXID: {}", result.reveal_txid);
                        if let Some(commit_fee) = result.commit_fee {
                            println!("💰 Commit Fee: {} sats", commit_fee);
                        }
                        println!("💰 Reveal Fee: {} sats", result.reveal_fee);
                        if let Some(traces) = result.traces {
                            println!("🔍 Traces: {}", serde_json::to_string_pretty(&traces)?);
                        }
                        break;
                    },
                    alkanes::types::ExecutionState::Complete(result) => {
                        println!("✅ Alkanes execution completed successfully!");
                        if let Some(commit_txid) = result.commit_txid {
                            println!("🔗 Commit TXID: {}", commit_txid);
                        }
                        println!("🔗 Reveal TXID: {}", result.reveal_txid);
                        if let Some(commit_fee) = result.commit_fee {
                            println!("💰 Commit Fee: {} sats", commit_fee);
                        }
                        println!("💰 Reveal Fee: {} sats", result.reveal_fee);
                        if let Some(traces) = result.traces {
                            println!("🔍 Traces: {}", serde_json::to_string_pretty(&traces)?);
                        }
                        break;
                    }
                };
            }
            Ok(())
        },
        Alkanes::Inspect { outpoint, disasm, fuzz, fuzz_ranges, meta, codehash, raw } => {
            let config = alkanes::types::AlkanesInspectConfig {
                disasm,
                fuzz,
                fuzz_ranges,
                meta,
                codehash,
                raw,
            };
            let result = system.provider().inspect(&outpoint, config).await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                pretty_print::print_inspection_result(&result);
            }
            Ok(())
        }
    }
}

fn to_enhanced_execute_params(args: AlkanesExecute) -> Result<alkanes::types::EnhancedExecuteParams> {
    let input_requirements = args.inputs.map(|s| alkanes::parsing::parse_input_requirements(&s)).transpose()?.unwrap_or_default();
    let protostones = alkanes::parsing::parse_protostones(&args.protostones.join(" "))?;
    let envelope_data = args.envelope.map(|path| std::fs::read(path)).transpose()?;

    Ok(alkanes::types::EnhancedExecuteParams {
        input_requirements,
        to_addresses: args.to,
        from_addresses: args.from,
        change_address: args.change,
        fee_rate: args.fee_rate,
        envelope_data,
        protostones,
        raw_output: args.raw,
        trace_enabled: args.trace,
        mine_enabled: args.mine,
        auto_confirm: args.auto_confirm,
    })
}

async fn execute_runestone_command(system: &SystemDeezel, command: Runestone) -> Result<()> {
    match command {
        Runestone::Analyze { txid, raw } => {
            let tx_hex = system.provider().get_transaction_hex(&txid).await?;
            let tx_bytes = hex::decode(tx_hex)?;
            let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&tx_bytes)?;
            let result = deezel_common::runestone_enhanced::format_runestone_with_decoded_messages(&tx)?;
            
            if raw {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                deezel_common::runestone_enhanced::print_human_readable_runestone(&tx, &result);
            }
        }
    }
    Ok(())
}



async fn execute_ord_command(
    provider: &dyn DeezelProvider,
    command: deezel_common::commands::OrdCommands,
) -> anyhow::Result<()> {
    match command {
        deezel_common::commands::OrdCommands::Inscription { id, raw } => {
            if raw {
                let inscription = provider.get_inscription(&id).await?;
                let json_value = serde_json::to_value(&inscription)?;
                if let Some(s) = json_value.as_str() {
                    println!("{}", s);
                } else {
                    println!("{}", json_value);
                }
            } else {
                let inscription = provider.get_inscription(&id).await?;
                print_inscription(&inscription);
            }
        }
        deezel_common::commands::OrdCommands::InscriptionsInBlock { hash, raw } => {
            if raw {
                let inscriptions = provider.get_inscriptions_in_block(&hash).await?;
                let json_value = serde_json::to_value(&inscriptions)?;
                if let Some(s) = json_value.as_str() {
                    println!("{}", s);
                } else {
                    println!("{}", json_value);
                }
            } else {
                let inscriptions = provider.get_inscriptions_in_block(&hash).await?;
                let inscription_futures = inscriptions.ids.into_iter().map(|id| {
                    let provider = provider;
                    async move { provider.get_inscription(&id.to_string()).await }
                });
                let results: Vec<_> = join_all(inscription_futures).await;
                let fetched_inscriptions: Result<Vec<_>, _> = results.into_iter().collect();
                print_inscriptions(&fetched_inscriptions?);
            }
        }
        deezel_common::commands::OrdCommands::AddressInfo { address, raw } => {
            if raw {
                let info = provider.get_ord_address_info(&address).await?;
                let json_value = serde_json::to_value(&info)?;
                if let Some(s) = json_value.as_str() {
                    println!("{}", s);
                } else {
                    println!("{}", json_value);
                }
            } else {
                let info = provider.get_ord_address_info(&address).await?;
                print_address_info(&info);
            }
        }
        deezel_common::commands::OrdCommands::BlockInfo { query, raw } => {
            if raw {
                let info = provider.get_block_info(&query).await?;
                let json_value = serde_json::to_value(&info)?;
                if let Some(s) = json_value.as_str() {
                    println!("{}", s);
                } else {
                    println!("{}", json_value);
                }
            } else {
                let info = provider.get_block_info(&query).await?;
                if let Some(info) = info.info {
                    print_block_info(&info);
                } else {
                    println!("Block info not available.");
                }
            }
        }
        deezel_common::commands::OrdCommands::BlockCount => {
            let info = provider.get_ord_block_count().await?;
            println!("{}", serde_json::to_string_pretty(&info)?);
        }
        deezel_common::commands::OrdCommands::Blocks { raw } => {
            if raw {
                let info = provider.get_ord_blocks().await?;
                let json_value = serde_json::to_value(&info)?;
                if let Some(s) = json_value.as_str() {
                    println!("{}", s);
                } else {
                    println!("{}", json_value);
                }
            } else {
                let info = provider.get_ord_blocks().await?;
                print_blocks(&info);
            }
        }
        deezel_common::commands::OrdCommands::Children { id, page, raw } => {
            if raw {
                let children = provider.get_children(&id, page).await?;
                let json_value = serde_json::to_value(&children)?;
                if let Some(s) = json_value.as_str() {
                    println!("{}", s);
                } else {
                    println!("{}", json_value);
                }
            } else {
                let children = provider.get_children(&id, page).await?;
                let inscription_futures = children.ids.into_iter().map(|id| {
                    let provider = provider;
                    async move { provider.get_inscription(&id.to_string()).await }
                });
                let results: Vec<_> = join_all(inscription_futures).await;
                let fetched_inscriptions: Result<Vec<_>, _> = results.into_iter().collect();
                print_children(&fetched_inscriptions?);
            }
        }
        deezel_common::commands::OrdCommands::Content { id } => {
            let content = provider.get_content(&id).await?;
            use std::io::{self, Write};
            io::stdout().write_all(&content)?;
        }
        deezel_common::commands::OrdCommands::Inscriptions { page, raw } => {
            if raw {
                let inscriptions = provider.get_inscriptions(page).await?;
                let json_value = serde_json::to_value(&inscriptions)?;
                if let Some(s) = json_value.as_str() {
                    println!("{}", s);
                } else {
                    println!("{}", json_value);
                }
            } else {
                let inscriptions = provider.get_inscriptions(page).await?;
                let inscription_futures = inscriptions.ids.into_iter().map(|id| {
                    let provider = provider;
                    async move { provider.get_inscription(&id.to_string()).await }
                });
                let results: Vec<_> = join_all(inscription_futures).await;
                let fetched_inscriptions: Result<Vec<_>, _> = results.into_iter().collect();
                print_inscriptions(&fetched_inscriptions?);
            }
        }
        deezel_common::commands::OrdCommands::Output { outpoint, raw } => {
            if raw {
                let output = provider.get_output(&outpoint).await?;
                let json_value = serde_json::to_value(&output)?;
                if let Some(s) = json_value.as_str() {
                    println!("{}", s);
                } else {
                    println!("{}", json_value);
                }
            } else {
                let output = provider.get_output(&outpoint).await?;
                print_output(&output);
            }
        }
        deezel_common::commands::OrdCommands::Parents { id, page, raw } => {
            if raw {
                let parents = provider.get_parents(&id, page).await?;
                let json_value = serde_json::to_value(&parents)?;
                if let Some(s) = json_value.as_str() {
                    println!("{}", s);
                } else {
                    println!("{}", json_value);
                }
            } else {
                let parents = provider.get_parents(&id, page).await?;
                print_parents(&parents);
            }
        }
        deezel_common::commands::OrdCommands::Rune { rune, raw } => {
            if raw {
                let rune_info = provider.get_rune(&rune).await?;
                let json_value = serde_json::to_value(&rune_info)?;
                if let Some(s) = json_value.as_str() {
                    println!("{}", s);
                } else {
                    println!("{}", json_value);
                }
            } else {
                let rune_info = provider.get_rune(&rune).await?;
                print_rune(&rune_info);
            }
        }
        deezel_common::commands::OrdCommands::Runes { page, raw } => {
            if raw {
                let runes = provider.get_runes(page).await?;
                let json_value = serde_json::to_value(&runes)?;
                if let Some(s) = json_value.as_str() {
                    println!("{}", s);
                } else {
                    println!("{}", json_value);
                }
            } else {
                let runes = provider.get_runes(page).await?;
                print_runes(&runes);
            }
        }
        deezel_common::commands::OrdCommands::Sat { sat, raw } => {
            if raw {
                let sat_info = provider.get_sat(sat).await?;
                let json_value = serde_json::to_value(&sat_info)?;
                if let Some(s) = json_value.as_str() {
                    println!("{}", s);
                } else {
                    println!("{}", json_value);
                }
            } else {
                let sat_info = provider.get_sat(sat).await?;
                print_sat_response(&sat_info);
            }
        }
        deezel_common::commands::OrdCommands::TxInfo { txid, raw } => {
            if raw {
                let tx_info = provider.get_tx_info(&txid).await?;
                let json_value = serde_json::to_value(&tx_info)?;
                if let Some(s) = json_value.as_str() {
                    println!("{}", s);
                } else {
                    println!("{}", json_value);
                }
            } else {
                let tx_info = provider.get_tx_info(&txid).await?;
                print_tx_info(&tx_info);
            }
        }
    }
    Ok(())
}

async fn execute_protorunes_command(
    provider: &dyn DeezelProvider,
    command: Protorunes,
) -> anyhow::Result<()> {
    match command {
        Protorunes::ByAddress {
            address,
            raw,
            block_tag,
            protocol_tag,
        } => {
            let result = provider
                .protorunes_by_address(&address, block_tag, protocol_tag)
                .await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                pretty_print::print_protorune_wallet_response(&result);
            }
        }
        Protorunes::ByOutpoint {
            txid,
            vout,
            raw,
            block_tag,
            protocol_tag,
        } => {
            let result = provider
                .protorunes_by_outpoint(&txid, vout, block_tag, protocol_tag)
                .await?;
            if raw {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                pretty_print::print_protorune_outpoint_response(&result);
            }
        }
    }
    Ok(())
}
