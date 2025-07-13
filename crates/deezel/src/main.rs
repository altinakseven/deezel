//! DEEZEL CLI - A thin wrapper around the deezel-sys library
//!
//! This crate is responsible for parsing command-line arguments and delegating
//! the actual work to the deezel-sys library. This keeps the CLI crate
//! lightweight and focused on its primary role as a user interface.

use anyhow::Result;
use clap::Parser;
use deezel_common::commands::Args;
use deezel_sys::SystemDeezel;
use deezel_common::traits::*;
use std::str::FromStr;
use hex;
use futures::future::join_all;

mod commands;
mod pretty_print;
use commands::pretty_print_json;
use deezel_common::commands::{BitcoindCommands, OrdCommands};
use pretty_print::*;


#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // Parse command-line arguments
    let args = Args::parse();

    // Initialize logger
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&args.log_level))
        .init();

    // Create a new SystemDeezel instance
    let system = SystemDeezel::new(&args).await?;

    // Execute the command
    execute_command(&system, args).await
}

async fn execute_command(system: &SystemDeezel, args: Args) -> Result<()> {
    let result: Result<(), anyhow::Error> = match args.command {
        deezel_common::commands::Commands::Bitcoind { command } => {
            let bitcoind_commands: BitcoindCommands = serde_json::from_value(serde_json::to_value(command)?)?;
            execute_bitcoind_command(system.provider(), bitcoind_commands).await
        },
        deezel_common::commands::Commands::Wallet { command } => system.execute_wallet_command(command).await.map_err(anyhow::Error::from),
        deezel_common::commands::Commands::Walletinfo { raw } => system.execute_walletinfo_command(raw).await.map_err(anyhow::Error::from),
        deezel_common::commands::Commands::Metashrew { command } => system.execute_metashrew_command(command).await.map_err(anyhow::Error::from),
        deezel_common::commands::Commands::Alkanes { command } => system.execute_alkanes_command(command).await.map_err(anyhow::Error::from),
        deezel_common::commands::Commands::Runestone { command } => system.execute_runestone_command(command).await.map_err(anyhow::Error::from),
        deezel_common::commands::Commands::Protorunes { command } => system.execute_protorunes_command(command).await.map_err(anyhow::Error::from),
        deezel_common::commands::Commands::Monitor { command } => system.execute_monitor_command(command).await.map_err(anyhow::Error::from),
        deezel_common::commands::Commands::Esplora { command } => system.execute_esplora_command(command).await.map_err(anyhow::Error::from),
        deezel_common::commands::Commands::Pgp { command } => system.execute_pgp_command(command).await.map_err(anyhow::Error::from),
        deezel_common::commands::Commands::Ord(command) => execute_ord_command(system.provider(), command).await,
    };

    result
}

async fn execute_bitcoind_command(
    provider: &dyn DeezelProvider,
    command: BitcoindCommands,
) -> anyhow::Result<()> {
    match command {
        BitcoindCommands::Getblockcount => {
            let count = <dyn DeezelProvider as BitcoinRpcProvider>::get_block_count(provider).await?;
            println!("{}", count);
        },
        BitcoindCommands::Getblock { hash, raw: _ } => {
            let hash = bitcoin::BlockHash::from_str(&hash)?;
            let block = <dyn DeezelProvider as BitcoinRpcProvider>::get_block(provider, &hash.to_string()).await?;
            println!("{}", pretty_print_json(&block));
        }
        BitcoindCommands::Getblockhash { height } => {
            let hash = <dyn DeezelProvider as BitcoinRpcProvider>::get_block_hash(provider, height).await?;
            println!("{}", hash);
        }
        BitcoindCommands::Getmempoolinfo { raw } => {
            let info = <dyn DeezelProvider as BitcoinRpcProvider>::get_mempool_info(provider).await?;
            if raw {
                println!("{}", serde_json::to_string(&info)?);
            } else {
                println!("{}", pretty_print_json(&serde_json::to_value(&info)?));
            }
        }
        BitcoindCommands::Sendrawtransaction { tx_hex } => {
            let _tx: bitcoin::Transaction =
                bitcoin::consensus::deserialize(&hex::decode(&tx_hex)?)?;
            let txid = <dyn DeezelProvider as BitcoinRpcProvider>::send_raw_transaction(provider, &tx_hex).await?;
            println!("{}", txid);
        }
        BitcoindCommands::Generatetoaddress { nblocks, address } => {
            let result = <dyn DeezelProvider as BitcoinRpcProvider>::generate_to_address(provider, nblocks, &address).await?;
            println!("{}", pretty_print_json(&result));
        },
        _ => {
            println!("This bitcoind command is not yet implemented in deezel-sys.");
        }
    }
    Ok(())
}

async fn execute_ord_command(
    provider: &dyn DeezelProvider,
    command: OrdCommands,
) -> anyhow::Result<()> {
    match command {
        OrdCommands::Inscription { id, raw } => {
            let inscription = provider.get_inscription(&id).await?;
            if raw {
                println!("{}", serde_json::to_string(&inscription)?);
            } else {
                print_inscription(&inscription);
            }
        }
        OrdCommands::InscriptionsInBlock { hash, raw } => {
            let inscriptions = provider.get_inscriptions_in_block(&hash).await?;
            if raw {
                println!("{}", serde_json::to_string(&inscriptions)?);
            } else {
                let inscription_futures = inscriptions.ids.into_iter().map(|id| {
                    let provider = provider;
                    async move { provider.get_inscription(&id.to_string()).await }
                });
                let results: Vec<_> = join_all(inscription_futures).await;
                let fetched_inscriptions: Result<Vec<_>, _> = results.into_iter().collect();
                print_inscriptions(&fetched_inscriptions?);
            }
        }
        OrdCommands::Address { address, raw } => {
            let info = provider.get_ord_address_info(&address).await?;
            if raw {
                println!("{}", serde_json::to_string(&info)?);
            } else {
                print_address_info(&info);
            }
        }
        OrdCommands::Block { query, raw } => {
            let info = provider.get_block_info(&query).await?;
            if raw {
                println!("{}", serde_json::to_string(&info)?);
            } else {
                if let Some(info) = info.info {
                    print_block_info(&info);
                } else {
                    println!("Block info not available.");
                }
            }
        }
        OrdCommands::BlockCount { raw } => {
            let info = provider.get_ord_block_count().await?;
            if raw {
                println!("{}", serde_json::to_string(&info)?);
            } else {
                println!("{}", serde_json::to_string_pretty(&info)?);
            }
        }
        OrdCommands::Blocks { raw } => {
            let info = provider.get_ord_blocks().await?;
            if raw {
                println!("{}", serde_json::to_string(&info)?);
            } else {
                print_blocks(&info);
            }
        }
        OrdCommands::Children { id, page, raw } => {
            let children = provider.get_children(&id, page).await?;
            if raw {
                println!("{}", serde_json::to_string(&children)?);
            } else {
                let inscription_futures = children.ids.into_iter().map(|id| {
                    let provider = provider;
                    async move { provider.get_inscription(&id.to_string()).await }
                });
                let results: Vec<_> = join_all(inscription_futures).await;
                let fetched_inscriptions: Result<Vec<_>, _> = results.into_iter().collect();
                print_children(&fetched_inscriptions?);
            }
        }
        OrdCommands::Content { id } => {
            let content = provider.get_content(&id).await?;
            use std::io::{self, Write};
            io::stdout().write_all(&content)?;
        }
        OrdCommands::Inscriptions { page, raw } => {
            let inscriptions = provider.get_inscriptions(page).await?;
            if raw {
                println!("{}", serde_json::to_string(&inscriptions)?);
            } else {
                let inscription_futures = inscriptions.ids.into_iter().map(|id| {
                    let provider = provider;
                    async move { provider.get_inscription(&id.to_string()).await }
                });
                let results: Vec<_> = join_all(inscription_futures).await;
                let fetched_inscriptions: Result<Vec<_>, _> = results.into_iter().collect();
                print_inscriptions(&fetched_inscriptions?);
            }
        }
        OrdCommands::Output { outpoint, raw } => {
            let output = provider.get_output(&outpoint).await?;
            if raw {
                println!("{}", serde_json::to_string(&output)?);
            } else {
                print_output(&output);
            }
        }
        OrdCommands::Parents { id, page, raw } => {
            let parents = provider.get_parents(&id, page).await?;
            if raw {
                println!("{}", serde_json::to_string(&parents)?);
            } else {
                print_parents(&parents);
            }
        }
        OrdCommands::Rune { rune, raw } => {
            let rune_info = provider.get_rune(&rune).await?;
            if raw {
                println!("{}", serde_json::to_string(&rune_info)?);
            } else {
                print_rune(&rune_info);
            }
        }
        OrdCommands::Runes { page, raw } => {
            let runes = provider.get_runes(page).await?;
            if raw {
                println!("{}", serde_json::to_string(&runes)?);
            } else {
                print_runes(&runes);
            }
        }
        OrdCommands::Sat { sat, raw } => {
            let sat_info = provider.get_sat(sat).await?;
            if raw {
                println!("{}", serde_json::to_string(&sat_info)?);
            } else {
                print_sat_response(&sat_info);
            }
        }
        OrdCommands::Tx { txid, raw } => {
            let tx_info = provider.get_tx_info(&txid).await?;
            if raw {
                println!("{}", serde_json::to_string(&tx_info)?);
            } else {
                print_tx_info(&tx_info);
            }
        }
    }
    Ok(())
}