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

mod commands;
use commands::pretty_print_json;
use deezel_common::commands::BitcoindCommands;


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
    };

    result
}

async fn execute_bitcoind_command(
    provider: &dyn DeezelProvider,
    command: BitcoindCommands,
) -> anyhow::Result<()> {
    match command {
        BitcoindCommands::Getblockcount => {
            let count = <dyn DeezelProvider as BitcoindProvider>::get_block_count(provider).await?;
            println!("{}", count);
        },
        BitcoindCommands::Getblockchaininfo { raw } => {
            let info = <dyn DeezelProvider as BitcoindProvider>::get_blockchain_info(provider).await?;
            if raw {
                println!("{}", serde_json::to_string(&info)?);
            } else {
                println!("{}", pretty_print_json(&serde_json::to_value(&info)?));
            }
        }
        BitcoindCommands::Getnetworkinfo { raw } => {
            let info = <dyn DeezelProvider as BitcoindProvider>::get_network_info(provider).await?;
            if raw {
                println!("{}", serde_json::to_string(&info)?);
            } else {
                println!("{}", pretty_print_json(&serde_json::to_value(&info)?));
            }
        }
        BitcoindCommands::Getrawtransaction {
            txid,
            block_hash,
            raw,
        } => {
            let txid = bitcoin::Txid::from_str(&txid)?;
            let block_hash = block_hash
                .map(|s| bitcoin::BlockHash::from_str(&s))
                .transpose()?;
            if raw {
                let tx = <dyn DeezelProvider as BitcoindProvider>::get_raw_transaction(provider, &txid, block_hash.as_ref()).await?;
                println!("{}", bitcoin::consensus::encode::serialize_hex(&tx));
            } else {
                let info = <dyn DeezelProvider as BitcoindProvider>::get_raw_transaction_info(provider, &txid, block_hash.as_ref())
                    .await?;
                println!("{}", pretty_print_json(&serde_json::to_value(&info)?));
            }
        }
        BitcoindCommands::Getblock { hash, raw } => {
            let hash = bitcoin::BlockHash::from_str(&hash)?;
            if raw {
                let block = <dyn DeezelProvider as BitcoindProvider>::get_block(provider, &hash).await?;
                println!("{}", bitcoin::consensus::encode::serialize_hex(&block));
            } else {
                let info = <dyn DeezelProvider as BitcoindProvider>::get_block_info(provider, &hash).await?;
                println!("{}", pretty_print_json(&serde_json::to_value(&info)?));
            }
        }
        BitcoindCommands::Getblockhash { height } => {
            let hash = <dyn DeezelProvider as BitcoindProvider>::get_block_hash(provider, height).await?;
            println!("{}", hash);
        }
        BitcoindCommands::Getblockheader { hash, raw } => {
            let hash = bitcoin::BlockHash::from_str(&hash)?;
            if raw {
                let header = <dyn DeezelProvider as BitcoindProvider>::get_block_header(provider, &hash).await?;
                println!("{}", bitcoin::consensus::encode::serialize_hex(&header));
            } else {
                let info = <dyn DeezelProvider as BitcoindProvider>::get_block_header_info(provider, &hash).await?;
                println!("{}", pretty_print_json(&serde_json::to_value(&info)?));
            }
        }
        BitcoindCommands::Getblockstats { hash, raw } => {
            let hash = bitcoin::BlockHash::from_str(&hash)?;
            let info = <dyn DeezelProvider as BitcoindProvider>::get_block_stats(provider, &hash).await?;
            if raw {
                println!("{}", serde_json::to_string(&info)?);
            } else {
                println!("{}", pretty_print_json(&serde_json::to_value(&info)?));
            }
        }
        BitcoindCommands::Getchaintips { raw } => {
            let info = <dyn DeezelProvider as BitcoindProvider>::get_chain_tips(provider).await?;
            if raw {
                println!("{}", serde_json::to_string(&info)?);
            } else {
                println!("{}", pretty_print_json(&serde_json::to_value(&info)?));
            }
        }
        BitcoindCommands::Getmempoolinfo { raw } => {
            let info = <dyn DeezelProvider as BitcoindProvider>::get_mempool_info(provider).await?;
            if raw {
                println!("{}", serde_json::to_string(&info)?);
            } else {
                println!("{}", pretty_print_json(&serde_json::to_value(&info)?));
            }
        }
        BitcoindCommands::Getrawmempool { raw } => {
            let info = <dyn DeezelProvider as BitcoindProvider>::get_raw_mempool(provider).await?;
            if raw {
                println!("{}", serde_json::to_string(&info)?);
            } else {
                println!("{}", pretty_print_json(&serde_json::to_value(&info)?));
            }
        }
        BitcoindCommands::Gettxout {
            txid,
            vout,
            include_mempool,
            raw,
        } => {
            let txid = bitcoin::Txid::from_str(&txid)?;
            let info = <dyn DeezelProvider as BitcoindProvider>::get_tx_out(provider, &txid, vout, include_mempool).await?;
            if raw {
                println!("{}", serde_json::to_string(&info)?);
            } else {
                println!("{}", pretty_print_json(&serde_json::to_value(&info)?));
            }
        }
        BitcoindCommands::Sendrawtransaction { tx_hex } => {
            let tx: bitcoin::Transaction =
                bitcoin::consensus::deserialize(&hex::decode(tx_hex)?)?;
            let txid = <dyn DeezelProvider as BitcoindProvider>::send_raw_transaction(provider, &tx).await?;
            println!("{}", txid);
        }
        BitcoindCommands::Generatetoaddress { nblocks, address } => {
            let result = <dyn DeezelProvider as BitcoindProvider>::generate_to_address(provider, nblocks, &address).await?;
            println!("{}", pretty_print_json(&result));
        }
    }
    Ok(())
}