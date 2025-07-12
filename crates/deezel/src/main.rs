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

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // Parse command-line arguments
    let mut args = Args::parse();

    // If the provider is regtest and sandshrew_rpc_url is not set, default it.
    if args.provider == "regtest" && args.sandshrew_rpc_url.is_none() {
        args.sandshrew_rpc_url = Some("http://localhost:18888".to_string());
    }

    // Initialize logger
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&args.log_level))
        .init();

    // Create a new SystemDeezel instance
    let system = SystemDeezel::new(&args).await?;

    // Execute the command
    execute_command(&system, args).await
}

async fn execute_command(system: &SystemDeezel, args: Args) -> Result<()> {
    let result = match args.command {
        deezel_common::commands::Commands::Wallet { command } => system.execute_wallet_command(command).await,
        deezel_common::commands::Commands::Walletinfo { raw } => system.execute_walletinfo_command(raw).await,
        deezel_common::commands::Commands::Bitcoind { command } => system.execute_bitcoind_command(command).await,
        deezel_common::commands::Commands::Metashrew { command } => system.execute_metashrew_command(command).await,
        deezel_common::commands::Commands::Alkanes { command } => system.execute_alkanes_command(command).await,
        deezel_common::commands::Commands::Runestone { command } => system.execute_runestone_command(command).await,
        deezel_common::commands::Commands::Protorunes { command } => system.execute_protorunes_command(command).await,
        deezel_common::commands::Commands::Monitor { command } => system.execute_monitor_command(command).await,
        deezel_common::commands::Commands::Esplora { command } => system.execute_esplora_command(command).await,
        deezel_common::commands::Commands::Pgp { command } => system.execute_pgp_command(command).await,
    };

    result.map_err(anyhow::Error::from)
}