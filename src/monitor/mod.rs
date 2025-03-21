//! Block monitoring and transaction tracking
//!
//! This module handles:
//! - Polling for new blocks
//! - Rate limiting
//! - Transaction confirmation tracking
//! - Event notifications for new blocks

use anyhow::{Context, Result};
use log::{debug, info, warn, error};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};
use tokio::time::sleep;

use crate::rpc::RpcClient;

/// Block monitor configuration
pub struct BlockMonitorConfig {
    /// Polling interval in seconds
    pub polling_interval: u64,
    /// Maximum number of retries for failed requests
    pub max_retries: u32,
    /// Retry delay in seconds
    pub retry_delay: u64,
}

impl Default for BlockMonitorConfig {
    fn default() -> Self {
        Self {
            polling_interval: 30, // 30 seconds between polls
            max_retries: 5,       // Retry 5 times before giving up
            retry_delay: 5,       // 5 seconds between retries
        }
    }
}

/// Block monitor events
#[derive(Debug, Clone)]
pub enum BlockEvent {
    /// New block detected
    NewBlock {
        /// Block height
        height: u64,
        /// Block hash
        hash: String,
    },
    /// Transaction confirmed
    TransactionConfirmed {
        /// Transaction ID
        txid: String,
        /// Confirmation count
        confirmations: u32,
    },
    /// Error occurred
    Error(String),
}

/// Block monitor for tracking new blocks and transaction confirmations
pub struct BlockMonitor {
    /// RPC client for blockchain queries
    rpc_client: Arc<RpcClient>,
    /// Monitor configuration
    config: BlockMonitorConfig,
    /// Current block height
    current_height: Mutex<u64>,
    /// Event sender
    event_sender: mpsc::Sender<BlockEvent>,
    /// Event receiver
    event_receiver: Mutex<mpsc::Receiver<BlockEvent>>,
    /// Running flag
    running: Mutex<bool>,
}

impl BlockMonitor {
    /// Create a new block monitor
    pub fn new(rpc_client: Arc<RpcClient>, config: BlockMonitorConfig) -> Self {
        let (tx, rx) = mpsc::channel(100); // Buffer up to 100 events
        
        Self {
            rpc_client,
            config,
            current_height: Mutex::new(0),
            event_sender: tx,
            event_receiver: Mutex::new(rx),
            running: Mutex::new(false),
        }
    }
    
    /// Start monitoring for new blocks
    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.lock().await;
        if *running {
            warn!("Block monitor is already running");
            return Ok(());
        }
        
        *running = true;
        info!("Starting block monitor");
        
        // Clone necessary values for the monitoring task
        let rpc_client = Arc::clone(&self.rpc_client);
        let polling_interval = self.config.polling_interval;
        let max_retries = self.config.max_retries;
        let retry_delay = self.config.retry_delay;
        let event_sender = self.event_sender.clone();
        let current_height = Arc::new(Mutex::new(0u64)); // Create a new Mutex
        
        // Spawn a task to monitor for new blocks
        tokio::spawn(async move {
            let mut retry_count = 0;
            
            loop {
                match Self::check_for_new_block(&rpc_client, &current_height, &event_sender).await {
                    Ok(true) => {
                        // Successfully found a new block, reset retry counter
                        retry_count = 0;
                    },
                    Ok(false) => {
                        // No new block, continue polling
                        debug!("No new block found");
                    },
                    Err(e) => {
                        // Error occurred, increment retry counter
                        retry_count += 1;
                        error!("Error checking for new block: {}", e);
                        
                        if retry_count >= max_retries {
                            error!("Maximum retry count reached, stopping block monitor");
                            let _ = event_sender.send(BlockEvent::Error(
                                format!("Maximum retry count reached: {}", e)
                            )).await;
                            break;
                        }
                        
                        // Wait before retrying
                        sleep(Duration::from_secs(retry_delay)).await;
                        continue;
                    }
                }
                
                // Wait for the next polling interval
                sleep(Duration::from_secs(polling_interval)).await;
            }
        });
        
        info!("Block monitor started");
        Ok(())
    }
    
    /// Stop monitoring for new blocks
    pub async fn stop(&self) -> Result<()> {
        let mut running = self.running.lock().await;
        if !*running {
            warn!("Block monitor is not running");
            return Ok(());
        }
        
        *running = false;
        info!("Stopping block monitor");
        
        // In a real implementation, we would need to cancel the monitoring task
        
        info!("Block monitor stopped");
        Ok(())
    }
    
    /// Check for new blocks
    async fn check_for_new_block(
        rpc_client: &RpcClient,
        current_height: &Mutex<u64>,
        event_sender: &mpsc::Sender<BlockEvent>,
    ) -> Result<bool> {
        // TODO: Implement actual block checking logic using RPC client
        // This is a placeholder implementation
        
        // Get current block height from Bitcoin RPC
        let bitcoin_height = rpc_client.get_block_count().await?;
        
        // Get current block height from Metashrew RPC
        let metashrew_height = rpc_client.get_metashrew_height().await?;
        
        // Verify that Metashrew height is Bitcoin height + 1
        if metashrew_height != bitcoin_height + 1 {
            warn!(
                "Metashrew height ({}) is not Bitcoin height ({}) + 1",
                metashrew_height, bitcoin_height
            );
            // Continue anyway, but log the warning
        }
        
        // Check if we have a new block
        let mut current = current_height.lock().await;
        if bitcoin_height > *current {
            // New block found
            info!("New block detected at height {}", bitcoin_height);
            
            // Update current height
            *current = bitcoin_height;
            
            // Send new block event
            let _ = event_sender.send(BlockEvent::NewBlock {
                height: bitcoin_height,
                hash: "placeholder_hash".to_string(), // In a real implementation, we would get the actual hash
            }).await;
            
            // Return true to indicate a new block was found
            return Ok(true);
        }
        
        // No new block found
        Ok(false)
    }
    
    /// Get the event receiver for listening to block events
    pub async fn get_event_receiver(&self) -> mpsc::Sender<BlockEvent> {
        // Return a clone of the sender instead
        self.event_sender.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::{RpcClient, RpcConfig};
    
    #[tokio::test]
    async fn test_block_monitor_creation() {
        // Create RPC client
        let rpc_config = RpcConfig {
            bitcoin_rpc_url: "http://localhost:18332".to_string(),
            metashrew_rpc_url: "http://localhost:8080".to_string(),
        };
        let rpc_client = Arc::new(RpcClient::new(rpc_config));
        
        // Create block monitor
        let config = BlockMonitorConfig::default();
        let monitor = BlockMonitor::new(rpc_client, config);
        
        // Verify initial state
        let current_height = monitor.current_height.lock().await;
        assert_eq!(*current_height, 0);
    }
}