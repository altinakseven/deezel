//! Collectible (NFT) support
//!
//! This module provides functionality for:
//! - NFT creation and minting
//! - NFT transfers
//! - Collection management
//! - Transaction construction

use anyhow::{Context, Result, anyhow};
use bdk::bitcoin::{Address, Network, OutPoint, Script, Transaction, TxOut};
use bdk::bitcoin::psbt::Psbt;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

use crate::account::Account;
use crate::rpc::RpcClient;
use crate::signer::Signer;
use crate::utils::{GatheredUtxos, UtxoInfo, DUST_OUTPUT_VALUE};

/// Collectible information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collectible {
    /// Collectible ID
    pub id: String,
    /// Collectible inscription ID
    pub inscription_id: String,
    /// Collectible number
    pub number: u64,
    /// Collectible address
    pub address: String,
    /// Collectible output
    pub output: String,
    /// Collectible content type
    pub content_type: String,
    /// Collectible content length
    pub content_length: u64,
    /// Collectible timestamp
    pub timestamp: u64,
    /// Collectible genesis transaction
    pub genesis_transaction: String,
    /// Collectible genesis fee
    pub genesis_fee: u64,
    /// Collectible location
    pub location: String,
    /// Collectible offset
    pub offset: u64,
    /// Collectible value
    pub value: u64,
    /// Collectible collection ID
    pub collection_id: Option<String>,
    /// Collectible metadata
    pub metadata: Option<CollectibleMetadata>,
}

/// Collectible metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectibleMetadata {
    /// Collectible name
    pub name: Option<String>,
    /// Collectible description
    pub description: Option<String>,
    /// Collectible attributes
    pub attributes: Option<Vec<CollectibleAttribute>>,
    /// Collectible image
    pub image: Option<String>,
    /// Collectible animation URL
    pub animation_url: Option<String>,
    /// Collectible external URL
    pub external_url: Option<String>,
}

/// Collectible attribute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectibleAttribute {
    /// Attribute trait type
    pub trait_type: String,
    /// Attribute value
    pub value: String,
}

/// Collection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collection {
    /// Collection ID
    pub id: String,
    /// Collection name
    pub name: String,
    /// Collection description
    pub description: Option<String>,
    /// Collection image
    pub image: Option<String>,
    /// Collection creator
    pub creator: Option<String>,
    /// Collection size
    pub size: u64,
    /// Collection items
    pub items: Vec<Collectible>,
}

/// Collectible operation type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CollectibleOperation {
    /// Create a new collectible
    Create,
    /// Transfer a collectible
    Transfer,
}

/// Collectible manager for NFT operations
pub struct CollectibleManager {
    /// RPC client
    rpc_client: RpcClient,
    /// Network
    network: Network,
}

impl CollectibleManager {
    /// Create a new Collectible manager
    pub fn new(rpc_client: RpcClient, network: Network) -> Self {
        Self {
            rpc_client,
            network,
        }
    }
    
    /// Get collectible information
    pub async fn get_collectible_info(&self, inscription_id: &str) -> Result<Collectible> {
        // Call ord_inscription RPC method
        let result = self.rpc_client._call(
            "ord_inscription",
            serde_json::json!([inscription_id]),
        ).await?;
        
        // Parse response
        let id = result.get("id")
            .and_then(|i| i.as_str())
            .ok_or_else(|| anyhow!("Invalid response: missing id"))?
            .to_string();
        
        let inscription_id = result.get("inscription_id")
            .and_then(|i| i.as_str())
            .ok_or_else(|| anyhow!("Invalid response: missing inscription_id"))?
            .to_string();
        
        let number = result.get("number")
            .and_then(|n| n.as_u64())
            .ok_or_else(|| anyhow!("Invalid response: missing number"))?;
        
        let address = result.get("address")
            .and_then(|a| a.as_str())
            .ok_or_else(|| anyhow!("Invalid response: missing address"))?
            .to_string();
        
        let output = result.get("output")
            .and_then(|o| o.as_str())
            .ok_or_else(|| anyhow!("Invalid response: missing output"))?
            .to_string();
        
        let content_type = result.get("content_type")
            .and_then(|c| c.as_str())
            .ok_or_else(|| anyhow!("Invalid response: missing content_type"))?
            .to_string();
        
        let content_length = result.get("content_length")
            .and_then(|c| c.as_u64())
            .ok_or_else(|| anyhow!("Invalid response: missing content_length"))?;
        
        let timestamp = result.get("timestamp")
            .and_then(|t| t.as_u64())
            .ok_or_else(|| anyhow!("Invalid response: missing timestamp"))?;
        
        let genesis_transaction = result.get("genesis_transaction")
            .and_then(|g| g.as_str())
            .ok_or_else(|| anyhow!("Invalid response: missing genesis_transaction"))?
            .to_string();
        
        let genesis_fee = result.get("genesis_fee")
            .and_then(|g| g.as_u64())
            .ok_or_else(|| anyhow!("Invalid response: missing genesis_fee"))?;
        
        let location = result.get("location")
            .and_then(|l| l.as_str())
            .ok_or_else(|| anyhow!("Invalid response: missing location"))?
            .to_string();
        
        let offset = result.get("offset")
            .and_then(|o| o.as_u64())
            .ok_or_else(|| anyhow!("Invalid response: missing offset"))?;
        
        let value = result.get("value")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow!("Invalid response: missing value"))?;
        
        let collection_id = result.get("collection_id")
            .and_then(|c| c.as_str())
            .map(|s| s.to_string());
        
        // Parse metadata if present
        let metadata = if let Some(metadata_obj) = result.get("metadata").and_then(|m| m.as_object()) {
            let name = metadata_obj.get("name")
                .and_then(|n| n.as_str())
                .map(|s| s.to_string());
            
            let description = metadata_obj.get("description")
                .and_then(|d| d.as_str())
                .map(|s| s.to_string());
            
            let image = metadata_obj.get("image")
                .and_then(|i| i.as_str())
                .map(|s| s.to_string());
            
            let animation_url = metadata_obj.get("animation_url")
                .and_then(|a| a.as_str())
                .map(|s| s.to_string());
            
            let external_url = metadata_obj.get("external_url")
                .and_then(|e| e.as_str())
                .map(|s| s.to_string());
            
            // Parse attributes if present
            let attributes = if let Some(attrs_array) = metadata_obj.get("attributes").and_then(|a| a.as_array()) {
                let mut attrs = Vec::new();
                
                for attr in attrs_array {
                    if let (Some(trait_type), Some(value)) = (
                        attr.get("trait_type").and_then(|t| t.as_str()),
                        attr.get("value").and_then(|v| v.as_str()),
                    ) {
                        attrs.push(CollectibleAttribute {
                            trait_type: trait_type.to_string(),
                            value: value.to_string(),
                        });
                    }
                }
                
                if attrs.is_empty() {
                    None
                } else {
                    Some(attrs)
                }
            } else {
                None
            };
            
            Some(CollectibleMetadata {
                name,
                description,
                attributes,
                image,
                animation_url,
                external_url,
            })
        } else {
            None
        };
        
        Ok(Collectible {
            id,
            inscription_id,
            number,
            address,
            output,
            content_type,
            content_length,
            timestamp,
            genesis_transaction,
            genesis_fee,
            location,
            offset,
            value,
            collection_id,
            metadata,
        })
    }
    
    /// Get collectibles for an address
    pub async fn get_collectibles(&self, address: &str) -> Result<Vec<Collectible>> {
        // Call ord_inscriptions_by_address RPC method
        let result = self.rpc_client._call(
            "ord_inscriptions_by_address",
            serde_json::json!([address]),
        ).await?;
        
        // Parse response
        let inscriptions = result.as_array()
            .ok_or_else(|| anyhow!("Invalid response: expected array"))?;
        
        let mut collectibles = Vec::new();
        
        for inscription in inscriptions {
            let id = inscription.get("id")
                .and_then(|i| i.as_str())
                .ok_or_else(|| anyhow!("Invalid inscription: missing id"))?
                .to_string();
            
            let inscription_id = inscription.get("inscription_id")
                .and_then(|i| i.as_str())
                .ok_or_else(|| anyhow!("Invalid inscription: missing inscription_id"))?
                .to_string();
            
            let number = inscription.get("number")
                .and_then(|n| n.as_u64())
                .ok_or_else(|| anyhow!("Invalid inscription: missing number"))?;
            
            let address = inscription.get("address")
                .and_then(|a| a.as_str())
                .ok_or_else(|| anyhow!("Invalid inscription: missing address"))?
                .to_string();
            
            let output = inscription.get("output")
                .and_then(|o| o.as_str())
                .ok_or_else(|| anyhow!("Invalid inscription: missing output"))?
                .to_string();
            
            let content_type = inscription.get("content_type")
                .and_then(|c| c.as_str())
                .ok_or_else(|| anyhow!("Invalid inscription: missing content_type"))?
                .to_string();
            
            let content_length = inscription.get("content_length")
                .and_then(|c| c.as_u64())
                .ok_or_else(|| anyhow!("Invalid inscription: missing content_length"))?;
            
            let timestamp = inscription.get("timestamp")
                .and_then(|t| t.as_u64())
                .ok_or_else(|| anyhow!("Invalid inscription: missing timestamp"))?;
            
            let genesis_transaction = inscription.get("genesis_transaction")
                .and_then(|g| g.as_str())
                .ok_or_else(|| anyhow!("Invalid inscription: missing genesis_transaction"))?
                .to_string();
            
            let genesis_fee = inscription.get("genesis_fee")
                .and_then(|g| g.as_u64())
                .ok_or_else(|| anyhow!("Invalid inscription: missing genesis_fee"))?;
            
            let location = inscription.get("location")
                .and_then(|l| l.as_str())
                .ok_or_else(|| anyhow!("Invalid inscription: missing location"))?
                .to_string();
            
            let offset = inscription.get("offset")
                .and_then(|o| o.as_u64())
                .ok_or_else(|| anyhow!("Invalid inscription: missing offset"))?;
            
            let value = inscription.get("value")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow!("Invalid inscription: missing value"))?;
            
            let collection_id = inscription.get("collection_id")
                .and_then(|c| c.as_str())
                .map(|s| s.to_string());
            
            // Parse metadata if present
            let metadata = if let Some(metadata_obj) = inscription.get("metadata").and_then(|m| m.as_object()) {
                let name = metadata_obj.get("name")
                    .and_then(|n| n.as_str())
                    .map(|s| s.to_string());
                
                let description = metadata_obj.get("description")
                    .and_then(|d| d.as_str())
                    .map(|s| s.to_string());
                
                let image = metadata_obj.get("image")
                    .and_then(|i| i.as_str())
                    .map(|s| s.to_string());
                
                let animation_url = metadata_obj.get("animation_url")
                    .and_then(|a| a.as_str())
                    .map(|s| s.to_string());
                
                let external_url = metadata_obj.get("external_url")
                    .and_then(|e| e.as_str())
                    .map(|s| s.to_string());
                
                // Parse attributes if present
                let attributes = if let Some(attrs_array) = metadata_obj.get("attributes").and_then(|a| a.as_array()) {
                    let mut attrs = Vec::new();
                    
                    for attr in attrs_array {
                        if let (Some(trait_type), Some(value)) = (
                            attr.get("trait_type").and_then(|t| t.as_str()),
                            attr.get("value").and_then(|v| v.as_str()),
                        ) {
                            attrs.push(CollectibleAttribute {
                                trait_type: trait_type.to_string(),
                                value: value.to_string(),
                            });
                        }
                    }
                    
                    if attrs.is_empty() {
                        None
                    } else {
                        Some(attrs)
                    }
                } else {
                    None
                };
                
                Some(CollectibleMetadata {
                    name,
                    description,
                    attributes,
                    image,
                    animation_url,
                    external_url,
                })
            } else {
                None
            };
            
            collectibles.push(Collectible {
                id,
                inscription_id,
                number,
                address,
                output,
                content_type,
                content_length,
                timestamp,
                genesis_transaction,
                genesis_fee,
                location,
                offset,
                value,
                collection_id,
                metadata,
            });
        }
        
        Ok(collectibles)
    }
    
    /// Get collection information
    pub async fn get_collection_info(&self, collection_id: &str) -> Result<Collection> {
        // Call ord_collection RPC method
        let result = self.rpc_client._call(
            "ord_collection",
            serde_json::json!([collection_id]),
        ).await?;
        
        // Parse response
        let id = result.get("id")
            .and_then(|i| i.as_str())
            .ok_or_else(|| anyhow!("Invalid response: missing id"))?
            .to_string();
        
        let name = result.get("name")
            .and_then(|n| n.as_str())
            .ok_or_else(|| anyhow!("Invalid response: missing name"))?
            .to_string();
        
        let description = result.get("description")
            .and_then(|d| d.as_str())
            .map(|s| s.to_string());
        
        let image = result.get("image")
            .and_then(|i| i.as_str())
            .map(|s| s.to_string());
        
        let creator = result.get("creator")
            .and_then(|c| c.as_str())
            .map(|s| s.to_string());
        
        let size = result.get("size")
            .and_then(|s| s.as_u64())
            .ok_or_else(|| anyhow!("Invalid response: missing size"))?;
        
        // Parse items if present
        let items = if let Some(items_array) = result.get("items").and_then(|i| i.as_array()) {
            let mut collectibles = Vec::new();
            
            for item in items_array {
                let id = item.get("id")
                    .and_then(|i| i.as_str())
                    .ok_or_else(|| anyhow!("Invalid item: missing id"))?
                    .to_string();
                
                let inscription_id = item.get("inscription_id")
                    .and_then(|i| i.as_str())
                    .ok_or_else(|| anyhow!("Invalid item: missing inscription_id"))?
                    .to_string();
                
                let number = item.get("number")
                    .and_then(|n| n.as_u64())
                    .ok_or_else(|| anyhow!("Invalid item: missing number"))?;
                
                let address = item.get("address")
                    .and_then(|a| a.as_str())
                    .ok_or_else(|| anyhow!("Invalid item: missing address"))?
                    .to_string();
                
                let output = item.get("output")
                    .and_then(|o| o.as_str())
                    .ok_or_else(|| anyhow!("Invalid item: missing output"))?
                    .to_string();
                
                let content_type = item.get("content_type")
                    .and_then(|c| c.as_str())
                    .ok_or_else(|| anyhow!("Invalid item: missing content_type"))?
                    .to_string();
                
                let content_length = item.get("content_length")
                    .and_then(|c| c.as_u64())
                    .ok_or_else(|| anyhow!("Invalid item: missing content_length"))?;
                
                let timestamp = item.get("timestamp")
                    .and_then(|t| t.as_u64())
                    .ok_or_else(|| anyhow!("Invalid item: missing timestamp"))?;
                
                let genesis_transaction = item.get("genesis_transaction")
                    .and_then(|g| g.as_str())
                    .ok_or_else(|| anyhow!("Invalid item: missing genesis_transaction"))?
                    .to_string();
                
                let genesis_fee = item.get("genesis_fee")
                    .and_then(|g| g.as_u64())
                    .ok_or_else(|| anyhow!("Invalid item: missing genesis_fee"))?;
                
                let location = item.get("location")
                    .and_then(|l| l.as_str())
                    .ok_or_else(|| anyhow!("Invalid item: missing location"))?
                    .to_string();
                
                let offset = item.get("offset")
                    .and_then(|o| o.as_u64())
                    .ok_or_else(|| anyhow!("Invalid item: missing offset"))?;
                
                let value = item.get("value")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| anyhow!("Invalid item: missing value"))?;
                
                let collection_id = item.get("collection_id")
                    .and_then(|c| c.as_str())
                    .map(|s| s.to_string());
                
                // Parse metadata if present
                let metadata = if let Some(metadata_obj) = item.get("metadata").and_then(|m| m.as_object()) {
                    let name = metadata_obj.get("name")
                        .and_then(|n| n.as_str())
                        .map(|s| s.to_string());
                    
                    let description = metadata_obj.get("description")
                        .and_then(|d| d.as_str())
                        .map(|s| s.to_string());
                    
                    let image = metadata_obj.get("image")
                        .and_then(|i| i.as_str())
                        .map(|s| s.to_string());
                    
                    let animation_url = metadata_obj.get("animation_url")
                        .and_then(|a| a.as_str())
                        .map(|s| s.to_string());
                    
                    let external_url = metadata_obj.get("external_url")
                        .and_then(|e| e.as_str())
                        .map(|s| s.to_string());
                    
                    // Parse attributes if present
                    let attributes = if let Some(attrs_array) = metadata_obj.get("attributes").and_then(|a| a.as_array()) {
                        let mut attrs = Vec::new();
                        
                        for attr in attrs_array {
                            if let (Some(trait_type), Some(value)) = (
                                attr.get("trait_type").and_then(|t| t.as_str()),
                                attr.get("value").and_then(|v| v.as_str()),
                            ) {
                                attrs.push(CollectibleAttribute {
                                    trait_type: trait_type.to_string(),
                                    value: value.to_string(),
                                });
                            }
                        }
                        
                        if attrs.is_empty() {
                            None
                        } else {
                            Some(attrs)
                        }
                    } else {
                        None
                    };
                    
                    Some(CollectibleMetadata {
                        name,
                        description,
                        attributes,
                        image,
                        animation_url,
                        external_url,
                    })
                } else {
                    None
                };
                
                collectibles.push(Collectible {
                    id,
                    inscription_id,
                    number,
                    address,
                    output,
                    content_type,
                    content_length,
                    timestamp,
                    genesis_transaction,
                    genesis_fee,
                    location,
                    offset,
                    value,
                    collection_id,
                    metadata,
                });
            }
            
            collectibles
        } else {
            Vec::new()
        };
        
        Ok(Collection {
            id,
            name,
            description,
            image,
            creator,
            size,
            items,
        })
    }
    
    /// Create a PSBT for a collectible operation
    pub async fn create_operation_psbt(
        &self,
        operation: CollectibleOperation,
        content: Option<&[u8]>,
        content_type: Option<&str>,
        metadata: Option<&CollectibleMetadata>,
        recipient: Option<&str>,
        inscription_id: Option<&str>,
        gathered_utxos: &GatheredUtxos,
        account: &Account,
        fee_rate: f64,
    ) -> Result<Psbt> {
        // TODO: Implement collectible operation
        // This is a placeholder implementation
        
        Err(anyhow!("Collectible operation not yet implemented"))
    }
    
    /// Create a new collectible
    pub async fn create(
        &self,
        content: &[u8],
        content_type: &str,
        metadata: Option<&CollectibleMetadata>,
        gathered_utxos: &GatheredUtxos,
        account: &Account,
        signer: &Signer,
        fee_rate: f64,
    ) -> Result<String> {
        // Create PSBT
        let mut psbt = self.create_operation_psbt(
            CollectibleOperation::Create,
            Some(content),
            Some(content_type),
            metadata,
            None,
            None,
            gathered_utxos,
            account,
            fee_rate,
        ).await?;
        
        // Sign PSBT
        signer.sign_psbt(&mut psbt)?;
        
        // Extract transaction
        let tx = psbt.extract_tx();
        
        // Broadcast transaction
        let tx_hex = hex::encode(bdk::bitcoin::consensus::serialize(&tx));
        let result = self.rpc_client._call(
            "btc_sendrawtransaction",
            serde_json::json!([tx_hex]),
        ).await?;
        
        // Get transaction ID
        let txid = tx.txid().to_string();
        
        Ok(txid)
    }
    
    /// Transfer a collectible
    pub async fn transfer(
        &self,
        inscription_id: &str,
        recipient: &str,
        gathered_utxos: &GatheredUtxos,
        account: &Account,
        signer: &Signer,
        fee_rate: f64,
    ) -> Result<String> {
        // Create PSBT
        let mut psbt = self.create_operation_psbt(
            CollectibleOperation::Transfer,
            None,
            None,
            None,
            Some(recipient),
            Some(inscription_id),
            gathered_utxos,
            account,
            fee_rate,
        ).await?;
        
        // Sign PSBT
        signer.sign_psbt(&mut psbt)?;
        
        // Extract transaction
        let tx = psbt.extract_tx();
        
        // Broadcast transaction
        let tx_hex = hex::encode(bdk::bitcoin::consensus::serialize(&tx));
        let result = self.rpc_client._call(
            "btc_sendrawtransaction",
            serde_json::json!([tx_hex]),
        ).await?;
        
        // Get transaction ID
        let txid = tx.txid().to_string();
        
        Ok(txid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // TODO: Add tests for Collectible functionality
}
