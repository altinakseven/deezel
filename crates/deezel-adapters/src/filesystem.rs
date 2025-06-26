//! Filesystem adapter implementations for CLI environment

use anyhow::Result;
use async_trait::async_trait;
use deezel_core::traits::{WalletStorageLike, ConfigStorageLike, FilesystemLike, BatchLike, FileMetadata};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::io::Error;
use std::path::PathBuf;

/// Filesystem batch for atomic operations
#[derive(Default)]
pub struct FilesystemBatch {
    operations: Vec<(String, Option<Vec<u8>>)>, // (path, data) - None for delete
}

impl BatchLike for FilesystemBatch {
    fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(&mut self, key: K, value: V) {
        let path = String::from_utf8_lossy(key.as_ref()).to_string();
        self.operations.push((path, Some(value.as_ref().to_vec())));
    }

    fn delete<K: AsRef<[u8]>>(&mut self, key: K) {
        let path = String::from_utf8_lossy(key.as_ref()).to_string();
        self.operations.push((path, None));
    }

    fn default() -> Self {
        Self {
            operations: Vec::new(),
        }
    }
}

/// Filesystem wallet storage adapter
pub struct FilesystemWalletStorage {
    base_dir: PathBuf,
}

impl FilesystemWalletStorage {
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }
}

#[async_trait]
impl WalletStorageLike for FilesystemWalletStorage {
    type Error = Error;
    type Batch = FilesystemBatch;

    async fn save_wallet(&mut self, name: &str, data: &[u8]) -> Result<(), Self::Error> {
        let path = self.base_dir.join(format!("{}.dat", name));
        tokio::fs::write(path, data).await
    }

    async fn load_wallet(&self, name: &str) -> Result<Option<Vec<u8>>, Self::Error> {
        let path = self.base_dir.join(format!("{}.dat", name));
        match tokio::fs::read(path).await {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn list_wallets(&self) -> Result<Vec<String>, Self::Error> {
        let mut wallets = Vec::new();
        let mut entries = tokio::fs::read_dir(&self.base_dir).await?;
        
        while let Some(entry) = entries.next_entry().await? {
            if let Some(name) = entry.file_name().to_str() {
                if name.ends_with(".dat") {
                    wallets.push(name.strip_suffix(".dat").unwrap().to_string());
                }
            }
        }
        
        Ok(wallets)
    }

    async fn delete_wallet(&mut self, name: &str) -> Result<(), Self::Error> {
        let path = self.base_dir.join(format!("{}.dat", name));
        tokio::fs::remove_file(path).await
    }

    async fn wallet_exists(&self, name: &str) -> Result<bool, Self::Error> {
        let path = self.base_dir.join(format!("{}.dat", name));
        Ok(path.exists())
    }

    fn create_batch(&self) -> Self::Batch {
        <FilesystemBatch as BatchLike>::default()
    }

    async fn write_batch(&mut self, batch: Self::Batch) -> Result<(), Self::Error> {
        for (path, data) in batch.operations {
            let full_path = self.base_dir.join(path);
            if let Some(data) = data {
                tokio::fs::write(full_path, data).await?;
            } else {
                let _ = tokio::fs::remove_file(full_path).await; // Ignore errors for delete
            }
        }
        Ok(())
    }
}

/// Filesystem config storage adapter
pub struct FilesystemConfigStorage {
    base_dir: PathBuf,
}

impl FilesystemConfigStorage {
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }
}

#[async_trait]
impl ConfigStorageLike for FilesystemConfigStorage {
    type Error = Error;

    async fn save_config<T: Serialize + Send + Sync>(&mut self, key: &str, config: &T) -> Result<(), Self::Error> {
        let path = self.base_dir.join(format!("{}.json", key));
        let data = serde_json::to_vec_pretty(config)
            .map_err(|e| Error::new(std::io::ErrorKind::InvalidData, e))?;
        tokio::fs::write(path, data).await
    }

    async fn load_config<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Result<Option<T>, Self::Error> {
        let path = self.base_dir.join(format!("{}.json", key));
        match tokio::fs::read(path).await {
            Ok(data) => {
                let config = serde_json::from_slice(&data)
                    .map_err(|e| Error::new(std::io::ErrorKind::InvalidData, e))?;
                Ok(Some(config))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn delete_config(&mut self, key: &str) -> Result<(), Self::Error> {
        let path = self.base_dir.join(format!("{}.json", key));
        tokio::fs::remove_file(path).await
    }

    async fn list_configs(&self) -> Result<Vec<String>, Self::Error> {
        let mut configs = Vec::new();
        let mut entries = tokio::fs::read_dir(&self.base_dir).await?;
        
        while let Some(entry) = entries.next_entry().await? {
            if let Some(name) = entry.file_name().to_str() {
                if name.ends_with(".json") {
                    configs.push(name.strip_suffix(".json").unwrap().to_string());
                }
            }
        }
        
        Ok(configs)
    }
}

/// Generic filesystem adapter
pub struct FilesystemAdapter {
    base_dir: PathBuf,
}

impl FilesystemAdapter {
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }
}

#[async_trait]
impl FilesystemLike for FilesystemAdapter {
    type Error = Error;

    async fn read_file(&self, path: &str) -> Result<Vec<u8>, Self::Error> {
        let full_path = self.base_dir.join(path);
        tokio::fs::read(full_path).await
    }

    async fn write_file(&self, path: &str, contents: &[u8]) -> Result<(), Self::Error> {
        let full_path = self.base_dir.join(path);
        if let Some(parent) = full_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(full_path, contents).await
    }

    async fn file_exists(&self, path: &str) -> Result<bool, Self::Error> {
        let full_path = self.base_dir.join(path);
        Ok(full_path.exists())
    }

    async fn create_dir(&self, path: &str) -> Result<(), Self::Error> {
        let full_path = self.base_dir.join(path);
        tokio::fs::create_dir_all(full_path).await
    }

    async fn list_dir(&self, path: &str) -> Result<Vec<String>, Self::Error> {
        let full_path = self.base_dir.join(path);
        let mut entries = Vec::new();
        let mut dir_entries = tokio::fs::read_dir(full_path).await?;
        
        while let Some(entry) = dir_entries.next_entry().await? {
            if let Some(name) = entry.file_name().to_str() {
                entries.push(name.to_string());
            }
        }
        
        Ok(entries)
    }

    async fn delete_file(&self, path: &str) -> Result<(), Self::Error> {
        let full_path = self.base_dir.join(path);
        tokio::fs::remove_file(full_path).await
    }

    async fn file_metadata(&self, path: &str) -> Result<FileMetadata, Self::Error> {
        let full_path = self.base_dir.join(path);
        let metadata = tokio::fs::metadata(full_path).await?;
        
        Ok(FileMetadata {
            size: metadata.len(),
            modified: metadata.modified()?
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            is_dir: metadata.is_dir(),
        })
    }
}