//! Comprehensive test coverage for URL passing from deezel-sys to deezel-common
//!
//! This module tests that the URLs provided on the command line are correctly
//! passed through the system and used in the JsonRpcProvider::call method.

use deezel_common::commands::Args;
use deezel_common::provider::ConcreteProvider;
use deezel_common::traits::JsonRpcProvider;
use deezel_sys::SystemDeezel;
use serde_json::json;
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;

// Custom log writer to capture log messages for testing
#[derive(Debug, Clone)]
pub struct TestLogCapture {
    messages: Arc<Mutex<VecDeque<String>>>,
}

impl TestLogCapture {
    pub fn new() -> Self {
        Self {
            messages: Arc::new(Mutex::new(VecDeque::new())),
        }
    }
    
    pub fn capture_message(&self, message: String) {
        let mut messages = self.messages.lock().unwrap();
        messages.push_back(message);
    }
    
    pub fn get_messages(&self) -> Vec<String> {
        let messages = self.messages.lock().unwrap();
        messages.iter().cloned().collect()
    }
    
    pub fn clear(&self) {
        let mut messages = self.messages.lock().unwrap();
        messages.clear();
    }
}

// Mock logger that captures debug messages
struct TestLogger {
    capture: TestLogCapture,
}

impl TestLogger {
    fn new(capture: TestLogCapture) -> Self {
        Self { capture }
    }
}

impl log::Log for TestLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Debug
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let message = format!("{}", record.args());
            self.capture.capture_message(message);
        }
    }

    fn flush(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    
    #[tokio::test]
    async fn test_bitcoin_rpc_url_is_passed_correctly() {
        let log_capture = TestLogCapture::new();
        let logger = TestLogger::new(log_capture.clone());
        log::set_boxed_logger(Box::new(logger)).unwrap();
        log::set_max_level(log::LevelFilter::Debug);

        let args = Args::try_parse_from(&[
            "deezel",
            "--bitcoin-rpc-url", "http://bitcoin.test.com:8332",
            "bitcoind",
            "getblockcount",
        ]).unwrap();
        
        let system = SystemDeezel::new(&args).await.unwrap();
        let provider = system.provider();
        
        // This will fail, but we can check the log for the correct URL
        let _ = provider.get_block_count().await;
        
        let logs = log_capture.get_messages();
        let rpc_call_log = logs.iter().find(|&m| m.contains("JsonRpcProvider::call")).unwrap();
        
        assert!(rpc_call_log.contains("URL: http://bitcoin.test.com:8332"));
    }

    #[tokio::test]
    async fn test_sandshrew_rpc_url_is_passed_correctly() {
        let log_capture = TestLogCapture::new();
        let logger = TestLogger::new(log_capture.clone());
        log::set_boxed_logger(Box::new(logger)).unwrap();
        log::set_max_level(log::LevelFilter::Debug);

        let args = Args::try_parse_from(&[
            "deezel",
            "--sandshrew-rpc-url", "https://mainnet.sandshrew.io/v2/lasereyes",
            "bitcoind",
            "getblockcount",
        ]).unwrap();
        
        let system = SystemDeezel::new(&args).await.unwrap();
        let provider = system.provider();
        
        // This will fail, but we can check the log for the correct URL
        let _ = provider.get_block_count().await;
        
        let logs = log_capture.get_messages();
        let rpc_call_log = logs.iter().find(|&m| m.contains("JsonRpcProvider::call")).unwrap();
        
        assert!(rpc_call_log.contains("URL: https://mainnet.sandshrew.io/v2/lasereyes"));
    }
}