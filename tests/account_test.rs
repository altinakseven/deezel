use anyhow::Result;
use deezel::account::{Account, AccountConfig, AddressType, DerivationStandard, SpendStrategy, CustomDerivationPaths};
use deezel::account::encryption::{EncryptedAccount, verify_password};
use bdk::bitcoin::Network;
use tempfile::tempdir;

#[test]
fn test_account_creation_from_mnemonic() -> Result<()> {
    // Test mnemonic
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    
    // Create account
    let account = Account::from_mnemonic(mnemonic, None)?;
    
    // Check network
    assert_eq!(account.network, Network::Bitcoin);
    
    // Check addresses
    assert!(!account.legacy.address.is_empty());
    assert!(!account.nested_segwit.address.is_empty());
    assert!(!account.native_segwit.address.is_empty());
    assert!(!account.taproot.address.is_empty());
    
    // Check specific addresses for the test mnemonic
    assert_eq!(account.get_address(AddressType::Legacy), "1JAd7XCBzGudGpJQSDSfpmJhiygtLQWaGL");
    assert_eq!(account.get_address(AddressType::NativeSegwit), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    
    Ok(())
}

#[test]
fn test_random_account_generation() -> Result<()> {
    // Generate random account
    let (account, mnemonic) = Account::generate(None)?;
    
    // Check mnemonic
    assert!(!mnemonic.is_empty());
    assert_eq!(mnemonic.split_whitespace().count(), 12); // 12 words
    
    // Check network
    assert_eq!(account.network, Network::Bitcoin);
    
    // Check addresses
    assert!(!account.legacy.address.is_empty());
    assert!(!account.nested_segwit.address.is_empty());
    assert!(!account.native_segwit.address.is_empty());
    assert!(!account.taproot.address.is_empty());
    
    Ok(())
}

#[test]
fn test_custom_derivation_paths() -> Result<()> {
    // Test mnemonic
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    
    // Custom paths
    let custom_paths = CustomDerivationPaths {
        legacy: Some("m/44'/0'/0'/0/1".to_string()),
        nested_segwit: Some("m/49'/0'/0'/0/1".to_string()),
        native_segwit: Some("m/84'/0'/0'/0/1".to_string()),
        taproot: Some("m/86'/0'/0'/0/1".to_string()),
    };
    
    // Create config
    let config = AccountConfig {
        network: Network::Bitcoin,
        index: 0,
        derivation_standard: DerivationStandard::Bip44AccountLast,
        custom_paths: Some(custom_paths),
        spend_strategy: SpendStrategy::default(),
    };
    
    // Create account
    let account = Account::from_mnemonic(mnemonic, Some(config))?;
    
    // Check derivation paths
    assert_eq!(account.legacy.derivation_path, "m/44'/0'/0'/0/1");
    assert_eq!(account.nested_segwit.derivation_path, "m/49'/0'/0'/0/1");
    assert_eq!(account.native_segwit.derivation_path, "m/84'/0'/0'/0/1");
    assert_eq!(account.taproot.derivation_path, "m/86'/0'/0'/0/1");
    
    // Check that addresses are different from default
    let default_account = Account::from_mnemonic(mnemonic, None)?;
    assert_ne!(account.get_address(AddressType::Legacy), default_account.get_address(AddressType::Legacy));
    assert_ne!(account.get_address(AddressType::NestedSegwit), default_account.get_address(AddressType::NestedSegwit));
    assert_ne!(account.get_address(AddressType::NativeSegwit), default_account.get_address(AddressType::NativeSegwit));
    assert_ne!(account.get_address(AddressType::Taproot), default_account.get_address(AddressType::Taproot));
    
    Ok(())
}

#[test]
fn test_account_encryption_decryption() -> Result<()> {
    // Test mnemonic
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    
    // Create account
    let account = Account::from_mnemonic(mnemonic, None)?;
    
    // Encrypt account
    let password = "test_password";
    let encrypted_account = account.encrypt(password)?;
    
    // Decrypt account
    let decrypted_account = encrypted_account.decrypt(password)?;
    
    // Check that decrypted account matches original
    assert_eq!(decrypted_account.legacy.address, account.legacy.address);
    assert_eq!(decrypted_account.nested_segwit.address, account.nested_segwit.address);
    assert_eq!(decrypted_account.native_segwit.address, account.native_segwit.address);
    assert_eq!(decrypted_account.taproot.address, account.taproot.address);
    
    // Try to decrypt with wrong password
    let wrong_password = "wrong_password";
    let result = encrypted_account.decrypt(wrong_password);
    
    // Check that decryption failed
    assert!(result.is_err());
    
    Ok(())
}

#[test]
fn test_account_save_load() -> Result<()> {
    // Create temporary directory
    let dir = tempdir()?;
    let file_path = dir.path().join("account.json");
    
    // Test mnemonic
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    
    // Create account
    let account = Account::from_mnemonic(mnemonic, None)?;
    
    // Save to file
    let password = "test_password";
    account.save_to_file(&file_path, password)?;
    
    // Load from file
    let loaded_account = Account::load_from_file(&file_path, password)?;
    
    // Check that loaded account matches original
    assert_eq!(loaded_account.legacy.address, account.legacy.address);
    assert_eq!(loaded_account.nested_segwit.address, account.nested_segwit.address);
    assert_eq!(loaded_account.native_segwit.address, account.native_segwit.address);
    assert_eq!(loaded_account.taproot.address, account.taproot.address);
    
    // Try to load with wrong password
    let wrong_password = "wrong_password";
    let result = Account::load_from_file(&file_path, wrong_password);
    
    // Check that loading failed
    assert!(result.is_err());
    
    Ok(())
}

#[test]
fn test_verify_password() -> Result<()> {
    // Create temporary directory
    let dir = tempdir()?;
    let file_path = dir.path().join("account.json");
    
    // Test mnemonic
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    
    // Create account
    let account = Account::from_mnemonic(mnemonic, None)?;
    
    // Save to file
    let password = "test_password";
    account.save_to_file(&file_path, password)?;
    
    // Verify correct password
    let result = Account::verify_password(&file_path, password)?;
    assert!(result);
    
    // Verify wrong password
    let wrong_password = "wrong_password";
    let result = Account::verify_password(&file_path, wrong_password)?;
    assert!(!result);
    
    Ok(())
}

#[test]
fn test_different_networks() -> Result<()> {
    // Test mnemonic
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    
    // Create mainnet account
    let mainnet_config = AccountConfig {
        network: Network::Bitcoin,
        index: 0,
        derivation_standard: DerivationStandard::Bip44AccountLast,
        custom_paths: None,
        spend_strategy: SpendStrategy::default(),
    };
    let mainnet_account = Account::from_mnemonic(mnemonic, Some(mainnet_config))?;
    
    // Create testnet account
    let testnet_config = AccountConfig {
        network: Network::Testnet,
        index: 0,
        derivation_standard: DerivationStandard::Bip44AccountLast,
        custom_paths: None,
        spend_strategy: SpendStrategy::default(),
    };
    let testnet_account = Account::from_mnemonic(mnemonic, Some(testnet_config))?;
    
    // Check networks
    assert_eq!(mainnet_account.network, Network::Bitcoin);
    assert_eq!(testnet_account.network, Network::Testnet);
    
    // Check that addresses are different
    assert_ne!(mainnet_account.get_address(AddressType::Legacy), testnet_account.get_address(AddressType::Legacy));
    assert_ne!(mainnet_account.get_address(AddressType::NestedSegwit), testnet_account.get_address(AddressType::NestedSegwit));
    assert_ne!(mainnet_account.get_address(AddressType::NativeSegwit), testnet_account.get_address(AddressType::NativeSegwit));
    assert_ne!(mainnet_account.get_address(AddressType::Taproot), testnet_account.get_address(AddressType::Taproot));
    
    // Check address prefixes
    assert!(mainnet_account.get_address(AddressType::Legacy).starts_with('1'));
    assert!(testnet_account.get_address(AddressType::Legacy).starts_with('m') || testnet_account.get_address(AddressType::Legacy).starts_with('n'));
    
    assert!(mainnet_account.get_address(AddressType::NativeSegwit).starts_with("bc1"));
    assert!(testnet_account.get_address(AddressType::NativeSegwit).starts_with("tb1"));
    
    Ok(())
}

#[test]
fn test_spend_strategy() -> Result<()> {
    // Test mnemonic
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    
    // Create custom spend strategy
    let spend_strategy = SpendStrategy {
        address_order: vec![
            AddressType::Taproot,
            AddressType::NativeSegwit,
            AddressType::NestedSegwit,
            AddressType::Legacy,
        ],
        utxo_sort_greatest_to_least: false,
        change_address: AddressType::Taproot,
    };
    
    // Create config
    let config = AccountConfig {
        network: Network::Bitcoin,
        index: 0,
        derivation_standard: DerivationStandard::Bip44AccountLast,
        custom_paths: None,
        spend_strategy,
    };
    
    // Create account
    let account = Account::from_mnemonic(mnemonic, Some(config))?;
    
    // Check spend strategy
    assert_eq!(account.spend_strategy.address_order[0], AddressType::Taproot);
    assert_eq!(account.spend_strategy.address_order[1], AddressType::NativeSegwit);
    assert_eq!(account.spend_strategy.address_order[2], AddressType::NestedSegwit);
    assert_eq!(account.spend_strategy.address_order[3], AddressType::Legacy);
    assert_eq!(account.spend_strategy.utxo_sort_greatest_to_least, false);
    assert_eq!(account.spend_strategy.change_address, AddressType::Taproot);
    
    Ok(())
}
