//! QuID Blockchain Integration
//!
//! This crate provides blockchain integration for QuID quantum-resistant authentication,
//! supporting Bitcoin, Ethereum, privacy coins, and a universal blockchain adapter framework.

pub mod bitcoin;
pub mod ethereum;
pub mod privacy;
pub mod universal;
pub mod adapters;
pub mod config;
pub mod utils;

// Re-export commonly used types
pub use bitcoin::{BitcoinAdapter, BitcoinAddress, BitcoinTransaction};
pub use ethereum::{EthereumAdapter, EthereumAddress, EthereumTransaction};
pub use privacy::{MoneroAdapter, ZcashAdapter, PrivacyTransaction, PrivacyConfig};
pub use universal::{UniversalBlockchainAdapter, BlockchainNetwork, BlockchainTransaction as UniversalTransaction};
pub use adapters::{BlockchainAdapter, AdapterRegistry, AdapterError, AdapterFactory};
pub use config::{QuIDBlockchainConfig, BlockchainSettings, CustomBlockchainConfig};

use anyhow::Result;
use quid_core::{QuIDClient, QuIDIdentity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// QuID blockchain integration error types
#[derive(thiserror::Error, Debug)]
pub enum QuIDBlockchainError {
    #[error("Address derivation failed: {0}")]
    AddressDerivationFailed(String),
    
    #[error("Transaction signing failed: {0}")]
    TransactionSigningFailed(String),
    
    #[error("Blockchain connection failed: {0}")]
    BlockchainConnectionFailed(String),
    
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),
    
    #[error("Insufficient funds: required {required}, available {available}")]
    InsufficientFunds { required: u64, available: u64 },
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Adapter error: {0}")]
    AdapterError(String),
    
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("Encoding error: {0}")]
    EncodingError(String),
    
    #[error("QuID core error: {0}")]
    QuIDCoreError(#[from] quid_core::QuIDError),
    
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Result type for QuID blockchain operations
pub type QuIDBlockchainResult<T> = Result<T, QuIDBlockchainError>;

/// Supported blockchain networks
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BlockchainType {
    Bitcoin,
    BitcoinTestnet,
    Ethereum,
    EthereumGoerli,
    EthereumSepolia,
    Monero,
    MoneroTestnet,
    Zcash,
    ZcashTestnet,
    Custom(String),
}

impl BlockchainType {
    /// Get the network name
    pub fn name(&self) -> &str {
        match self {
            BlockchainType::Bitcoin => "bitcoin",
            BlockchainType::BitcoinTestnet => "bitcoin-testnet",
            BlockchainType::Ethereum => "ethereum",
            BlockchainType::EthereumGoerli => "ethereum-goerli",
            BlockchainType::EthereumSepolia => "ethereum-sepolia",
            BlockchainType::Monero => "monero",
            BlockchainType::MoneroTestnet => "monero-testnet",
            BlockchainType::Zcash => "zcash",
            BlockchainType::ZcashTestnet => "zcash-testnet",
            BlockchainType::Custom(name) => name,
        }
    }

    /// Check if this is a testnet
    pub fn is_testnet(&self) -> bool {
        matches!(self, 
            BlockchainType::BitcoinTestnet | 
            BlockchainType::EthereumGoerli | 
            BlockchainType::EthereumSepolia |
            BlockchainType::MoneroTestnet | 
            BlockchainType::ZcashTestnet
        )
    }

    /// Check if this is a privacy coin
    pub fn is_privacy_coin(&self) -> bool {
        matches!(self, 
            BlockchainType::Monero | 
            BlockchainType::MoneroTestnet |
            BlockchainType::Zcash | 
            BlockchainType::ZcashTestnet
        )
    }
}

/// Blockchain account derived from QuID identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainAccount {
    /// QuID identity used for derivation
    pub identity: QuIDIdentity,
    /// Blockchain network
    pub network: BlockchainType,
    /// Derived address
    pub address: String,
    /// Address derivation path (for HD wallets)
    pub derivation_path: Option<String>,
    /// Public key
    pub public_key: Vec<u8>,
    /// Account metadata
    pub metadata: HashMap<String, String>,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl BlockchainAccount {
    /// Create a new blockchain account
    pub fn new(
        identity: QuIDIdentity,
        network: BlockchainType,
        address: String,
        public_key: Vec<u8>,
    ) -> Self {
        Self {
            identity,
            network,
            address,
            derivation_path: None,
            public_key,
            metadata: HashMap::new(),
            created_at: chrono::Utc::now(),
        }
    }

    /// Add derivation path
    pub fn with_derivation_path(mut self, path: &str) -> Self {
        self.derivation_path = Some(path.to_string());
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }

    /// Get account identifier
    pub fn identifier(&self) -> String {
        format!("{}-{}-{}", self.identity.id, self.network.name(), &self.address[..8])
    }
}

/// Transaction status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TransactionStatus {
    /// Transaction is being prepared
    Preparing,
    /// Transaction is pending broadcast
    Pending,
    /// Transaction has been broadcast
    Broadcast,
    /// Transaction is confirmed
    Confirmed { confirmations: u32 },
    /// Transaction failed
    Failed { reason: String },
}

/// Generic blockchain transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction ID (once broadcast)
    pub txid: Option<String>,
    /// Source account
    pub from: BlockchainAccount,
    /// Destination address
    pub to: String,
    /// Amount in base units (satoshis, wei, etc.)
    pub amount: u64,
    /// Transaction fee
    pub fee: u64,
    /// Transaction data/memo
    pub data: Option<Vec<u8>>,
    /// Gas limit (for Ethereum-like chains)
    pub gas_limit: Option<u64>,
    /// Gas price (for Ethereum-like chains)
    pub gas_price: Option<u64>,
    /// Transaction status
    pub status: TransactionStatus,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Network confirmation target
    pub confirmation_target: u32,
}

/// Initialize QuID blockchain integration
pub async fn initialize_quid_blockchain(config: QuIDBlockchainConfig) -> QuIDBlockchainResult<()> {
    tracing::info!("Initializing QuID blockchain integration");
    
    // Validate configuration
    config.validate()?;
    
    // Initialize adapter registry
    let mut registry = AdapterRegistry::new();
    
    // Register built-in adapters
    if config.bitcoin.enabled {
        let bitcoin_adapter = BitcoinAdapter::new(config.bitcoin.clone()).await?;
        registry.register("bitcoin", Box::new(bitcoin_adapter));
    }
    
    if config.ethereum.enabled {
        let ethereum_adapter = EthereumAdapter::new(config.ethereum.clone()).await?;
        registry.register("ethereum", Box::new(ethereum_adapter));
    }
    
    if config.privacy.monero_enabled {
        let monero_adapter = MoneroAdapter::new(config.privacy.clone()).await?;
        registry.register("monero", Box::new(monero_adapter));
    }
    
    if config.privacy.zcash_enabled {
        let zcash_adapter = ZcashAdapter::new(config.privacy.clone()).await?;
        registry.register("zcash", Box::new(zcash_adapter));
    }
    
    tracing::info!("QuID blockchain integration initialized with {} adapters", registry.count());
    Ok(())
}

/// Derive blockchain address from QuID identity
pub async fn derive_address(
    quid_client: &QuIDClient,
    identity: &QuIDIdentity,
    network: BlockchainType,
    derivation_path: Option<&str>,
) -> QuIDBlockchainResult<BlockchainAccount> {
    tracing::debug!("Deriving {} address for identity {}", network.name(), identity.name);
    
    match network {
        BlockchainType::Bitcoin | BlockchainType::BitcoinTestnet => {
            bitcoin::derive_bitcoin_address(quid_client, identity, network, derivation_path).await
        }
        BlockchainType::Ethereum | BlockchainType::EthereumGoerli | BlockchainType::EthereumSepolia => {
            ethereum::derive_ethereum_address(quid_client, identity, network).await
        }
        BlockchainType::Monero | BlockchainType::MoneroTestnet => {
            privacy::derive_monero_address(quid_client, identity, network).await
        }
        BlockchainType::Zcash | BlockchainType::ZcashTestnet => {
            privacy::derive_zcash_address(quid_client, identity, network).await
        }
        BlockchainType::Custom(name) => {
            universal::derive_custom_address(quid_client, identity, name).await
        }
    }
}

/// Sign blockchain transaction with QuID identity
pub async fn sign_transaction(
    quid_client: &QuIDClient,
    identity: &QuIDIdentity,
    transaction: &mut Transaction,
) -> QuIDBlockchainResult<Vec<u8>> {
    tracing::debug!("Signing transaction for {} network", transaction.from.network.name());
    
    match transaction.from.network {
        BlockchainType::Bitcoin | BlockchainType::BitcoinTestnet => {
            bitcoin::sign_bitcoin_transaction(quid_client, identity, transaction).await
        }
        BlockchainType::Ethereum | BlockchainType::EthereumGoerli | BlockchainType::EthereumSepolia => {
            ethereum::sign_ethereum_transaction(quid_client, identity, transaction).await
        }
        BlockchainType::Monero | BlockchainType::MoneroTestnet => {
            privacy::sign_monero_transaction(quid_client, identity, transaction).await
        }
        BlockchainType::Zcash | BlockchainType::ZcashTestnet => {
            privacy::sign_zcash_transaction(quid_client, identity, transaction).await
        }
        BlockchainType::Custom(ref name) => {
            universal::sign_custom_transaction(quid_client, identity, transaction, name).await
        }
    }
}

/// Get default blockchain configuration directory
pub fn get_default_config_dir() -> std::path::PathBuf {
    if let Some(home) = dirs::home_dir() {
        home.join(".quid").join("blockchain")
    } else {
        std::path::PathBuf::from("/etc/quid/blockchain")
    }
}

/// Get default accounts directory
pub fn get_default_accounts_dir() -> std::path::PathBuf {
    if let Some(home) = dirs::home_dir() {
        home.join(".quid").join("blockchain").join("accounts")
    } else {
        std::path::PathBuf::from("/var/lib/quid/blockchain/accounts")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blockchain_types() {
        assert_eq!(BlockchainType::Bitcoin.name(), "bitcoin");
        assert_eq!(BlockchainType::EthereumGoerli.name(), "ethereum-goerli");
        
        assert!(!BlockchainType::Bitcoin.is_testnet());
        assert!(BlockchainType::BitcoinTestnet.is_testnet());
        
        assert!(!BlockchainType::Bitcoin.is_privacy_coin());
        assert!(BlockchainType::Monero.is_privacy_coin());
    }

    #[test]
    fn test_blockchain_account() {
        let identity = quid_core::QuIDIdentity {
            id: "test-identity".to_string(),
            name: "test".to_string(),
            security_level: quid_core::SecurityLevel::Level1,
            created_at: chrono::Utc::now(),
            contexts: vec!["blockchain".to_string()],
            metadata: None,
        };

        let account = BlockchainAccount::new(
            identity,
            BlockchainType::Bitcoin,
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
            vec![0; 33],
        )
        .with_derivation_path("m/44'/0'/0'/0/0")
        .with_metadata("wallet", "primary");

        assert_eq!(account.network, BlockchainType::Bitcoin);
        assert!(account.derivation_path.is_some());
        assert_eq!(account.metadata.get("wallet"), Some(&"primary".to_string()));
    }

    #[test]
    fn test_transaction_status() {
        let status = TransactionStatus::Confirmed { confirmations: 6 };
        assert!(matches!(status, TransactionStatus::Confirmed { confirmations } if confirmations == 6));
        
        let failed_status = TransactionStatus::Failed { reason: "Insufficient funds".to_string() };
        assert!(matches!(failed_status, TransactionStatus::Failed { .. }));
    }
}