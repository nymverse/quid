//! QuID Wallet Integration
//!
//! This crate provides comprehensive wallet integration for QuID quantum-resistant authentication,
//! supporting both hardware wallets (Ledger, Trezor) and software wallet SDKs.
//!
//! Features:
//! - Hardware wallet compatibility with security validation
//! - Software wallet SDK for third-party integration
//! - Multi-currency wallet support leveraging blockchain adapters
//! - Portfolio management and transaction tracking
//! - Secure key derivation and storage

use quid_core::{QuIDIdentity, SecurityLevel, Result as QuIDResult};
// use quid_blockchain::{BlockchainType, BlockchainAccount, Transaction, TransactionStatus};

// Temporary stub definitions for blockchain types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum BlockchainType {
    Bitcoin,
    Ethereum,
}

impl ToString for BlockchainType {
    fn to_string(&self) -> String {
        match self {
            BlockchainType::Bitcoin => "bitcoin".to_string(),
            BlockchainType::Ethereum => "ethereum".to_string(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Transaction {
    id: String,
    network: BlockchainType,
}

impl Transaction {
    pub fn id(&self) -> &str {
        &self.id
    }
    
    pub fn network(&self) -> BlockchainType {
        self.network
    }
    
    pub fn to_bytes(&self) -> Vec<u8> {
        self.id.as_bytes().to_vec()
    }
}
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use uuid::Uuid;

pub mod hardware;
pub mod software;
pub mod portfolio;
pub mod error;
pub mod types;
pub mod config;

pub use error::{WalletError, WalletResult};
pub use types::*;
pub use config::WalletConfig;

/// QuID wallet manager for hardware and software wallet integration
#[derive(Debug)]
pub struct QuIDWalletManager {
    /// Wallet configuration
    config: WalletConfig,
    /// Connected hardware wallets
    hardware_wallets: RwLock<HashMap<String, Arc<dyn hardware::HardwareWallet>>>,
    /// Software wallet instances
    software_wallets: RwLock<HashMap<String, Arc<dyn software::SoftwareWallet>>>,
    /// Portfolio manager for tracking assets
    portfolio: Arc<portfolio::PortfolioManager>,
    /// Wallet registry for discovery
    wallet_registry: Arc<WalletRegistry>,
}

/// Wallet registry for managing different wallet types
#[derive(Debug)]
pub struct WalletRegistry {
    /// Hardware wallet factories
    hardware_factories: RwLock<HashMap<String, Box<dyn hardware::HardwareWalletFactory>>>,
    /// Software wallet factories
    software_factories: RwLock<HashMap<String, Box<dyn software::SoftwareWalletFactory>>>,
    /// Discovery service
    discovery: Arc<WalletDiscovery>,
}

/// Wallet discovery service for finding available wallets
#[derive(Debug)]
pub struct WalletDiscovery {
    /// Hardware wallet discovery
    hardware_discovery: hardware::HardwareDiscovery,
    /// Software wallet discovery
    software_discovery: software::SoftwareDiscovery,
}

impl QuIDWalletManager {
    /// Create new QuID wallet manager
    pub async fn new(config: WalletConfig) -> WalletResult<Self> {
        let hardware_wallets = RwLock::new(HashMap::new());
        let software_wallets = RwLock::new(HashMap::new());
        
        let portfolio = Arc::new(portfolio::PortfolioManager::new(config.portfolio.clone()).await?);
        let wallet_registry = Arc::new(WalletRegistry::new().await?);
        
        Ok(Self {
            config,
            hardware_wallets,
            software_wallets,
            portfolio,
            wallet_registry,
        })
    }

    /// Discover available wallets
    pub async fn discover_wallets(&self) -> WalletResult<WalletDiscoveryResult> {
        let discovery = &self.wallet_registry.discovery;
        
        let hardware_wallets = discovery.discover_hardware_wallets().await?;
        let software_wallets = discovery.discover_software_wallets().await?;
        
        Ok(WalletDiscoveryResult {
            hardware_wallets,
            software_wallets,
            total_found: hardware_wallets.len() + software_wallets.len(),
            discovery_time: Utc::now(),
        })
    }

    /// Connect to a hardware wallet
    pub async fn connect_hardware_wallet(
        &self,
        wallet_id: &str,
        wallet_type: HardwareWalletType,
    ) -> WalletResult<Arc<dyn hardware::HardwareWallet>> {
        let factory = self.wallet_registry.get_hardware_factory(&wallet_type.to_string()).await?;
        
        let wallet = factory.connect(wallet_id).await?;
        
        let mut hardware_wallets = self.hardware_wallets.write().await;
        hardware_wallets.insert(wallet_id.to_string(), wallet.clone());
        
        tracing::info!("Connected to hardware wallet: {} ({})", wallet_id, wallet_type);
        
        Ok(wallet)
    }

    /// Create software wallet instance
    pub async fn create_software_wallet(
        &self,
        wallet_name: &str,
        wallet_type: SoftwareWalletType,
        identity: &QuIDIdentity,
    ) -> WalletResult<Arc<dyn software::SoftwareWallet>> {
        let factory = self.wallet_registry.get_software_factory(&wallet_type.to_string()).await?;
        
        let wallet = factory.create(wallet_name, identity).await?;
        
        let mut software_wallets = self.software_wallets.write().await;
        software_wallets.insert(wallet_name.to_string(), wallet.clone());
        
        tracing::info!("Created software wallet: {} ({})", wallet_name, wallet_type);
        
        Ok(wallet)
    }

    /// Get wallet by ID
    pub async fn get_wallet(&self, wallet_id: &str) -> WalletResult<WalletInstance> {
        // Check hardware wallets first
        {
            let hardware_wallets = self.hardware_wallets.read().await;
            if let Some(wallet) = hardware_wallets.get(wallet_id) {
                return Ok(WalletInstance::Hardware(wallet.clone()));
            }
        }
        
        // Check software wallets
        {
            let software_wallets = self.software_wallets.read().await;
            if let Some(wallet) = software_wallets.get(wallet_id) {
                return Ok(WalletInstance::Software(wallet.clone()));
            }
        }
        
        Err(WalletError::WalletNotFound(wallet_id.to_string()))
    }

    /// List all connected wallets
    pub async fn list_wallets(&self) -> Vec<WalletInfo> {
        let mut wallets = Vec::new();
        
        // Add hardware wallets
        {
            let hardware_wallets = self.hardware_wallets.read().await;
            for (id, wallet) in hardware_wallets.iter() {
                wallets.push(WalletInfo {
                    id: id.clone(),
                    name: wallet.name().to_string(),
                    wallet_type: WalletType::Hardware,
                    status: WalletStatus::Connected,
                    supported_networks: wallet.supported_networks().await,
                    last_used: wallet.last_used().await,
                });
            }
        }
        
        // Add software wallets
        {
            let software_wallets = self.software_wallets.read().await;
            for (id, wallet) in software_wallets.iter() {
                wallets.push(WalletInfo {
                    id: id.clone(),
                    name: wallet.name().to_string(),
                    wallet_type: WalletType::Software,
                    status: WalletStatus::Connected,
                    supported_networks: wallet.supported_networks().await,
                    last_used: wallet.last_used().await,
                });
            }
        }
        
        wallets
    }

    /// Get portfolio manager
    pub fn portfolio(&self) -> Arc<portfolio::PortfolioManager> {
        self.portfolio.clone()
    }

    /// Disconnect wallet
    pub async fn disconnect_wallet(&self, wallet_id: &str) -> WalletResult<()> {
        // Try hardware wallets first
        {
            let mut hardware_wallets = self.hardware_wallets.write().await;
            if let Some(wallet) = hardware_wallets.remove(wallet_id) {
                wallet.disconnect().await?;
                tracing::info!("Disconnected hardware wallet: {}", wallet_id);
                return Ok(());
            }
        }
        
        // Try software wallets
        {
            let mut software_wallets = self.software_wallets.write().await;
            if let Some(wallet) = software_wallets.remove(wallet_id) {
                wallet.disconnect().await?;
                tracing::info!("Disconnected software wallet: {}", wallet_id);
                return Ok(());
            }
        }
        
        Err(WalletError::WalletNotFound(wallet_id.to_string()))
    }

    /// Sign transaction with wallet
    pub async fn sign_transaction(
        &self,
        wallet_id: &str,
        transaction: &Transaction,
        identity: &QuIDIdentity,
    ) -> WalletResult<Vec<u8>> {
        let wallet = self.get_wallet(wallet_id).await?;
        
        match wallet {
            WalletInstance::Hardware(hw_wallet) => {
                hw_wallet.sign_transaction(transaction, identity).await
            }
            WalletInstance::Software(sw_wallet) => {
                sw_wallet.sign_transaction(transaction, identity).await
            }
        }
    }

    /// Get account balance across all wallets
    pub async fn get_total_balance(&self, network: BlockchainType) -> WalletResult<u64> {
        let mut total_balance = 0u64;
        
        // Get balances from hardware wallets
        {
            let hardware_wallets = self.hardware_wallets.read().await;
            for wallet in hardware_wallets.values() {
                if let Ok(balance) = wallet.get_balance(network).await {
                    total_balance = total_balance.saturating_add(balance);
                }
            }
        }
        
        // Get balances from software wallets
        {
            let software_wallets = self.software_wallets.read().await;
            for wallet in software_wallets.values() {
                if let Ok(balance) = wallet.get_balance(network).await {
                    total_balance = total_balance.saturating_add(balance);
                }
            }
        }
        
        Ok(total_balance)
    }
}

impl WalletRegistry {
    /// Create new wallet registry
    pub async fn new() -> WalletResult<Self> {
        let hardware_factories = RwLock::new(HashMap::new());
        let software_factories = RwLock::new(HashMap::new());
        let discovery = Arc::new(WalletDiscovery::new().await?);
        
        let registry = Self {
            hardware_factories,
            software_factories,
            discovery,
        };
        
        // Register built-in wallet factories
        registry.register_builtin_factories().await?;
        
        Ok(registry)
    }

    /// Register built-in wallet factories
    async fn register_builtin_factories(&self) -> WalletResult<()> {
        // Register hardware wallet factories
        {
            let mut hardware_factories = self.hardware_factories.write().await;
            
            #[cfg(feature = "ledger")]
            {
                let ledger_factory = Box::new(hardware::LedgerWalletFactory::new());
                hardware_factories.insert("ledger".to_string(), ledger_factory);
            }
            
            #[cfg(feature = "trezor")]
            {
                let trezor_factory = Box::new(hardware::TrezorWalletFactory::new());
                hardware_factories.insert("trezor".to_string(), trezor_factory);
            }
        }
        
        // Register software wallet factories
        {
            let mut software_factories = self.software_factories.write().await;
            
            let basic_factory = Box::new(software::BasicWalletFactory::new());
            software_factories.insert("basic".to_string(), basic_factory);
            
            let hd_factory = Box::new(software::HDWalletFactory::new());
            software_factories.insert("hd".to_string(), hd_factory);
        }
        
        Ok(())
    }

    /// Get hardware wallet factory
    pub async fn get_hardware_factory(&self, wallet_type: &str) -> WalletResult<&dyn hardware::HardwareWalletFactory> {
        let factories = self.hardware_factories.read().await;
        factories.get(wallet_type)
            .map(|f| f.as_ref())
            .ok_or_else(|| WalletError::UnsupportedWalletType(wallet_type.to_string()))
    }

    /// Get software wallet factory
    pub async fn get_software_factory(&self, wallet_type: &str) -> WalletResult<&dyn software::SoftwareWalletFactory> {
        let factories = self.software_factories.read().await;
        factories.get(wallet_type)
            .map(|f| f.as_ref())
            .ok_or_else(|| WalletError::UnsupportedWalletType(wallet_type.to_string()))
    }
}

impl WalletDiscovery {
    /// Create new wallet discovery service
    pub async fn new() -> WalletResult<Self> {
        let hardware_discovery = hardware::HardwareDiscovery::new().await?;
        let software_discovery = software::SoftwareDiscovery::new().await?;
        
        Ok(Self {
            hardware_discovery,
            software_discovery,
        })
    }

    /// Discover hardware wallets
    pub async fn discover_hardware_wallets(&self) -> WalletResult<Vec<HardwareWalletInfo>> {
        self.hardware_discovery.discover().await
    }

    /// Discover software wallets
    pub async fn discover_software_wallets(&self) -> WalletResult<Vec<SoftwareWalletInfo>> {
        self.software_discovery.discover().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quid_core::{QuIDIdentity, SecurityLevel};

    #[tokio::test]
    async fn test_wallet_manager_creation() {
        let config = WalletConfig::default();
        let manager = QuIDWalletManager::new(config).await.unwrap();
        
        let wallets = manager.list_wallets().await;
        assert_eq!(wallets.len(), 0);
    }

    #[tokio::test]
    async fn test_wallet_discovery() {
        let config = WalletConfig::default();
        let manager = QuIDWalletManager::new(config).await.unwrap();
        
        let discovery_result = manager.discover_wallets().await.unwrap();
        assert_eq!(discovery_result.total_found, discovery_result.hardware_wallets.len() + discovery_result.software_wallets.len());
    }

    #[tokio::test]
    async fn test_wallet_registry() {
        let registry = WalletRegistry::new().await.unwrap();
        
        // Test that built-in factories are registered
        let software_factory = registry.get_software_factory("basic").await;
        assert!(software_factory.is_ok());
    }
}