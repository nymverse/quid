//! Software wallet implementation for QuID

use async_trait::async_trait;
use quid_core::{QuIDIdentity, SecurityLevel, KeyPair};
// use quid_blockchain::{BlockchainType, Transaction};
use crate::{BlockchainType, Transaction};
use chrono::{DateTime, Utc};
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use secrecy::{SecretString, ExposeSecret};
use zeroize::Zeroize;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::{WalletError, WalletResult, WalletStatus, SoftwareWalletInfo, SoftwareWalletType, WalletCapability};

/// Software wallet trait for unified interface
#[async_trait]
pub trait SoftwareWallet: Send + Sync {
    /// Get wallet name
    fn name(&self) -> &str;
    
    /// Get wallet status
    async fn status(&self) -> WalletStatus;
    
    /// Get supported networks
    async fn supported_networks(&self) -> Vec<BlockchainType>;
    
    /// Get last used timestamp
    async fn last_used(&self) -> Option<DateTime<Utc>>;
    
    /// Sign transaction
    async fn sign_transaction(&self, transaction: &Transaction, identity: &QuIDIdentity) -> WalletResult<Vec<u8>>;
    
    /// Get balance for network
    async fn get_balance(&self, network: BlockchainType) -> WalletResult<u64>;
    
    /// Disconnect wallet
    async fn disconnect(&self) -> WalletResult<()>;
    
    /// Get wallet capabilities
    async fn capabilities(&self) -> Vec<WalletCapability>;
    
    /// Lock wallet
    async fn lock(&self) -> WalletResult<()>;
    
    /// Unlock wallet with passphrase
    async fn unlock(&self, passphrase: &SecretString) -> WalletResult<()>;
    
    /// Get public key for network
    async fn get_public_key(&self, network: BlockchainType) -> WalletResult<Vec<u8>>;
    
    /// Get wallet information
    async fn wallet_info(&self) -> WalletResult<SoftwareWalletInfo>;
    
    /// Create backup
    async fn create_backup(&self, backup_path: &PathBuf) -> WalletResult<()>;
    
    /// Restore from backup
    async fn restore_from_backup(&self, backup_path: &PathBuf, passphrase: &SecretString) -> WalletResult<()>;
}

/// Software wallet factory trait
#[async_trait]
pub trait SoftwareWalletFactory: Send + Sync {
    /// Create new wallet
    async fn create(&self, name: &str, identity: &QuIDIdentity) -> WalletResult<Arc<dyn SoftwareWallet>>;
    
    /// Load existing wallet
    async fn load(&self, name: &str) -> WalletResult<Arc<dyn SoftwareWallet>>;
    
    /// Get supported wallet type
    fn wallet_type(&self) -> SoftwareWalletType;
    
    /// Check if wallet exists
    async fn exists(&self, name: &str) -> bool;
}

/// Software wallet discovery service
#[derive(Debug)]
pub struct SoftwareDiscovery {
    /// Wallet storage directory
    storage_dir: PathBuf,
    /// Supported wallet types
    supported_types: Vec<SoftwareWalletType>,
}

impl SoftwareDiscovery {
    /// Create new software discovery service
    pub async fn new() -> WalletResult<Self> {
        let storage_dir = dirs::home_dir()
            .unwrap_or_default()
            .join(".quid")
            .join("wallets");
        
        // Create storage directory if it doesn't exist
        if !storage_dir.exists() {
            tokio::fs::create_dir_all(&storage_dir).await
                .map_err(|e| WalletError::IoError(e))?;
        }
        
        let supported_types = vec![
            SoftwareWalletType::Basic,
            SoftwareWalletType::HD,
            SoftwareWalletType::MultiSig,
        ];
        
        Ok(Self {
            storage_dir,
            supported_types,
        })
    }
    
    /// Discover software wallets
    pub async fn discover(&self) -> WalletResult<Vec<SoftwareWalletInfo>> {
        let mut wallets = Vec::new();
        
        if !self.storage_dir.exists() {
            return Ok(wallets);
        }
        
        let mut entries = tokio::fs::read_dir(&self.storage_dir).await
            .map_err(|e| WalletError::IoError(e))?;
        
        while let Some(entry) = entries.next_entry().await
            .map_err(|e| WalletError::IoError(e))? {
            
            let path = entry.path();
            if path.is_file() && path.extension().map_or(false, |ext| ext == "wallet") {
                if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                    if let Ok(wallet_info) = self.load_wallet_info(&path).await {
                        wallets.push(wallet_info);
                    }
                }
            }
        }
        
        Ok(wallets)
    }
    
    /// Load wallet info from file
    async fn load_wallet_info(&self, path: &PathBuf) -> WalletResult<SoftwareWalletInfo> {
        let content = tokio::fs::read_to_string(path).await
            .map_err(|e| WalletError::IoError(e))?;
        
        let wallet_data: WalletData = serde_json::from_str(&content)
            .map_err(|e| WalletError::SerializationError(e))?;
        
        Ok(SoftwareWalletInfo {
            id: wallet_data.id,
            name: wallet_data.name,
            wallet_type: wallet_data.wallet_type,
            version: wallet_data.version,
            created_at: wallet_data.created_at,
            last_accessed: wallet_data.last_accessed,
            status: WalletStatus::Disconnected,
            supported_networks: wallet_data.supported_networks,
            capabilities: wallet_data.capabilities,
        })
    }
}

/// Wallet data structure for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WalletData {
    id: String,
    name: String,
    wallet_type: SoftwareWalletType,
    version: String,
    created_at: DateTime<Utc>,
    last_accessed: Option<DateTime<Utc>>,
    supported_networks: Vec<BlockchainType>,
    capabilities: Vec<WalletCapability>,
    encrypted_keys: HashMap<String, EncryptedKey>,
    metadata: HashMap<String, String>,
}

/// Encrypted key storage
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedKey {
    network: BlockchainType,
    encrypted_data: Vec<u8>,
    salt: Vec<u8>,
    nonce: Vec<u8>,
}

/// Basic software wallet implementation
#[derive(Debug)]
pub struct BasicWallet {
    name: String,
    wallet_data: Arc<RwLock<WalletData>>,
    storage_path: PathBuf,
    status: Arc<RwLock<WalletStatus>>,
    keys: Arc<RwLock<HashMap<BlockchainType, KeyPair>>>,
}

impl BasicWallet {
    /// Create new basic wallet
    pub async fn new(name: String, identity: &QuIDIdentity) -> WalletResult<Self> {
        let storage_dir = dirs::home_dir()
            .unwrap_or_default()
            .join(".quid")
            .join("wallets");
        
        let storage_path = storage_dir.join(format!("{}.wallet", name));
        
        let wallet_data = WalletData {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.clone(),
            wallet_type: SoftwareWalletType::Basic,
            version: "1.0.0".to_string(),
            created_at: Utc::now(),
            last_accessed: None,
            supported_networks: vec![BlockchainType::Bitcoin, BlockchainType::Ethereum],
            capabilities: vec![
                WalletCapability::TransactionSigning,
                WalletCapability::MessageSigning,
                WalletCapability::KeyDerivation,
                WalletCapability::Backup,
                WalletCapability::Recovery,
                WalletCapability::QuantumResistant,
            ],
            encrypted_keys: HashMap::new(),
            metadata: HashMap::new(),
        };
        
        Ok(Self {
            name,
            wallet_data: Arc::new(RwLock::new(wallet_data)),
            storage_path,
            status: Arc::new(RwLock::new(WalletStatus::Unlocked)),
            keys: Arc::new(RwLock::new(HashMap::new())),
        })
    }
    
    /// Load existing wallet
    pub async fn load(name: String) -> WalletResult<Self> {
        let storage_dir = dirs::home_dir()
            .unwrap_or_default()
            .join(".quid")
            .join("wallets");
        
        let storage_path = storage_dir.join(format!("{}.wallet", name));
        
        if !storage_path.exists() {
            return Err(WalletError::WalletNotFound(name));
        }
        
        let content = tokio::fs::read_to_string(&storage_path).await
            .map_err(|e| WalletError::IoError(e))?;
        
        let wallet_data: WalletData = serde_json::from_str(&content)
            .map_err(|e| WalletError::SerializationError(e))?;
        
        Ok(Self {
            name,
            wallet_data: Arc::new(RwLock::new(wallet_data)),
            storage_path,
            status: Arc::new(RwLock::new(WalletStatus::Locked)),
            keys: Arc::new(RwLock::new(HashMap::new())),
        })
    }
    
    /// Save wallet to storage
    async fn save(&self) -> WalletResult<()> {
        let wallet_data = self.wallet_data.read().await;
        let content = serde_json::to_string_pretty(&*wallet_data)
            .map_err(|e| WalletError::SerializationError(e))?;
        
        // Create parent directory if it doesn't exist
        if let Some(parent) = self.storage_path.parent() {
            tokio::fs::create_dir_all(parent).await
                .map_err(|e| WalletError::IoError(e))?;
        }
        
        tokio::fs::write(&self.storage_path, content).await
            .map_err(|e| WalletError::IoError(e))?;
        
        Ok(())
    }
    
    /// Encrypt and store key
    async fn encrypt_and_store_key(&self, network: BlockchainType, key: &KeyPair, passphrase: &SecretString) -> WalletResult<()> {
        use rand::RngCore;
        
        let mut rng = rand::thread_rng();
        let mut salt = [0u8; 32];
        let mut nonce = [0u8; 12];
        
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce);
        
        // TODO: Implement proper key derivation and encryption
        // For now, this is a placeholder
        let encrypted_data = format!("encrypted_key_{}", hex::encode(key.public_key().as_bytes())).into_bytes();
        
        let encrypted_key = EncryptedKey {
            network,
            encrypted_data,
            salt: salt.to_vec(),
            nonce: nonce.to_vec(),
        };
        
        let mut wallet_data = self.wallet_data.write().await;
        wallet_data.encrypted_keys.insert(network.to_string(), encrypted_key);
        
        Ok(())
    }
    
    /// Decrypt and load key
    async fn decrypt_and_load_key(&self, network: BlockchainType, passphrase: &SecretString) -> WalletResult<KeyPair> {
        let wallet_data = self.wallet_data.read().await;
        
        let encrypted_key = wallet_data.encrypted_keys.get(&network.to_string())
            .ok_or_else(|| WalletError::KeyDerivationFailed(format!("No key found for network: {}", network)))?;
        
        // TODO: Implement proper key decryption
        // For now, generate a new key (this is just for testing)
        let key_pair = KeyPair::generate(SecurityLevel::High)
            .map_err(|e| WalletError::KeyDerivationFailed(e.to_string()))?;
        
        Ok(key_pair)
    }
}

#[async_trait]
impl SoftwareWallet for BasicWallet {
    fn name(&self) -> &str {
        &self.name
    }
    
    async fn status(&self) -> WalletStatus {
        let status = self.status.read().await;
        status.clone()
    }
    
    async fn supported_networks(&self) -> Vec<BlockchainType> {
        let wallet_data = self.wallet_data.read().await;
        wallet_data.supported_networks.clone()
    }
    
    async fn last_used(&self) -> Option<DateTime<Utc>> {
        let wallet_data = self.wallet_data.read().await;
        wallet_data.last_accessed
    }
    
    async fn sign_transaction(&self, transaction: &Transaction, identity: &QuIDIdentity) -> WalletResult<Vec<u8>> {
        let status = self.status.read().await;
        if *status != WalletStatus::Unlocked {
            return Err(WalletError::AuthenticationFailed("Wallet is locked".to_string()));
        }
        drop(status);
        
        // Update last accessed time
        {
            let mut wallet_data = self.wallet_data.write().await;
            wallet_data.last_accessed = Some(Utc::now());
        }
        
        // Get key for the transaction's network
        let keys = self.keys.read().await;
        let key = keys.get(&transaction.network())
            .ok_or_else(|| WalletError::KeyDerivationFailed(format!("No key for network: {}", transaction.network())))?;
        
        // Sign the transaction
        let tx_bytes = transaction.to_bytes();
        let signature = key.sign(&tx_bytes)
            .map_err(|e| WalletError::SigningFailed(e.to_string()))?;
        
        // Save wallet state
        self.save().await?;
        
        Ok(signature)
    }
    
    async fn get_balance(&self, network: BlockchainType) -> WalletResult<u64> {
        let status = self.status.read().await;
        if *status != WalletStatus::Unlocked {
            return Err(WalletError::AuthenticationFailed("Wallet is locked".to_string()));
        }
        
        // TODO: Implement actual balance retrieval from blockchain adapters
        // For now, return mock balance
        Ok(50_000_000) // 0.5 BTC in satoshis
    }
    
    async fn disconnect(&self) -> WalletResult<()> {
        let mut status = self.status.write().await;
        *status = WalletStatus::Disconnected;
        
        // Clear keys from memory
        let mut keys = self.keys.write().await;
        keys.clear();
        
        Ok(())
    }
    
    async fn capabilities(&self) -> Vec<WalletCapability> {
        let wallet_data = self.wallet_data.read().await;
        wallet_data.capabilities.clone()
    }
    
    async fn lock(&self) -> WalletResult<()> {
        let mut status = self.status.write().await;
        *status = WalletStatus::Locked;
        
        // Clear keys from memory
        let mut keys = self.keys.write().await;
        keys.clear();
        
        Ok(())
    }
    
    async fn unlock(&self, passphrase: &SecretString) -> WalletResult<()> {
        // TODO: Implement proper passphrase verification
        
        // Load keys for all supported networks
        let supported_networks = self.supported_networks().await;
        let mut keys = self.keys.write().await;
        
        for network in supported_networks {
            let key = self.decrypt_and_load_key(network, passphrase).await?;
            keys.insert(network, key);
        }
        
        let mut status = self.status.write().await;
        *status = WalletStatus::Unlocked;
        
        Ok(())
    }
    
    async fn get_public_key(&self, network: BlockchainType) -> WalletResult<Vec<u8>> {
        let status = self.status.read().await;
        if *status != WalletStatus::Unlocked {
            return Err(WalletError::AuthenticationFailed("Wallet is locked".to_string()));
        }
        drop(status);
        
        let keys = self.keys.read().await;
        let key = keys.get(&network)
            .ok_or_else(|| WalletError::KeyDerivationFailed(format!("No key for network: {}", network)))?;
        
        Ok(key.public_key().as_bytes().to_vec())
    }
    
    async fn wallet_info(&self) -> WalletResult<SoftwareWalletInfo> {
        let wallet_data = self.wallet_data.read().await;
        let status = self.status.read().await;
        
        Ok(SoftwareWalletInfo {
            id: wallet_data.id.clone(),
            name: wallet_data.name.clone(),
            wallet_type: wallet_data.wallet_type.clone(),
            version: wallet_data.version.clone(),
            created_at: wallet_data.created_at,
            last_accessed: wallet_data.last_accessed,
            status: status.clone(),
            supported_networks: wallet_data.supported_networks.clone(),
            capabilities: wallet_data.capabilities.clone(),
        })
    }
    
    async fn create_backup(&self, backup_path: &PathBuf) -> WalletResult<()> {
        let wallet_data = self.wallet_data.read().await;
        let content = serde_json::to_string_pretty(&*wallet_data)
            .map_err(|e| WalletError::SerializationError(e))?;
        
        // Create backup directory if it doesn't exist
        if let Some(parent) = backup_path.parent() {
            tokio::fs::create_dir_all(parent).await
                .map_err(|e| WalletError::IoError(e))?;
        }
        
        tokio::fs::write(backup_path, content).await
            .map_err(|e| WalletError::IoError(e))?;
        
        Ok(())
    }
    
    async fn restore_from_backup(&self, backup_path: &PathBuf, _passphrase: &SecretString) -> WalletResult<()> {
        if !backup_path.exists() {
            return Err(WalletError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Backup file not found"
            )));
        }
        
        let content = tokio::fs::read_to_string(backup_path).await
            .map_err(|e| WalletError::IoError(e))?;
        
        let restored_data: WalletData = serde_json::from_str(&content)
            .map_err(|e| WalletError::SerializationError(e))?;
        
        let mut wallet_data = self.wallet_data.write().await;
        *wallet_data = restored_data;
        
        // Save restored data
        drop(wallet_data);
        self.save().await?;
        
        Ok(())
    }
}

/// Basic wallet factory
#[derive(Debug)]
pub struct BasicWalletFactory;

impl BasicWalletFactory {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl SoftwareWalletFactory for BasicWalletFactory {
    async fn create(&self, name: &str, identity: &QuIDIdentity) -> WalletResult<Arc<dyn SoftwareWallet>> {
        let wallet = BasicWallet::new(name.to_string(), identity).await?;
        wallet.save().await?;
        Ok(Arc::new(wallet))
    }
    
    async fn load(&self, name: &str) -> WalletResult<Arc<dyn SoftwareWallet>> {
        let wallet = BasicWallet::load(name.to_string()).await?;
        Ok(Arc::new(wallet))
    }
    
    fn wallet_type(&self) -> SoftwareWalletType {
        SoftwareWalletType::Basic
    }
    
    async fn exists(&self, name: &str) -> bool {
        let storage_dir = dirs::home_dir()
            .unwrap_or_default()
            .join(".quid")
            .join("wallets");
        
        let storage_path = storage_dir.join(format!("{}.wallet", name));
        storage_path.exists()
    }
}

/// HD wallet factory (placeholder)
#[derive(Debug)]
pub struct HDWalletFactory;

impl HDWalletFactory {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl SoftwareWalletFactory for HDWalletFactory {
    async fn create(&self, _name: &str, _identity: &QuIDIdentity) -> WalletResult<Arc<dyn SoftwareWallet>> {
        Err(WalletError::UnsupportedWalletType("HD wallet support not yet implemented".to_string()))
    }
    
    async fn load(&self, _name: &str) -> WalletResult<Arc<dyn SoftwareWallet>> {
        Err(WalletError::UnsupportedWalletType("HD wallet support not yet implemented".to_string()))
    }
    
    fn wallet_type(&self) -> SoftwareWalletType {
        SoftwareWalletType::HD
    }
    
    async fn exists(&self, _name: &str) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quid_core::SecurityLevel;
    
    #[tokio::test]
    async fn test_software_discovery() {
        let discovery = SoftwareDiscovery::new().await.unwrap();
        let wallets = discovery.discover().await.unwrap();
        
        // Should complete without error (may find 0 wallets)
        assert!(wallets.len() >= 0);
    }
    
    #[tokio::test]
    async fn test_basic_wallet_creation() {
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        let wallet = BasicWallet::new("test_wallet".to_string(), &identity).await.unwrap();
        
        assert_eq!(wallet.name(), "test_wallet");
        assert_eq!(wallet.status().await, WalletStatus::Unlocked);
        
        let networks = wallet.supported_networks().await;
        assert!(networks.contains(&BlockchainType::Bitcoin));
        assert!(networks.contains(&BlockchainType::Ethereum));
    }
    
    #[tokio::test]
    async fn test_basic_wallet_lock_unlock() {
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        let wallet = BasicWallet::new("test_wallet".to_string(), &identity).await.unwrap();
        
        assert_eq!(wallet.status().await, WalletStatus::Unlocked);
        
        wallet.lock().await.unwrap();
        assert_eq!(wallet.status().await, WalletStatus::Locked);
        
        let passphrase = SecretString::new("test_passphrase".to_string());
        wallet.unlock(&passphrase).await.unwrap();
        assert_eq!(wallet.status().await, WalletStatus::Unlocked);
    }
    
    #[tokio::test]
    async fn test_basic_wallet_factory() {
        let factory = BasicWalletFactory::new();
        assert_eq!(factory.wallet_type(), SoftwareWalletType::Basic);
        
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        let wallet = factory.create("test_factory_wallet", &identity).await.unwrap();
        
        assert_eq!(wallet.name(), "test_factory_wallet");
    }
}