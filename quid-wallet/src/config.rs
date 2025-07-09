//! Configuration for QuID wallet integration

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

/// Wallet configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    /// Hardware wallet configuration
    pub hardware: HardwareWalletConfig,
    /// Software wallet configuration
    pub software: SoftwareWalletConfig,
    /// Portfolio configuration
    pub portfolio: PortfolioConfig,
    /// Security configuration
    pub security: SecurityConfig,
    /// Storage configuration
    pub storage: StorageConfig,
    /// Discovery configuration
    pub discovery: DiscoveryConfig,
}

/// Hardware wallet configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareWalletConfig {
    /// Enable hardware wallet support
    pub enabled: bool,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Maximum retry attempts
    pub max_retries: u32,
    /// Supported wallet types
    pub supported_types: Vec<String>,
    /// Auto-discovery interval in seconds
    pub discovery_interval: u64,
    /// USB configuration
    pub usb: UsbConfig,
    /// Bluetooth configuration
    pub bluetooth: BluetoothConfig,
}

/// USB configuration for hardware wallets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbConfig {
    /// USB timeout in milliseconds
    pub timeout: u64,
    /// USB buffer size
    pub buffer_size: usize,
    /// Vendor ID filter
    pub vendor_id_filter: Option<Vec<u16>>,
    /// Product ID filter
    pub product_id_filter: Option<Vec<u16>>,
}

/// Bluetooth configuration for hardware wallets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BluetoothConfig {
    /// Bluetooth discovery timeout in seconds
    pub discovery_timeout: u64,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Maximum concurrent connections
    pub max_connections: u32,
}

/// Software wallet configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareWalletConfig {
    /// Enable software wallet support
    pub enabled: bool,
    /// Default wallet type
    pub default_type: String,
    /// Storage encryption
    pub encrypt_storage: bool,
    /// Backup configuration
    pub backup: BackupConfig,
    /// HD wallet configuration
    pub hd_wallet: HDWalletConfig,
}

/// Backup configuration for software wallets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    /// Enable automatic backups
    pub enabled: bool,
    /// Backup interval in seconds
    pub interval: u64,
    /// Backup directory
    pub directory: PathBuf,
    /// Maximum number of backups to keep
    pub max_backups: u32,
    /// Backup encryption
    pub encrypt_backups: bool,
}

/// HD wallet configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HDWalletConfig {
    /// Default derivation path
    pub default_derivation_path: String,
    /// Hardened derivation by default
    pub hardened_derivation: bool,
    /// Maximum derivation depth
    pub max_derivation_depth: u32,
    /// Gap limit for address generation
    pub gap_limit: u32,
}

/// Portfolio configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortfolioConfig {
    /// Enable portfolio tracking
    pub enabled: bool,
    /// Update interval in seconds
    pub update_interval: u64,
    /// Price feeds configuration
    pub price_feeds: PriceFeedsConfig,
    /// Supported networks
    pub supported_networks: Vec<String>,
    /// Historical data retention days
    pub history_retention_days: u32,
}

/// Price feeds configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceFeedsConfig {
    /// Primary price feed provider
    pub primary_provider: String,
    /// Fallback providers
    pub fallback_providers: Vec<String>,
    /// Update interval in seconds
    pub update_interval: u64,
    /// API keys for price providers
    pub api_keys: HashMap<String, String>,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Require PIN for wallet operations
    pub require_pin: bool,
    /// Require biometric authentication
    pub require_biometric: bool,
    /// Auto-lock timeout in seconds
    pub auto_lock_timeout: u64,
    /// Session timeout in seconds
    pub session_timeout: u64,
    /// Enable transaction confirmation
    pub require_confirmation: bool,
    /// Maximum transaction amount without confirmation
    pub max_amount_without_confirmation: u64,
    /// Enable audit logging
    pub audit_logging: bool,
    /// Secure element configuration
    pub secure_element: SecureElementConfig,
}

/// Secure element configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureElementConfig {
    /// Enable secure element usage
    pub enabled: bool,
    /// Required for key operations
    pub required_for_keys: bool,
    /// Required for signing
    pub required_for_signing: bool,
    /// Secure element type preference
    pub preferred_type: String,
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Base directory for wallet storage
    pub base_directory: PathBuf,
    /// Encryption configuration
    pub encryption: EncryptionConfig,
    /// Database configuration
    pub database: DatabaseConfig,
    /// Cache configuration
    pub cache: CacheConfig,
}

/// Encryption configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    /// Enable encryption
    pub enabled: bool,
    /// Encryption algorithm
    pub algorithm: String,
    /// Key derivation function
    pub key_derivation: String,
    /// Encryption parameters
    pub parameters: HashMap<String, String>,
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database type
    pub database_type: String,
    /// Database URL/path
    pub url: String,
    /// Connection pool size
    pub pool_size: u32,
    /// Connection timeout
    pub connection_timeout: u64,
}

/// Cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Enable caching
    pub enabled: bool,
    /// Cache size in MB
    pub size_mb: u64,
    /// Cache TTL in seconds
    pub ttl: u64,
    /// Cache type
    pub cache_type: String,
}

/// Discovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Enable automatic discovery
    pub enabled: bool,
    /// Discovery interval in seconds
    pub interval: u64,
    /// Discovery timeout in seconds
    pub timeout: u64,
    /// Maximum concurrent discoveries
    pub max_concurrent: u32,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            hardware: HardwareWalletConfig::default(),
            software: SoftwareWalletConfig::default(),
            portfolio: PortfolioConfig::default(),
            security: SecurityConfig::default(),
            storage: StorageConfig::default(),
            discovery: DiscoveryConfig::default(),
        }
    }
}

impl Default for HardwareWalletConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            connection_timeout: 30,
            max_retries: 3,
            supported_types: vec!["ledger".to_string(), "trezor".to_string()],
            discovery_interval: 60,
            usb: UsbConfig::default(),
            bluetooth: BluetoothConfig::default(),
        }
    }
}

impl Default for UsbConfig {
    fn default() -> Self {
        Self {
            timeout: 5000,
            buffer_size: 1024,
            vendor_id_filter: None,
            product_id_filter: None,
        }
    }
}

impl Default for BluetoothConfig {
    fn default() -> Self {
        Self {
            discovery_timeout: 30,
            connection_timeout: 15,
            max_connections: 5,
        }
    }
}

impl Default for SoftwareWalletConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_type: "hd".to_string(),
            encrypt_storage: true,
            backup: BackupConfig::default(),
            hd_wallet: HDWalletConfig::default(),
        }
    }
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: 86400, // 24 hours
            directory: dirs::home_dir().unwrap_or_default().join(".quid").join("backups"),
            max_backups: 7,
            encrypt_backups: true,
        }
    }
}

impl Default for HDWalletConfig {
    fn default() -> Self {
        Self {
            default_derivation_path: "m/44'/0'/0'/0".to_string(),
            hardened_derivation: true,
            max_derivation_depth: 10,
            gap_limit: 20,
        }
    }
}

impl Default for PortfolioConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            update_interval: 300, // 5 minutes
            price_feeds: PriceFeedsConfig::default(),
            supported_networks: vec!["bitcoin".to_string(), "ethereum".to_string()],
            history_retention_days: 365,
        }
    }
}

impl Default for PriceFeedsConfig {
    fn default() -> Self {
        Self {
            primary_provider: "coingecko".to_string(),
            fallback_providers: vec!["coinbase".to_string(), "kraken".to_string()],
            update_interval: 300,
            api_keys: HashMap::new(),
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            require_pin: true,
            require_biometric: false,
            auto_lock_timeout: 300, // 5 minutes
            session_timeout: 3600, // 1 hour
            require_confirmation: true,
            max_amount_without_confirmation: 1000000, // 0.01 BTC in satoshis
            audit_logging: true,
            secure_element: SecureElementConfig::default(),
        }
    }
}

impl Default for SecureElementConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            required_for_keys: true,
            required_for_signing: true,
            preferred_type: "tpm".to_string(),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            base_directory: dirs::home_dir().unwrap_or_default().join(".quid").join("wallets"),
            encryption: EncryptionConfig::default(),
            database: DatabaseConfig::default(),
            cache: CacheConfig::default(),
        }
    }
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            algorithm: "aes-256-gcm".to_string(),
            key_derivation: "pbkdf2".to_string(),
            parameters: HashMap::new(),
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            database_type: "sqlite".to_string(),
            url: "wallets.db".to_string(),
            pool_size: 10,
            connection_timeout: 30,
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            size_mb: 100,
            ttl: 3600, // 1 hour
            cache_type: "lru".to_string(),
        }
    }
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: 60,
            timeout: 30,
            max_concurrent: 5,
        }
    }
}

impl WalletConfig {
    /// Load configuration from file
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, std::io::Error> {
        let content = std::fs::read_to_string(path)?;
        let config: WalletConfig = toml::from_str(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(config)
    }
    
    /// Save configuration to file
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), std::io::Error> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, content)
    }
    
    /// Get default configuration directory
    pub fn default_config_dir() -> PathBuf {
        dirs::config_dir().unwrap_or_default().join("quid")
    }
    
    /// Get default configuration file path
    pub fn default_config_path() -> PathBuf {
        Self::default_config_dir().join("wallet.toml")
    }
    
    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        // Validate hardware configuration
        if self.hardware.enabled && self.hardware.connection_timeout == 0 {
            return Err("Hardware wallet connection timeout cannot be zero".to_string());
        }
        
        // Validate software configuration
        if self.software.enabled && self.software.default_type.is_empty() {
            return Err("Software wallet default type cannot be empty".to_string());
        }
        
        // Validate security configuration
        if self.security.auto_lock_timeout == 0 {
            return Err("Auto-lock timeout cannot be zero".to_string());
        }
        
        // Validate storage configuration
        if self.storage.base_directory.to_str().map_or(true, |s| s.is_empty()) {
            return Err("Storage base directory cannot be empty".to_string());
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_default_config() {
        let config = WalletConfig::default();
        assert!(config.hardware.enabled);
        assert!(config.software.enabled);
        assert!(config.portfolio.enabled);
        assert!(config.security.require_pin);
        assert!(config.storage.encryption.enabled);
        assert!(config.discovery.enabled);
    }

    #[test]
    fn test_config_validation() {
        let config = WalletConfig::default();
        assert!(config.validate().is_ok());
        
        let mut invalid_config = WalletConfig::default();
        invalid_config.hardware.connection_timeout = 0;
        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn test_config_file_operations() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("test_config.toml");
        
        let original_config = WalletConfig::default();
        original_config.save_to_file(&config_path).unwrap();
        
        let loaded_config = WalletConfig::load_from_file(&config_path).unwrap();
        
        assert_eq!(original_config.hardware.enabled, loaded_config.hardware.enabled);
        assert_eq!(original_config.software.enabled, loaded_config.software.enabled);
    }
}