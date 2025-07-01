//! Configuration management for QuID blockchain integration

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use crate::{QuIDBlockchainError, QuIDBlockchainResult};

/// Main blockchain configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuIDBlockchainConfig {
    /// Bitcoin configuration
    pub bitcoin: crate::bitcoin::BitcoinConfig,
    /// Ethereum configuration
    pub ethereum: crate::ethereum::EthereumConfig,
    /// Privacy coins configuration
    pub privacy: crate::privacy::PrivacyConfig,
    /// Universal adapter configuration
    pub universal: UniversalConfig,
    /// General blockchain settings
    pub settings: BlockchainSettings,
}

/// Universal blockchain adapter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniversalConfig {
    /// Enable universal adapter
    pub enabled: bool,
    /// Custom blockchain configurations
    pub custom_blockchains: Vec<CustomBlockchainConfig>,
    /// Default adapter settings
    pub default_settings: AdapterSettings,
}

/// Custom blockchain configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomBlockchainConfig {
    /// Blockchain name
    pub name: String,
    /// Chain ID (if applicable)
    pub chain_id: Option<u64>,
    /// RPC endpoint
    pub rpc_url: String,
    /// WebSocket endpoint
    pub ws_url: Option<String>,
    /// Native token symbol
    pub native_token: String,
    /// Block time in seconds
    pub block_time: u64,
    /// Confirmation requirements
    pub confirmation_blocks: u32,
    /// Address format
    pub address_format: AddressFormat,
    /// Signature algorithm
    pub signature_algorithm: SignatureAlgorithm,
}

/// Address format types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AddressFormat {
    /// Bitcoin-style Base58Check
    Base58Check,
    /// Ethereum-style hex with 0x prefix
    EthereumHex,
    /// Bech32 (SegWit style)
    Bech32,
    /// Custom format with regex pattern
    Custom(String),
}

/// Signature algorithm types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// ECDSA secp256k1 (Bitcoin, Ethereum)
    EcdsaSecp256k1,
    /// Ed25519 (newer chains)
    Ed25519,
    /// SR25519 (Substrate/Polkadot)
    Sr25519,
    /// QuID quantum-resistant
    QuIDQuantumResistant,
    /// Hybrid classical + quantum-resistant
    Hybrid,
}

/// Adapter settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterSettings {
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Request retry attempts
    pub retry_attempts: u32,
    /// Request retry delay in milliseconds
    pub retry_delay: u64,
    /// Enable caching
    pub enable_caching: bool,
    /// Cache TTL in seconds
    pub cache_ttl: u64,
}

/// General blockchain settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainSettings {
    /// Enable quantum-resistant features globally
    pub quantum_resistant: bool,
    /// Default derivation path
    pub default_derivation_path: String,
    /// Account discovery depth
    pub account_discovery_depth: u32,
    /// Transaction confirmation requirements
    pub default_confirmations: u32,
    /// Fee estimation strategy
    pub fee_strategy: FeeStrategy,
    /// Network selection
    pub preferred_networks: Vec<String>,
    /// Security level
    pub security_level: SecurityLevel,
}

/// Fee estimation strategies
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FeeStrategy {
    /// Conservative (high priority)
    Conservative,
    /// Standard (normal priority)
    Standard,
    /// Economic (low priority)
    Economic,
    /// Custom fee rates
    Custom(CustomFeeRates),
}

/// Custom fee rates for different networks
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CustomFeeRates {
    /// Bitcoin fee rate (sat/vB)
    pub bitcoin: Option<u64>,
    /// Ethereum gas price (gwei)
    pub ethereum: Option<u64>,
    /// Other network fees
    pub other: std::collections::HashMap<String, u64>,
}

/// Security level configuration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// Basic security (faster operations)
    Basic,
    /// Standard security (balanced)
    Standard,
    /// High security (slower but more secure)
    High,
    /// Maximum security (quantum-resistant only)
    Maximum,
}

impl Default for QuIDBlockchainConfig {
    fn default() -> Self {
        Self {
            bitcoin: crate::bitcoin::BitcoinConfig::default(),
            ethereum: crate::ethereum::EthereumConfig::default(),
            privacy: crate::privacy::PrivacyConfig::default(),
            universal: UniversalConfig::default(),
            settings: BlockchainSettings::default(),
        }
    }
}

impl Default for UniversalConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            custom_blockchains: Vec::new(),
            default_settings: AdapterSettings::default(),
        }
    }
}

impl Default for AdapterSettings {
    fn default() -> Self {
        Self {
            connection_timeout: 30,
            retry_attempts: 3,
            retry_delay: 1000,
            enable_caching: true,
            cache_ttl: 300,
        }
    }
}

impl Default for BlockchainSettings {
    fn default() -> Self {
        Self {
            quantum_resistant: true,
            default_derivation_path: "m/44'/0'/0'/0/0".to_string(),
            account_discovery_depth: 20,
            default_confirmations: 6,
            fee_strategy: FeeStrategy::Standard,
            preferred_networks: vec![
                "bitcoin".to_string(),
                "ethereum".to_string(),
            ],
            security_level: SecurityLevel::Standard,
        }
    }
}

impl QuIDBlockchainConfig {
    /// Create configuration from file
    pub fn from_file(path: &Path) -> QuIDBlockchainResult<Self> {
        let config_str = std::fs::read_to_string(path)
            .map_err(|e| QuIDBlockchainError::ConfigurationError(
                format!("Failed to read config file: {}", e)
            ))?;

        if path.extension().and_then(|s| s.to_str()) == Some("toml") {
            toml::from_str(&config_str)
                .map_err(|e| QuIDBlockchainError::ConfigurationError(
                    format!("Failed to parse TOML config: {}", e)
                ))
        } else {
            serde_json::from_str(&config_str)
                .map_err(|e| QuIDBlockchainError::ConfigurationError(
                    format!("Failed to parse JSON config: {}", e)
                ))
        }
    }

    /// Save configuration to file
    pub fn save_to_file(&self, path: &Path) -> QuIDBlockchainResult<()> {
        let config_str = if path.extension().and_then(|s| s.to_str()) == Some("toml") {
            toml::to_string_pretty(self)
                .map_err(|e| QuIDBlockchainError::ConfigurationError(
                    format!("Failed to serialize config as TOML: {}", e)
                ))?
        } else {
            serde_json::to_string_pretty(self)
                .map_err(|e| QuIDBlockchainError::ConfigurationError(
                    format!("Failed to serialize config as JSON: {}", e)
                ))?
        };

        std::fs::write(path, config_str)
            .map_err(|e| QuIDBlockchainError::ConfigurationError(
                format!("Failed to write config file: {}", e)
            ))?;

        Ok(())
    }

    /// Validate configuration
    pub fn validate(&self) -> QuIDBlockchainResult<()> {
        // Validate derivation path format
        if !self.settings.default_derivation_path.starts_with("m/") {
            return Err(QuIDBlockchainError::ConfigurationError(
                "Invalid derivation path format".to_string()
            ));
        }

        // Validate account discovery depth
        if self.settings.account_discovery_depth == 0 || self.settings.account_discovery_depth > 100 {
            return Err(QuIDBlockchainError::ConfigurationError(
                "Account discovery depth must be between 1 and 100".to_string()
            ));
        }

        // Validate confirmation requirements
        if self.settings.default_confirmations > 1000 {
            return Err(QuIDBlockchainError::ConfigurationError(
                "Default confirmations cannot exceed 1000".to_string()
            ));
        }

        // Validate custom blockchain configurations
        for blockchain in &self.universal.custom_blockchains {
            blockchain.validate()?;
        }

        Ok(())
    }

    /// Get configuration for specific network
    pub fn get_network_config(&self, network: &str) -> Option<&CustomBlockchainConfig> {
        self.universal.custom_blockchains
            .iter()
            .find(|config| config.name == network)
    }

    /// Get default configuration directory
    pub fn get_default_config_dir() -> PathBuf {
        crate::get_default_config_dir()
    }

    /// Get default configuration file path
    pub fn get_default_config_file() -> PathBuf {
        Self::get_default_config_dir().join("blockchain.toml")
    }

    /// Create default configuration file if it doesn't exist
    pub fn ensure_default_config() -> QuIDBlockchainResult<PathBuf> {
        let config_file = Self::get_default_config_file();
        
        if !config_file.exists() {
            // Create directory if it doesn't exist
            if let Some(parent) = config_file.parent() {
                std::fs::create_dir_all(parent)?;
            }

            // Save default configuration
            let default_config = Self::default();
            default_config.save_to_file(&config_file)?;
            
            tracing::info!("Created default configuration at: {}", config_file.display());
        }

        Ok(config_file)
    }
}

impl CustomBlockchainConfig {
    /// Validate custom blockchain configuration
    pub fn validate(&self) -> QuIDBlockchainResult<()> {
        // Validate RPC URL
        if self.rpc_url.is_empty() {
            return Err(QuIDBlockchainError::ConfigurationError(
                format!("RPC URL cannot be empty for blockchain: {}", self.name)
            ));
        }

        // Validate block time
        if self.block_time == 0 {
            return Err(QuIDBlockchainError::ConfigurationError(
                format!("Block time must be greater than 0 for blockchain: {}", self.name)
            ));
        }

        // Validate confirmation blocks
        if self.confirmation_blocks > 1000 {
            return Err(QuIDBlockchainError::ConfigurationError(
                format!("Confirmation blocks cannot exceed 1000 for blockchain: {}", self.name)
            ));
        }

        Ok(())
    }

    /// Get estimated confirmation time
    pub fn estimated_confirmation_time(&self) -> u64 {
        self.block_time * self.confirmation_blocks as u64
    }
}

impl SecurityLevel {
    /// Get minimum confirmations for security level
    pub fn min_confirmations(&self) -> u32 {
        match self {
            SecurityLevel::Basic => 1,
            SecurityLevel::Standard => 6,
            SecurityLevel::High => 12,
            SecurityLevel::Maximum => 24,
        }
    }

    /// Check if quantum-resistant features are required
    pub fn requires_quantum_resistant(&self) -> bool {
        matches!(self, SecurityLevel::Maximum)
    }
}

/// Configuration builder for easy construction
pub struct ConfigBuilder {
    config: QuIDBlockchainConfig,
}

impl ConfigBuilder {
    /// Create new configuration builder
    pub fn new() -> Self {
        Self {
            config: QuIDBlockchainConfig::default(),
        }
    }

    /// Enable/disable quantum-resistant features
    pub fn quantum_resistant(mut self, enabled: bool) -> Self {
        self.config.settings.quantum_resistant = enabled;
        self.config.bitcoin.quantum_resistant = enabled;
        self.config.ethereum.quantum_resistant = enabled;
        self.config.privacy.quantum_resistant = enabled;
        self
    }

    /// Set security level
    pub fn security_level(mut self, level: SecurityLevel) -> Self {
        self.config.settings.security_level = level;
        self
    }

    /// Set default derivation path
    pub fn derivation_path(mut self, path: &str) -> Self {
        self.config.settings.default_derivation_path = path.to_string();
        self
    }

    /// Add custom blockchain
    pub fn add_custom_blockchain(mut self, blockchain: CustomBlockchainConfig) -> Self {
        self.config.universal.custom_blockchains.push(blockchain);
        self
    }

    /// Set fee strategy
    pub fn fee_strategy(mut self, strategy: FeeStrategy) -> Self {
        self.config.settings.fee_strategy = strategy;
        self
    }

    /// Build configuration
    pub fn build(self) -> QuIDBlockchainResult<QuIDBlockchainConfig> {
        self.config.validate()?;
        Ok(self.config)
    }
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_default_config() {
        let config = QuIDBlockchainConfig::default();
        assert!(config.settings.quantum_resistant);
        assert_eq!(config.settings.security_level, SecurityLevel::Standard);
    }

    #[test]
    fn test_config_validation() {
        let config = QuIDBlockchainConfig::default();
        assert!(config.validate().is_ok());

        let mut invalid_config = config;
        invalid_config.settings.default_derivation_path = "invalid".to_string();
        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn test_security_levels() {
        assert_eq!(SecurityLevel::Basic.min_confirmations(), 1);
        assert_eq!(SecurityLevel::Standard.min_confirmations(), 6);
        assert_eq!(SecurityLevel::High.min_confirmations(), 12);
        assert_eq!(SecurityLevel::Maximum.min_confirmations(), 24);

        assert!(!SecurityLevel::Standard.requires_quantum_resistant());
        assert!(SecurityLevel::Maximum.requires_quantum_resistant());
    }

    #[test]
    fn test_config_builder() {
        let config = ConfigBuilder::new()
            .quantum_resistant(true)
            .security_level(SecurityLevel::High)
            .derivation_path("m/84'/0'/0'/0/0")
            .build()
            .unwrap();

        assert!(config.settings.quantum_resistant);
        assert_eq!(config.settings.security_level, SecurityLevel::High);
        assert_eq!(config.settings.default_derivation_path, "m/84'/0'/0'/0/0");
    }

    #[test]
    fn test_custom_blockchain_validation() {
        let valid_blockchain = CustomBlockchainConfig {
            name: "polygon".to_string(),
            chain_id: Some(137),
            rpc_url: "https://polygon-rpc.com".to_string(),
            ws_url: None,
            native_token: "MATIC".to_string(),
            block_time: 2,
            confirmation_blocks: 20,
            address_format: AddressFormat::EthereumHex,
            signature_algorithm: SignatureAlgorithm::EcdsaSecp256k1,
        };

        assert!(valid_blockchain.validate().is_ok());

        let invalid_blockchain = CustomBlockchainConfig {
            rpc_url: "".to_string(),
            ..valid_blockchain
        };

        assert!(invalid_blockchain.validate().is_err());
    }

    #[test]
    fn test_config_file_operations() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("test_config.toml");

        let config = QuIDBlockchainConfig::default();
        config.save_to_file(&config_path).unwrap();

        let loaded_config = QuIDBlockchainConfig::from_file(&config_path).unwrap();
        assert_eq!(config.settings.quantum_resistant, loaded_config.settings.quantum_resistant);
    }
}