//! Configuration for Nym adapter

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use crate::PrivacyLevel;

/// Nym adapter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NymAdapterConfig {
    /// Network configuration
    pub network: NetworkConfig,
    /// Address generation configuration
    pub address_config: AddressConfig,
    /// Transaction configuration
    pub transaction_config: TransactionConfig,
    /// Privacy configuration
    pub privacy_config: PrivacyConfig,
    /// Smart contract configuration
    pub smart_contract_config: SmartContractConfig,
    /// Mixnet configuration
    pub mixnet_config: MixnetConfig,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Network type (mainnet, testnet, devnet)
    pub network_type: NetworkType,
    /// RPC endpoint
    pub rpc_endpoint: String,
    /// Chain ID
    pub chain_id: String,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Request timeout in seconds
    pub request_timeout: u64,
    /// Maximum retries
    pub max_retries: u32,
}

/// Network type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum NetworkType {
    Mainnet,
    Testnet,
    Devnet,
}

/// Address configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressConfig {
    /// Address prefix
    pub prefix: String,
    /// Address derivation path
    pub derivation_path: String,
    /// Default privacy level
    pub default_privacy_level: PrivacyLevel,
    /// Address validation enabled
    pub validation_enabled: bool,
}

/// Transaction configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionConfig {
    /// Default gas limit
    pub default_gas_limit: u64,
    /// Gas price
    pub gas_price: u128,
    /// Transaction timeout in seconds
    pub timeout: u64,
    /// Confirmation blocks required
    pub confirmation_blocks: u32,
}

/// Privacy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyConfig {
    /// Enable privacy features
    pub enabled: bool,
    /// Default privacy level
    pub default_level: PrivacyLevel,
    /// Shielded pool parameters
    pub shielded_pool: ShieldedPoolConfig,
    /// Anonymous transaction parameters
    pub anonymous_tx: AnonymousTransactionConfig,
    /// Zero-knowledge proof parameters
    pub zk_proof: ZKProofConfig,
}

/// Shielded pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldedPoolConfig {
    /// Pool contract address
    pub pool_address: String,
    /// Merkle tree depth
    pub merkle_depth: u32,
    /// Note encryption key
    pub encryption_key: Vec<u8>,
    /// Nullifier window size
    pub nullifier_window: u32,
}

/// Anonymous transaction configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymousTransactionConfig {
    /// Ring size for mixing
    pub ring_size: u32,
    /// Decoy selection algorithm
    pub decoy_algorithm: String,
    /// Minimum confirmations for decoys
    pub min_decoy_confirmations: u32,
    /// Maximum transaction amount for anonymity
    pub max_anonymous_amount: u128,
}

/// Zero-knowledge proof configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZKProofConfig {
    /// Proof system type
    pub proof_system: String,
    /// Trusted setup parameters path
    pub trusted_setup_path: Option<PathBuf>,
    /// Proof generation timeout
    pub proof_timeout: u64,
    /// Verification timeout
    pub verification_timeout: u64,
}

/// Smart contract configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartContractConfig {
    /// VM type (EVM, WASM, etc.)
    pub vm_type: String,
    /// Default gas limit for contract calls
    pub default_gas_limit: u64,
    /// Gas price
    pub gas_price: u128,
    /// Contract deployment enabled
    pub deployment_enabled: bool,
}

/// Mixnet configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixnetConfig {
    /// Enable mixnet routing
    pub enabled: bool,
    /// Entry gateway address
    pub entry_gateway: Option<String>,
    /// Mix node selection strategy
    pub node_selection: NodeSelectionStrategy,
    /// Packet delay parameters
    pub delays: DelayConfig,
    /// Routing layers
    pub routing_layers: u32,
}

/// Node selection strategy
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum NodeSelectionStrategy {
    Random,
    Weighted,
    Latency,
    Reputation,
}

/// Delay configuration for mixnet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelayConfig {
    /// Minimum delay in milliseconds
    pub min_delay: u32,
    /// Maximum delay in milliseconds
    pub max_delay: u32,
    /// Delay distribution type
    pub distribution: DelayDistribution,
}

/// Delay distribution type
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum DelayDistribution {
    Uniform,
    Exponential,
    Poisson,
}

impl Default for NymAdapterConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig::default(),
            address_config: AddressConfig::default(),
            transaction_config: TransactionConfig::default(),
            privacy_config: PrivacyConfig::default(),
            smart_contract_config: SmartContractConfig::default(),
            mixnet_config: MixnetConfig::default(),
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            network_type: NetworkType::Testnet,
            rpc_endpoint: "https://testnet-rpc.nym.network".to_string(),
            chain_id: "nym-testnet".to_string(),
            connection_timeout: 30,
            request_timeout: 10,
            max_retries: 3,
        }
    }
}

impl Default for AddressConfig {
    fn default() -> Self {
        Self {
            prefix: "nym".to_string(),
            derivation_path: "m/44'/118'/0'/0/0".to_string(),
            default_privacy_level: PrivacyLevel::Shielded,
            validation_enabled: true,
        }
    }
}

impl Default for TransactionConfig {
    fn default() -> Self {
        Self {
            default_gas_limit: 200_000,
            gas_price: 25,
            timeout: 60,
            confirmation_blocks: 1,
        }
    }
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_level: PrivacyLevel::Shielded,
            shielded_pool: ShieldedPoolConfig::default(),
            anonymous_tx: AnonymousTransactionConfig::default(),
            zk_proof: ZKProofConfig::default(),
        }
    }
}

impl Default for ShieldedPoolConfig {
    fn default() -> Self {
        Self {
            pool_address: "nym1shielded...".to_string(),
            merkle_depth: 32,
            encryption_key: vec![0; 32],
            nullifier_window: 1000,
        }
    }
}

impl Default for AnonymousTransactionConfig {
    fn default() -> Self {
        Self {
            ring_size: 11,
            decoy_algorithm: "weighted".to_string(),
            min_decoy_confirmations: 10,
            max_anonymous_amount: 1_000_000_000, // 1 billion units
        }
    }
}

impl Default for ZKProofConfig {
    fn default() -> Self {
        Self {
            proof_system: "groth16".to_string(),
            trusted_setup_path: None,
            proof_timeout: 30,
            verification_timeout: 5,
        }
    }
}

impl Default for SmartContractConfig {
    fn default() -> Self {
        Self {
            vm_type: "CosmWasm".to_string(),
            default_gas_limit: 1_000_000,
            gas_price: 50,
            deployment_enabled: false,
        }
    }
}

impl Default for MixnetConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            entry_gateway: None,
            node_selection: NodeSelectionStrategy::Weighted,
            delays: DelayConfig::default(),
            routing_layers: 3,
        }
    }
}

impl Default for DelayConfig {
    fn default() -> Self {
        Self {
            min_delay: 100,
            max_delay: 5000,
            distribution: DelayDistribution::Exponential,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_config_defaults() {
        let config = NymAdapterConfig::default();
        assert_eq!(config.network.network_type, NetworkType::Testnet);
        assert_eq!(config.address_config.prefix, "nym");
        assert_eq!(config.privacy_config.default_level, PrivacyLevel::Shielded);
        assert!(config.privacy_config.enabled);
        assert!(config.mixnet_config.enabled);
    }
    
    #[test]
    fn test_network_type_serialization() {
        let network_type = NetworkType::Mainnet;
        let serialized = serde_json::to_string(&network_type).unwrap();
        let deserialized: NetworkType = serde_json::from_str(&serialized).unwrap();
        assert_eq!(network_type, deserialized);
    }
    
    #[test]
    fn test_node_selection_strategy() {
        let strategy = NodeSelectionStrategy::Weighted;
        let serialized = serde_json::to_string(&strategy).unwrap();
        let deserialized: NodeSelectionStrategy = serde_json::from_str(&serialized).unwrap();
        assert_eq!(strategy, deserialized);
    }
    
    #[test]
    fn test_delay_distribution() {
        let distribution = DelayDistribution::Exponential;
        let serialized = serde_json::to_string(&distribution).unwrap();
        let deserialized: DelayDistribution = serde_json::from_str(&serialized).unwrap();
        assert_eq!(distribution, deserialized);
    }
}