//! Utility functions for QuID blockchain integration

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{QuIDBlockchainError, QuIDBlockchainResult, BlockchainType};

/// Cryptocurrency units and conversions
pub mod units {
    /// Bitcoin units
    pub mod bitcoin {
        /// Satoshis per Bitcoin
        pub const SATOSHIS_PER_BTC: u64 = 100_000_000;
        
        /// Convert BTC to satoshis
        pub fn btc_to_satoshis(btc: f64) -> u64 {
            (btc * SATOSHIS_PER_BTC as f64) as u64
        }
        
        /// Convert satoshis to BTC
        pub fn satoshis_to_btc(satoshis: u64) -> f64 {
            satoshis as f64 / SATOSHIS_PER_BTC as f64
        }
        
        /// Format satoshis as BTC string
        pub fn format_btc(satoshis: u64) -> String {
            format!("{:.8} BTC", satoshis_to_btc(satoshis))
        }
    }
    
    /// Ethereum units
    pub mod ethereum {
        /// Wei per Ether
        pub const WEI_PER_ETH: u64 = 1_000_000_000_000_000_000;
        /// Gwei per Ether
        pub const GWEI_PER_ETH: u64 = 1_000_000_000;
        
        /// Convert ETH to wei
        pub fn eth_to_wei(eth: f64) -> u64 {
            (eth * WEI_PER_ETH as f64) as u64
        }
        
        /// Convert wei to ETH
        pub fn wei_to_eth(wei: u64) -> f64 {
            wei as f64 / WEI_PER_ETH as f64
        }
        
        /// Convert gwei to wei
        pub fn gwei_to_wei(gwei: u64) -> u64 {
            gwei * 1_000_000_000
        }
        
        /// Convert wei to gwei
        pub fn wei_to_gwei(wei: u64) -> u64 {
            wei / 1_000_000_000
        }
        
        /// Format wei as ETH string
        pub fn format_eth(wei: u64) -> String {
            format!("{:.6} ETH", wei_to_eth(wei))
        }
        
        /// Format wei as gwei string
        pub fn format_gwei(wei: u64) -> String {
            format!("{} gwei", wei_to_gwei(wei))
        }
    }
}

/// Address validation utilities
pub mod validation {
    use super::*;
    
    /// Validate Bitcoin address
    pub fn validate_bitcoin_address(address: &str, testnet: bool) -> bool {
        if address.is_empty() {
            return false;
        }
        
        // Legacy addresses
        if address.starts_with('1') && !testnet {
            return validate_base58_address(address);
        }
        if (address.starts_with('m') || address.starts_with('n')) && testnet {
            return validate_base58_address(address);
        }
        
        // SegWit addresses
        if address.starts_with("bc1") && !testnet {
            return validate_bech32_address(address);
        }
        if address.starts_with("tb1") && testnet {
            return validate_bech32_address(address);
        }
        
        false
    }
    
    /// Validate Ethereum address
    pub fn validate_ethereum_address(address: &str) -> bool {
        if !address.starts_with("0x") || address.len() != 42 {
            return false;
        }
        
        address[2..].chars().all(|c| c.is_ascii_hexdigit())
    }
    
    /// Validate Monero address
    pub fn validate_monero_address(address: &str, testnet: bool) -> bool {
        if address.is_empty() {
            return false;
        }
        
        let expected_prefix = if testnet { '9' } else { '4' };
        address.starts_with(expected_prefix) && address.len() >= 64
    }
    
    /// Validate Zcash address
    pub fn validate_zcash_address(address: &str, testnet: bool) -> bool {
        if address.is_empty() {
            return false;
        }
        
        if testnet {
            address.starts_with("tm") || address.starts_with("tn") || address.starts_with("ztestsapling")
        } else {
            address.starts_with('t') || address.starts_with("zs1")
        }
    }
    
    /// Validate Base58 address
    fn validate_base58_address(address: &str) -> bool {
        bs58::decode(address).into_vec().is_ok() && address.len() >= 26 && address.len() <= 35
    }
    
    /// Validate Bech32 address
    fn validate_bech32_address(address: &str) -> bool {
        // Simplified bech32 validation
        address.len() >= 14 && address.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    }
    
    /// Validate address for any blockchain type
    pub fn validate_address(address: &str, blockchain_type: &BlockchainType) -> bool {
        match blockchain_type {
            BlockchainType::Bitcoin => validate_bitcoin_address(address, false),
            BlockchainType::BitcoinTestnet => validate_bitcoin_address(address, true),
            BlockchainType::Ethereum | BlockchainType::EthereumGoerli | BlockchainType::EthereumSepolia => {
                validate_ethereum_address(address)
            }
            BlockchainType::Monero => validate_monero_address(address, false),
            BlockchainType::MoneroTestnet => validate_monero_address(address, true),
            BlockchainType::Zcash => validate_zcash_address(address, false),
            BlockchainType::ZcashTestnet => validate_zcash_address(address, true),
            BlockchainType::Custom(_) => {
                // For custom chains, do basic checks
                !address.is_empty() && address.len() >= 8
            }
        }
    }
}

/// Cryptographic utilities
pub mod crypto {
    use super::*;
    use sha2::{Sha256, Digest};
    use blake2::{Blake2b, Blake2s};
    
    /// Hash data with SHA256
    pub fn sha256(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
    
    /// Hash data with Blake2b
    pub fn blake2b(data: &[u8]) -> Vec<u8> {
        let mut hasher = Blake2b::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
    
    /// Hash data with Blake2s
    pub fn blake2s(data: &[u8]) -> Vec<u8> {
        let mut hasher = Blake2s::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
    
    /// Double SHA256 hash (used in Bitcoin)
    pub fn double_sha256(data: &[u8]) -> Vec<u8> {
        let first_hash = sha256(data);
        sha256(&first_hash)
    }
    
    /// Generate random bytes
    pub fn random_bytes(length: usize) -> Vec<u8> {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut bytes = vec![0u8; length];
        rng.fill_bytes(&mut bytes);
        bytes
    }
    
    /// Secure compare two byte arrays
    pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        
        let mut result = 0u8;
        for (a_byte, b_byte) in a.iter().zip(b.iter()) {
            result |= a_byte ^ b_byte;
        }
        result == 0
    }
}

/// Encoding utilities
pub mod encoding {
    use super::*;
    
    /// Encode bytes as hex string
    pub fn to_hex(data: &[u8]) -> String {
        hex::encode(data)
    }
    
    /// Decode hex string to bytes
    pub fn from_hex(hex_str: &str) -> QuIDBlockchainResult<Vec<u8>> {
        hex::decode(hex_str.trim_start_matches("0x"))
            .map_err(|e| QuIDBlockchainError::EncodingError(format!("Invalid hex: {}", e)))
    }
    
    /// Encode bytes as Base58
    pub fn to_base58(data: &[u8]) -> String {
        bs58::encode(data).into_string()
    }
    
    /// Decode Base58 string to bytes
    pub fn from_base58(base58_str: &str) -> QuIDBlockchainResult<Vec<u8>> {
        bs58::decode(base58_str).into_vec()
            .map_err(|e| QuIDBlockchainError::EncodingError(format!("Invalid Base58: {}", e)))
    }
    
    /// Encode bytes as Base64
    pub fn to_base64(data: &[u8]) -> String {
        base64::encode(data)
    }
    
    /// Decode Base64 string to bytes
    pub fn from_base64(base64_str: &str) -> QuIDBlockchainResult<Vec<u8>> {
        base64::decode(base64_str)
            .map_err(|e| QuIDBlockchainError::EncodingError(format!("Invalid Base64: {}", e)))
    }
}

/// Network utilities
pub mod network {
    use super::*;
    use std::time::Duration;
    
    /// Network endpoints
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct NetworkEndpoints {
        /// RPC endpoint
        pub rpc: String,
        /// WebSocket endpoint
        pub websocket: Option<String>,
        /// REST API endpoint
        pub rest: Option<String>,
        /// Explorer URL
        pub explorer: Option<String>,
    }
    
    /// Well-known network endpoints
    pub struct WellKnownEndpoints;
    
    impl WellKnownEndpoints {
        /// Get Bitcoin mainnet endpoints
        pub fn bitcoin_mainnet() -> NetworkEndpoints {
            NetworkEndpoints {
                rpc: "https://bitcoin-rpc.example.com".to_string(),
                websocket: Some("wss://bitcoin-ws.example.com".to_string()),
                rest: Some("https://bitcoin-api.example.com".to_string()),
                explorer: Some("https://blockstream.info".to_string()),
            }
        }
        
        /// Get Ethereum mainnet endpoints
        pub fn ethereum_mainnet() -> NetworkEndpoints {
            NetworkEndpoints {
                rpc: "https://mainnet.infura.io/v3/YOUR-PROJECT-ID".to_string(),
                websocket: Some("wss://mainnet.infura.io/ws/v3/YOUR-PROJECT-ID".to_string()),
                rest: Some("https://api.etherscan.io/api".to_string()),
                explorer: Some("https://etherscan.io".to_string()),
            }
        }
        
        /// Get endpoints for blockchain type
        pub fn get_endpoints(blockchain_type: &BlockchainType) -> Option<NetworkEndpoints> {
            match blockchain_type {
                BlockchainType::Bitcoin => Some(Self::bitcoin_mainnet()),
                BlockchainType::Ethereum => Some(Self::ethereum_mainnet()),
                _ => None,
            }
        }
    }
    
    /// Check if URL is reachable
    pub async fn check_connectivity(url: &str, timeout: Duration) -> bool {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build();
        
        if let Ok(client) = client {
            client.head(url).send().await.is_ok()
        } else {
            false
        }
    }
    
    /// Get optimal RPC endpoint from list
    pub async fn get_optimal_endpoint(endpoints: &[String], timeout: Duration) -> Option<String> {
        for endpoint in endpoints {
            if check_connectivity(endpoint, timeout).await {
                return Some(endpoint.clone());
            }
        }
        None
    }
}

/// Transaction utilities
pub mod transaction {
    use super::*;
    use crate::{Transaction, TransactionStatus};
    
    /// Transaction statistics
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct TransactionStats {
        /// Total transaction count
        pub total_count: u64,
        /// Confirmed transactions
        pub confirmed_count: u64,
        /// Pending transactions
        pub pending_count: u64,
        /// Failed transactions
        pub failed_count: u64,
        /// Total volume
        pub total_volume: u64,
        /// Average fee
        pub average_fee: u64,
    }
    
    /// Calculate transaction statistics
    pub fn calculate_stats(transactions: &[Transaction]) -> TransactionStats {
        let mut stats = TransactionStats {
            total_count: transactions.len() as u64,
            confirmed_count: 0,
            pending_count: 0,
            failed_count: 0,
            total_volume: 0,
            average_fee: 0,
        };
        
        let mut total_fees = 0u64;
        
        for tx in transactions {
            stats.total_volume += tx.amount;
            total_fees += tx.fee;
            
            match &tx.status {
                TransactionStatus::Confirmed { .. } => stats.confirmed_count += 1,
                TransactionStatus::Pending | TransactionStatus::Broadcast => stats.pending_count += 1,
                TransactionStatus::Failed { .. } => stats.failed_count += 1,
                _ => {}
            }
        }
        
        if !transactions.is_empty() {
            stats.average_fee = total_fees / transactions.len() as u64;
        }
        
        stats
    }
    
    /// Estimate confirmation time
    pub fn estimate_confirmation_time(
        blockchain_type: &BlockchainType,
        confirmation_target: u32,
    ) -> Duration {
        let block_time = match blockchain_type {
            BlockchainType::Bitcoin | BlockchainType::BitcoinTestnet => 600, // 10 minutes
            BlockchainType::Ethereum | BlockchainType::EthereumGoerli | BlockchainType::EthereumSepolia => 15, // 15 seconds
            BlockchainType::Monero | BlockchainType::MoneroTestnet => 120, // 2 minutes
            BlockchainType::Zcash | BlockchainType::ZcashTestnet => 150, // 2.5 minutes
            BlockchainType::Custom(_) => 60, // Default 1 minute
        };
        
        Duration::from_secs(block_time * confirmation_target as u64)
    }
    
    /// Check if transaction is final
    pub fn is_final(tx: &Transaction, required_confirmations: u32) -> bool {
        match &tx.status {
            TransactionStatus::Confirmed { confirmations } => *confirmations >= required_confirmations,
            _ => false,
        }
    }
}

/// Fee estimation utilities
pub mod fees {
    use super::*;
    
    /// Fee estimation strategy
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum FeeEstimationStrategy {
        /// Conservative (high priority)
        Conservative,
        /// Standard (normal priority)
        Standard,
        /// Economic (low priority)
        Economic,
        /// Custom fee rate
        Custom(u64),
    }
    
    /// Fee rate information
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct FeeRates {
        /// Conservative fee rate
        pub conservative: u64,
        /// Standard fee rate
        pub standard: u64,
        /// Economic fee rate
        pub economic: u64,
        /// Timestamp of fee rates
        pub timestamp: chrono::DateTime<chrono::Utc>,
    }
    
    /// Estimate transaction fee
    pub fn estimate_fee(
        blockchain_type: &BlockchainType,
        strategy: &FeeEstimationStrategy,
        transaction_size: u64,
    ) -> u64 {
        let base_rate = match blockchain_type {
            BlockchainType::Bitcoin | BlockchainType::BitcoinTestnet => {
                match strategy {
                    FeeEstimationStrategy::Conservative => 50, // sat/vB
                    FeeEstimationStrategy::Standard => 20,
                    FeeEstimationStrategy::Economic => 5,
                    FeeEstimationStrategy::Custom(rate) => *rate,
                }
            }
            BlockchainType::Ethereum | BlockchainType::EthereumGoerli | BlockchainType::EthereumSepolia => {
                match strategy {
                    FeeEstimationStrategy::Conservative => 50_000_000_000, // 50 gwei
                    FeeEstimationStrategy::Standard => 20_000_000_000,     // 20 gwei
                    FeeEstimationStrategy::Economic => 10_000_000_000,     // 10 gwei
                    FeeEstimationStrategy::Custom(rate) => *rate,
                }
            }
            _ => {
                match strategy {
                    FeeEstimationStrategy::Conservative => 1000,
                    FeeEstimationStrategy::Standard => 500,
                    FeeEstimationStrategy::Economic => 100,
                    FeeEstimationStrategy::Custom(rate) => *rate,
                }
            }
        };
        
        base_rate * transaction_size
    }
    
    /// Get default fee rates
    pub fn get_default_fee_rates(blockchain_type: &BlockchainType) -> FeeRates {
        match blockchain_type {
            BlockchainType::Bitcoin | BlockchainType::BitcoinTestnet => FeeRates {
                conservative: 50,
                standard: 20,
                economic: 5,
                timestamp: chrono::Utc::now(),
            },
            BlockchainType::Ethereum | BlockchainType::EthereumGoerli | BlockchainType::EthereumSepolia => FeeRates {
                conservative: 50_000_000_000,
                standard: 20_000_000_000,
                economic: 10_000_000_000,
                timestamp: chrono::Utc::now(),
            },
            _ => FeeRates {
                conservative: 1000,
                standard: 500,
                economic: 100,
                timestamp: chrono::Utc::now(),
            },
        }
    }
}

/// Derivation path utilities
pub mod derivation {
    use super::*;
    
    /// BIP44 derivation path
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DerivationPath {
        /// Purpose (usually 44 for BIP44)
        pub purpose: u32,
        /// Coin type
        pub coin_type: u32,
        /// Account index
        pub account: u32,
        /// Change flag (0 for external, 1 for internal)
        pub change: u32,
        /// Address index
        pub address_index: u32,
    }
    
    impl DerivationPath {
        /// Create BIP44 path for Bitcoin
        pub fn bitcoin(account: u32, change: u32, address_index: u32) -> Self {
            Self {
                purpose: 44,
                coin_type: 0, // Bitcoin
                account,
                change,
                address_index,
            }
        }
        
        /// Create BIP44 path for Ethereum
        pub fn ethereum(account: u32, change: u32, address_index: u32) -> Self {
            Self {
                purpose: 44,
                coin_type: 60, // Ethereum
                account,
                change,
                address_index,
            }
        }
        
        /// Convert to string format
        pub fn to_string(&self) -> String {
            format!("m/{}'/{}'/{}'/{}/{}", 
                self.purpose, self.coin_type, self.account, self.change, self.address_index)
        }
        
        /// Parse from string format
        pub fn from_string(path: &str) -> QuIDBlockchainResult<Self> {
            let parts: Vec<&str> = path.trim_start_matches("m/").split('/').collect();
            
            if parts.len() != 5 {
                return Err(QuIDBlockchainError::ConfigurationError(
                    "Invalid derivation path format".to_string()
                ));
            }
            
            let purpose = parts[0].trim_end_matches('\'').parse()
                .map_err(|_| QuIDBlockchainError::ConfigurationError("Invalid purpose".to_string()))?;
            let coin_type = parts[1].trim_end_matches('\'').parse()
                .map_err(|_| QuIDBlockchainError::ConfigurationError("Invalid coin type".to_string()))?;
            let account = parts[2].trim_end_matches('\'').parse()
                .map_err(|_| QuIDBlockchainError::ConfigurationError("Invalid account".to_string()))?;
            let change = parts[3].parse()
                .map_err(|_| QuIDBlockchainError::ConfigurationError("Invalid change".to_string()))?;
            let address_index = parts[4].parse()
                .map_err(|_| QuIDBlockchainError::ConfigurationError("Invalid address index".to_string()))?;
            
            Ok(Self {
                purpose,
                coin_type,
                account,
                change,
                address_index,
            })
        }
    }
    
    /// Get coin type for blockchain
    pub fn get_coin_type(blockchain_type: &BlockchainType) -> u32 {
        match blockchain_type {
            BlockchainType::Bitcoin => 0,
            BlockchainType::BitcoinTestnet => 1,
            BlockchainType::Ethereum | BlockchainType::EthereumGoerli | BlockchainType::EthereumSepolia => 60,
            BlockchainType::Monero | BlockchainType::MoneroTestnet => 128,
            BlockchainType::Zcash | BlockchainType::ZcashTestnet => 133,
            BlockchainType::Custom(_) => 999, // Custom coin type
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitcoin_units() {
        assert_eq!(units::bitcoin::btc_to_satoshis(1.0), 100_000_000);
        assert_eq!(units::bitcoin::satoshis_to_btc(100_000_000), 1.0);
        assert_eq!(units::bitcoin::format_btc(50_000_000), "0.50000000 BTC");
    }

    #[test]
    fn test_ethereum_units() {
        assert_eq!(units::ethereum::eth_to_wei(1.0), 1_000_000_000_000_000_000);
        assert_eq!(units::ethereum::wei_to_eth(1_000_000_000_000_000_000), 1.0);
        assert_eq!(units::ethereum::gwei_to_wei(20), 20_000_000_000);
    }

    #[test]
    fn test_address_validation() {
        assert!(validation::validate_ethereum_address("0x742C3cF9bF1bD96C6d0cC8B2A5d4bbf8b8C8A3F8"));
        assert!(!validation::validate_ethereum_address("742C3cF9bF1bD96C6d0cC8B2A5d4bbf8b8C8A3F8"));
        
        assert!(validation::validate_address(
            "0x742C3cF9bF1bD96C6d0cC8B2A5d4bbf8b8C8A3F8",
            &BlockchainType::Ethereum
        ));
    }

    #[test]
    fn test_encoding() {
        let data = b"hello world";
        let hex = encoding::to_hex(data);
        assert_eq!(hex, "68656c6c6f20776f726c64");
        
        let decoded = encoding::from_hex(&hex).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_derivation_path() {
        let path = derivation::DerivationPath::bitcoin(0, 0, 0);
        assert_eq!(path.to_string(), "m/44'/0'/0'/0/0");
        
        let parsed = derivation::DerivationPath::from_string("m/44'/60'/0'/0/1").unwrap();
        assert_eq!(parsed.coin_type, 60);
        assert_eq!(parsed.address_index, 1);
    }

    #[test]
    fn test_crypto_functions() {
        let data = b"test data";
        let hash1 = crypto::sha256(data);
        let hash2 = crypto::sha256(data);
        assert_eq!(hash1, hash2);
        
        let double_hash = crypto::double_sha256(data);
        assert_eq!(double_hash, crypto::sha256(&hash1));
    }
}