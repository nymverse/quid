//! Type definitions for QuID wallet integration

use quid_core::QuIDIdentity;
// use quid_blockchain::{BlockchainType, Transaction};
use crate::{BlockchainType, Transaction};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{WalletResult};

/// Wallet instance enum for hardware and software wallets
#[derive(Debug)]
pub enum WalletInstance {
    Hardware(Arc<dyn crate::hardware::HardwareWallet>),
    Software(Arc<dyn crate::software::SoftwareWallet>),
}

/// Wallet type enumeration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum WalletType {
    Hardware,
    Software,
}

/// Hardware wallet types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HardwareWalletType {
    Ledger,
    Trezor,
    KeepKey,
    BitBox,
    ColdCard,
    Generic,
}

impl ToString for HardwareWalletType {
    fn to_string(&self) -> String {
        match self {
            HardwareWalletType::Ledger => "ledger".to_string(),
            HardwareWalletType::Trezor => "trezor".to_string(),
            HardwareWalletType::KeepKey => "keepkey".to_string(),
            HardwareWalletType::BitBox => "bitbox".to_string(),
            HardwareWalletType::ColdCard => "coldcard".to_string(),
            HardwareWalletType::Generic => "generic".to_string(),
        }
    }
}

/// Software wallet types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SoftwareWalletType {
    Basic,
    HD,
    MultiSig,
    Hierarchical,
    Deterministic,
}

impl ToString for SoftwareWalletType {
    fn to_string(&self) -> String {
        match self {
            SoftwareWalletType::Basic => "basic".to_string(),
            SoftwareWalletType::HD => "hd".to_string(),
            SoftwareWalletType::MultiSig => "multisig".to_string(),
            SoftwareWalletType::Hierarchical => "hierarchical".to_string(),
            SoftwareWalletType::Deterministic => "deterministic".to_string(),
        }
    }
}

/// Wallet status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum WalletStatus {
    Connected,
    Disconnected,
    Connecting,
    Error(String),
    Locked,
    Unlocked,
}

/// Wallet information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletInfo {
    pub id: String,
    pub name: String,
    pub wallet_type: WalletType,
    pub status: WalletStatus,
    pub supported_networks: Vec<BlockchainType>,
    pub last_used: Option<DateTime<Utc>>,
}

/// Hardware wallet information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareWalletInfo {
    pub id: String,
    pub name: String,
    pub wallet_type: HardwareWalletType,
    pub model: String,
    pub firmware_version: Option<String>,
    pub manufacturer: String,
    pub serial_number: Option<String>,
    pub connection_type: ConnectionType,
    pub status: WalletStatus,
    pub supported_networks: Vec<BlockchainType>,
    pub capabilities: Vec<WalletCapability>,
}

/// Software wallet information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareWalletInfo {
    pub id: String,
    pub name: String,
    pub wallet_type: SoftwareWalletType,
    pub version: String,
    pub created_at: DateTime<Utc>,
    pub last_accessed: Option<DateTime<Utc>>,
    pub status: WalletStatus,
    pub supported_networks: Vec<BlockchainType>,
    pub capabilities: Vec<WalletCapability>,
}

/// Connection type for hardware wallets
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConnectionType {
    USB,
    Bluetooth,
    NFC,
    WebUSB,
    HID,
}

/// Wallet capabilities
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum WalletCapability {
    TransactionSigning,
    MessageSigning,
    KeyDerivation,
    SecureKeyStorage,
    BiometricAuth,
    PinProtection,
    Backup,
    Recovery,
    MultiSignature,
    HierarchicalDeterministic,
    QuantumResistant,
}

/// Wallet discovery result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletDiscoveryResult {
    pub hardware_wallets: Vec<HardwareWalletInfo>,
    pub software_wallets: Vec<SoftwareWalletInfo>,
    pub total_found: usize,
    pub discovery_time: DateTime<Utc>,
}

/// Wallet authentication request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAuthRequest {
    pub request_id: String,
    pub wallet_id: String,
    pub identity: QuIDIdentity,
    pub challenge: Vec<u8>,
    pub network: BlockchainType,
    pub timestamp: DateTime<Utc>,
}

/// Wallet authentication response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAuthResponse {
    pub request_id: String,
    pub wallet_id: String,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
    pub timestamp: DateTime<Utc>,
    pub success: bool,
}

/// Wallet transaction request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletTransactionRequest {
    pub request_id: String,
    pub wallet_id: String,
    pub transaction: Transaction,
    pub identity: QuIDIdentity,
    pub confirmation_required: bool,
    pub timestamp: DateTime<Utc>,
}

/// Wallet transaction response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletTransactionResponse {
    pub request_id: String,
    pub wallet_id: String,
    pub signature: Vec<u8>,
    pub signed_transaction: Vec<u8>,
    pub transaction_id: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub success: bool,
}

/// Wallet balance information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletBalance {
    pub network: BlockchainType,
    pub address: String,
    pub balance: u64,
    pub confirmed_balance: u64,
    pub pending_balance: u64,
    pub last_updated: DateTime<Utc>,
}

/// Wallet account information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAccount {
    pub id: String,
    pub name: String,
    pub network: BlockchainType,
    pub address: String,
    pub public_key: Vec<u8>,
    pub derivation_path: Option<String>,
    pub balance: Option<WalletBalance>,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
}

/// Wallet security settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSecuritySettings {
    pub require_pin: bool,
    pub require_biometric: bool,
    pub auto_lock_timeout: Option<u64>, // seconds
    pub require_confirmation: bool,
    pub enable_recovery: bool,
    pub backup_enabled: bool,
    pub encryption_enabled: bool,
}

/// Wallet operation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletOperationResult {
    pub operation_id: String,
    pub wallet_id: String,
    pub operation_type: WalletOperationType,
    pub success: bool,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
    pub duration_ms: u64,
    pub timestamp: DateTime<Utc>,
}

/// Wallet operation types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum WalletOperationType {
    Connect,
    Disconnect,
    Authenticate,
    SignTransaction,
    SignMessage,
    GetBalance,
    GetAccounts,
    DeriveKey,
    Backup,
    Recovery,
}

/// Wallet metrics for monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletMetrics {
    pub wallet_id: String,
    pub total_operations: u64,
    pub successful_operations: u64,
    pub failed_operations: u64,
    pub avg_response_time_ms: f64,
    pub last_operation: Option<DateTime<Utc>>,
    pub uptime_percentage: f64,
}

impl WalletInstance {
    /// Get wallet name
    pub async fn name(&self) -> String {
        match self {
            WalletInstance::Hardware(wallet) => wallet.name().to_string(),
            WalletInstance::Software(wallet) => wallet.name().to_string(),
        }
    }

    /// Get wallet status
    pub async fn status(&self) -> WalletStatus {
        match self {
            WalletInstance::Hardware(wallet) => wallet.status().await,
            WalletInstance::Software(wallet) => wallet.status().await,
        }
    }

    /// Get supported networks
    pub async fn supported_networks(&self) -> Vec<BlockchainType> {
        match self {
            WalletInstance::Hardware(wallet) => wallet.supported_networks().await,
            WalletInstance::Software(wallet) => wallet.supported_networks().await,
        }
    }

    /// Sign transaction
    pub async fn sign_transaction(
        &self,
        transaction: &Transaction,
        identity: &QuIDIdentity,
    ) -> WalletResult<Vec<u8>> {
        match self {
            WalletInstance::Hardware(wallet) => wallet.sign_transaction(transaction, identity).await,
            WalletInstance::Software(wallet) => wallet.sign_transaction(transaction, identity).await,
        }
    }

    /// Get balance
    pub async fn get_balance(&self, network: BlockchainType) -> WalletResult<u64> {
        match self {
            WalletInstance::Hardware(wallet) => wallet.get_balance(network).await,
            WalletInstance::Software(wallet) => wallet.get_balance(network).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_types() {
        let hw_type = HardwareWalletType::Ledger;
        assert_eq!(hw_type.to_string(), "ledger");
        
        let sw_type = SoftwareWalletType::HD;
        assert_eq!(sw_type.to_string(), "hd");
    }

    #[test]
    fn test_wallet_info_serialization() {
        let info = WalletInfo {
            id: "test-wallet".to_string(),
            name: "Test Wallet".to_string(),
            wallet_type: WalletType::Hardware,
            status: WalletStatus::Connected,
            supported_networks: vec![BlockchainType::Bitcoin],
            last_used: Some(Utc::now()),
        };
        
        let serialized = serde_json::to_string(&info).unwrap();
        let deserialized: WalletInfo = serde_json::from_str(&serialized).unwrap();
        
        assert_eq!(info.id, deserialized.id);
        assert_eq!(info.name, deserialized.name);
        assert_eq!(info.wallet_type, deserialized.wallet_type);
    }

    #[test]
    fn test_wallet_capabilities() {
        let capabilities = vec![
            WalletCapability::TransactionSigning,
            WalletCapability::QuantumResistant,
            WalletCapability::SecureKeyStorage,
        ];
        
        assert!(capabilities.contains(&WalletCapability::TransactionSigning));
        assert!(capabilities.contains(&WalletCapability::QuantumResistant));
    }
}