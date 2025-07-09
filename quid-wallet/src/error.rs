//! Error types for QuID wallet integration

use quid_core::QuIDError;
// use quid_blockchain::QuIDBlockchainError;

// Temporary stub for blockchain error
#[derive(Debug, thiserror::Error)]
pub enum QuIDBlockchainError {
    #[error("Blockchain error: {0}")]
    Generic(String),
}

/// Result type for wallet operations
pub type WalletResult<T> = std::result::Result<T, WalletError>;

/// Wallet error types
#[derive(thiserror::Error, Debug)]
pub enum WalletError {
    #[error("Wallet not found: {0}")]
    WalletNotFound(String),
    
    #[error("Wallet connection failed: {0}")]
    ConnectionFailed(String),
    
    #[error("Wallet disconnection failed: {0}")]
    DisconnectionFailed(String),
    
    #[error("Hardware wallet error: {0}")]
    HardwareWalletError(String),
    
    #[error("Software wallet error: {0}")]
    SoftwareWalletError(String),
    
    #[error("Unsupported wallet type: {0}")]
    UnsupportedWalletType(String),
    
    #[error("Wallet discovery failed: {0}")]
    DiscoveryFailed(String),
    
    #[error("Transaction signing failed: {0}")]
    SigningFailed(String),
    
    #[error("Balance retrieval failed: {0}")]
    BalanceRetrievalFailed(String),
    
    #[error("Portfolio management error: {0}")]
    PortfolioError(String),
    
    #[error("Wallet configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("USB/HID communication error: {0}")]
    CommunicationError(String),
    
    #[error("Wallet authentication failed: {0}")]
    AuthenticationFailed(String),
    
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),
    
    #[error("Wallet timeout: {0}")]
    Timeout(String),
    
    #[error("Insufficient funds: required {required}, available {available}")]
    InsufficientFunds { required: u64, available: u64 },
    
    #[error("QuID core error: {0}")]
    QuIDError(#[from] QuIDError),
    
    #[error("Blockchain error: {0}")]
    BlockchainError(#[from] QuIDBlockchainError),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("USB error: {0}")]
    UsbError(String),
    
    #[error("Bluetooth error: {0}")]
    BluetoothError(String),
}

impl WalletError {
    /// Check if error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            WalletError::WalletNotFound(_) => false,
            WalletError::UnsupportedWalletType(_) => false,
            WalletError::ConfigurationError(_) => false,
            WalletError::ConnectionFailed(_) => true,
            WalletError::CommunicationError(_) => true,
            WalletError::Timeout(_) => true,
            WalletError::AuthenticationFailed(_) => true,
            _ => false,
        }
    }
    
    /// Get error category
    pub fn category(&self) -> WalletErrorCategory {
        match self {
            WalletError::WalletNotFound(_) => WalletErrorCategory::NotFound,
            WalletError::ConnectionFailed(_) | WalletError::DisconnectionFailed(_) => WalletErrorCategory::Connection,
            WalletError::HardwareWalletError(_) => WalletErrorCategory::Hardware,
            WalletError::SoftwareWalletError(_) => WalletErrorCategory::Software,
            WalletError::UnsupportedWalletType(_) => WalletErrorCategory::Unsupported,
            WalletError::DiscoveryFailed(_) => WalletErrorCategory::Discovery,
            WalletError::SigningFailed(_) => WalletErrorCategory::Signing,
            WalletError::BalanceRetrievalFailed(_) => WalletErrorCategory::Balance,
            WalletError::PortfolioError(_) => WalletErrorCategory::Portfolio,
            WalletError::ConfigurationError(_) => WalletErrorCategory::Configuration,
            WalletError::CommunicationError(_) | WalletError::UsbError(_) | WalletError::BluetoothError(_) => WalletErrorCategory::Communication,
            WalletError::AuthenticationFailed(_) => WalletErrorCategory::Authentication,
            WalletError::KeyDerivationFailed(_) => WalletErrorCategory::KeyDerivation,
            WalletError::Timeout(_) => WalletErrorCategory::Timeout,
            WalletError::InsufficientFunds { .. } => WalletErrorCategory::InsufficientFunds,
            WalletError::QuIDError(_) => WalletErrorCategory::QuID,
            WalletError::BlockchainError(_) => WalletErrorCategory::Blockchain,
            WalletError::SerializationError(_) => WalletErrorCategory::Serialization,
            WalletError::IoError(_) => WalletErrorCategory::IO,
        }
    }
}

/// Wallet error categories for handling
#[derive(Debug, Clone, PartialEq)]
pub enum WalletErrorCategory {
    NotFound,
    Connection,
    Hardware,
    Software,
    Unsupported,
    Discovery,
    Signing,
    Balance,
    Portfolio,
    Configuration,
    Communication,
    Authentication,
    KeyDerivation,
    Timeout,
    InsufficientFunds,
    QuID,
    Blockchain,
    Serialization,
    IO,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_categories() {
        let error = WalletError::WalletNotFound("test".to_string());
        assert_eq!(error.category(), WalletErrorCategory::NotFound);
        assert!(!error.is_recoverable());
        
        let error = WalletError::ConnectionFailed("test".to_string());
        assert_eq!(error.category(), WalletErrorCategory::Connection);
        assert!(error.is_recoverable());
    }
    
    #[test]
    fn test_insufficient_funds_error() {
        let error = WalletError::InsufficientFunds {
            required: 1000,
            available: 500,
        };
        assert_eq!(error.category(), WalletErrorCategory::InsufficientFunds);
        assert!(!error.is_recoverable());
    }
}