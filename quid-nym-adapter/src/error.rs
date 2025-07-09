//! Error types for Nym adapter

use quid_core::QuIDError;
use crate::BlockchainError;

/// Result type for Nym adapter operations
pub type NymAdapterResult<T> = std::result::Result<T, NymAdapterError>;

/// Nym adapter error types
#[derive(thiserror::Error, Debug)]
pub enum NymAdapterError {
    #[error("Address derivation failed: {0}")]
    AddressDerivationFailed(String),
    
    #[error("Invalid address format: {0}")]
    InvalidAddressFormat(String),
    
    #[error("Transaction building failed: {0}")]
    TransactionBuildingFailed(String),
    
    #[error("Privacy operation failed: {0}")]
    PrivacyOperationFailed(String),
    
    #[error("Smart contract error: {0}")]
    SmartContractError(String),
    
    #[error("Insufficient balance for privacy level: required {required}, available {available}")]
    InsufficientBalanceForPrivacy { required: u128, available: u128 },
    
    #[error("Mixnet routing failed: {0}")]
    MixnetRoutingFailed(String),
    
    #[error("Zero-knowledge proof generation failed: {0}")]
    ZKProofGenerationFailed(String),
    
    #[error("Zero-knowledge proof verification failed: {0}")]
    ZKProofVerificationFailed(String),
    
    #[error("Shielding operation failed: {0}")]
    ShieldingFailed(String),
    
    #[error("Unshielding operation failed: {0}")]
    UnshieldingFailed(String),
    
    #[error("Anonymous transaction creation failed: {0}")]
    AnonymousTransactionFailed(String),
    
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("QuID error: {0}")]
    QuIDError(#[from] QuIDError),
    
    #[error("Blockchain error: {0}")]
    BlockchainError(#[from] BlockchainError),
    
    #[error("JSON serialization error: {0}")]
    JsonError(#[from] serde_json::Error),
    
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

impl NymAdapterError {
    /// Check if error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            NymAdapterError::NetworkError(_) => true,
            NymAdapterError::MixnetRoutingFailed(_) => true,
            NymAdapterError::TransactionBuildingFailed(_) => true,
            _ => false,
        }
    }
}