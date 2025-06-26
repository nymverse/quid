//! Error types for QuID operations

use thiserror::Error;

#[derive(Error, Debug)]
pub enum QuIDError {
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),
    
    #[error("Invalid identity format: {0}")]
    InvalidIdentity(String),
    
    #[error("Extension error: {0}")]
    ExtensionError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Invalid security level")]
    InvalidSecurityLevel,
}