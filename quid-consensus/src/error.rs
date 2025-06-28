//! Error types for the consensus system

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConsensusError {
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),
    
    #[error("QuID error: {0}")]
    QuIDError(#[from] quid_core::QuIDError),

    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),
    
    #[error("Duplicate transaction")]
    DuplicateTransaction,
    
    #[error("Transaction pool is full")]
    TransactionPoolFull,
    
    #[error("Invalid nonce: expected {expected}, got {got}")]
    InvalidNonce { expected: u64, got: u64 },
    
    #[error("Insufficient balance: need {needed}, have {available}")]
    InsufficientBalance { needed: u64, available: u64 },
    
    #[error("Invalid block: {0}")]
    InvalidBlock(String),
    
    #[error("Block validation failed: {0}")]
    BlockValidation(String),
    
    #[error("Consensus failure: {0}")]
    ConsensusFailure(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Validator error: {0}")]
    ValidatorError(String),
}
