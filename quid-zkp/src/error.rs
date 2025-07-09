//! Error types for Zero-Knowledge Proof operations

use quid_core::QuIDError;

/// Result type for ZKP operations
pub type ZKPResult<T> = std::result::Result<T, ZKPError>;

/// Zero-Knowledge Proof error types
#[derive(thiserror::Error, Debug)]
pub enum ZKPError {
    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),
    
    #[error("Proof verification failed: {0}")]
    ProofVerificationFailed(String),
    
    #[error("Witness generation failed: {0}")]
    WitnessGenerationFailed(String),
    
    #[error("Circuit compilation failed: {0}")]
    CircuitCompilationFailed(String),
    
    #[error("Trusted setup failed: {0}")]
    TrustedSetupFailed(String),
    
    #[error("Unsupported proof system: {0:?}")]
    UnsupportedProofSystem(crate::ProofSystem),
    
    #[error("Invalid proof format: {0}")]
    InvalidProofFormat(String),
    
    #[error("Invalid witness format: {0}")]
    InvalidWitnessFormat(String),
    
    #[error("Invalid circuit parameters: {0}")]
    InvalidCircuitParameters(String),
    
    #[error("Commitment generation failed: {0}")]
    CommitmentGenerationFailed(String),
    
    #[error("Commitment verification failed: {0}")]
    CommitmentVerificationFailed(String),
    
    #[error("Commitment not found: {0}")]
    CommitmentNotFound(String),
    
    #[error("Merkle tree construction failed: {0}")]
    MerkleTreeConstructionFailed(String),
    
    #[error("Merkle proof generation failed: {0}")]
    MerkleProofGenerationFailed(String),
    
    #[error("Merkle tree not found: {0}")]
    MerkleTreeNotFound(String),
    
    #[error("Element not in set")]
    ElementNotInSet,
    
    #[error("Invalid range parameters: {0}")]
    InvalidRangeParameters(String),
    
    #[error("Range proof failed: {0}")]
    RangeProofFailed(String),
    
    #[error("Attribute proof failed: {0}")]
    AttributeProofFailed(String),
    
    #[error("Membership proof failed: {0}")]
    MembershipProofFailed(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    
    #[error("Cryptographic error: {0}")]
    CryptographicError(String),
    
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("Timeout error: {0}")]
    TimeoutError(String),
    
    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),
    
    #[error("QuID error: {0}")]
    QuIDError(#[from] QuIDError),
    
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Parse error: {0}")]
    ParseError(String),
    
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    #[error("Arithmetic error: {0}")]
    ArithmeticError(String),
}

impl ZKPError {
    /// Check if error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            ZKPError::TimeoutError(_) => true,
            ZKPError::ResourceExhausted(_) => true,
            ZKPError::ProofGenerationFailed(_) => true,
            _ => false,
        }
    }
    
    /// Check if error is cryptographic
    pub fn is_cryptographic(&self) -> bool {
        matches!(
            self,
            ZKPError::ProofGenerationFailed(_) |
            ZKPError::ProofVerificationFailed(_) |
            ZKPError::CryptographicError(_) |
            ZKPError::CommitmentGenerationFailed(_) |
            ZKPError::CommitmentVerificationFailed(_) |
            ZKPError::TrustedSetupFailed(_)
        )
    }
    
    /// Check if error is configuration related
    pub fn is_configuration_error(&self) -> bool {
        matches!(
            self,
            ZKPError::ConfigurationError(_) |
            ZKPError::InvalidCircuitParameters(_) |
            ZKPError::UnsupportedProofSystem(_)
        )
    }
    
    /// Check if error is input validation related
    pub fn is_validation_error(&self) -> bool {
        matches!(
            self,
            ZKPError::InvalidInput(_) |
            ZKPError::InvalidProofFormat(_) |
            ZKPError::InvalidWitnessFormat(_) |
            ZKPError::InvalidRangeParameters(_) |
            ZKPError::ElementNotInSet
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProofSystem;
    
    #[test]
    fn test_error_classification() {
        let timeout_err = ZKPError::TimeoutError("operation timed out".to_string());
        assert!(timeout_err.is_recoverable());
        assert!(!timeout_err.is_cryptographic());
        assert!(!timeout_err.is_configuration_error());
        assert!(!timeout_err.is_validation_error());
        
        let crypto_err = ZKPError::ProofGenerationFailed("proof failed".to_string());
        assert!(crypto_err.is_recoverable());
        assert!(crypto_err.is_cryptographic());
        assert!(!crypto_err.is_configuration_error());
        assert!(!crypto_err.is_validation_error());
        
        let config_err = ZKPError::UnsupportedProofSystem(ProofSystem::ZkSNARK);
        assert!(!config_err.is_recoverable());
        assert!(!config_err.is_cryptographic());
        assert!(config_err.is_configuration_error());
        assert!(!config_err.is_validation_error());
        
        let validation_err = ZKPError::ElementNotInSet;
        assert!(!validation_err.is_recoverable());
        assert!(!validation_err.is_cryptographic());
        assert!(!validation_err.is_configuration_error());
        assert!(validation_err.is_validation_error());
    }
    
    #[test]
    fn test_error_display() {
        let err = ZKPError::ProofGenerationFailed("circuit too large".to_string());
        assert_eq!(err.to_string(), "Proof generation failed: circuit too large");
        
        let err = ZKPError::ElementNotInSet;
        assert_eq!(err.to_string(), "Element not in set");
        
        let err = ZKPError::UnsupportedProofSystem(ProofSystem::ZkSTARK);
        assert!(err.to_string().contains("Unsupported proof system"));
    }
}