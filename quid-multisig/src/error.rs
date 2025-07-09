//! Error types for QuID multi-signature recovery

use quid_core::QuIDError;
use quid_wallet::WalletError;

/// Result type for multisig operations
pub type MultisigResult<T> = std::result::Result<T, MultisigError>;

/// Multi-signature error types
#[derive(thiserror::Error, Debug)]
pub enum MultisigError {
    #[error("Invalid threshold: must be greater than 0 and less than or equal to total shares")]
    InvalidThreshold,
    
    #[error("Invalid signature count: must be greater than 0")]
    InvalidSignatureCount,
    
    #[error("Invalid timeout: must be greater than 0")]
    InvalidTimeout,
    
    #[error("No participants provided")]
    NoParticipants,
    
    #[error("Invalid signature")]
    InvalidSignature,
    
    #[error("Invalid threshold signature")]
    InvalidThresholdSignature,
    
    #[error("Invalid social signature")]
    InvalidSocialSignature,
    
    #[error("Duplicate signature from signer: {0}")]
    DuplicateSignature(String),
    
    #[error("Recovery session not found: {0}")]
    RecoverySessionNotFound(String),
    
    #[error("Recovery session expired")]
    RecoverySessionExpired,
    
    #[error("Recovery session cancelled")]
    RecoverySessionCancelled,
    
    #[error("Recovery session already completed")]
    RecoverySessionCompleted,
    
    #[error("Insufficient signatures: have {have}, need {need}")]
    InsufficientSignatures { have: u32, need: u32 },
    
    #[error("Secret sharing failed: {0}")]
    SecretSharingFailed(String),
    
    #[error("Secret reconstruction failed: {0}")]
    SecretReconstructionFailed(String),
    
    #[error("Threshold signature aggregation failed: {0}")]
    ThresholdAggregationFailed(String),
    
    #[error("Social recovery failed: {0}")]
    SocialRecoveryFailed(String),
    
    #[error("Time lock not met")]
    TimeLockNotMet,
    
    #[error("Time lock expired")]
    TimeLockExpired,
    
    #[error("Emergency recovery not authorized")]
    EmergencyRecoveryNotAuthorized,
    
    #[error("Identity recovery failed: {0}")]
    IdentityRecoveryFailed(String),
    
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),
    
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    
    #[error("Storage error: {0}")]
    StorageError(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("Participant not found: {0}")]
    ParticipantNotFound(String),
    
    #[error("Trusted contact not found: {0}")]
    TrustedContactNotFound(String),
    
    #[error("Share not found: {0}")]
    ShareNotFound(String),
    
    #[error("Invalid share: {0}")]
    InvalidShare(String),
    
    #[error("Share verification failed: {0}")]
    ShareVerificationFailed(String),
    
    #[error("QuID error: {0}")]
    QuIDError(#[from] QuIDError),
    
    #[error("Wallet error: {0}")]
    WalletError(#[from] WalletError),
    
    #[error("JSON serialization error: {0}")]
    JsonError(#[from] serde_json::Error),
    
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("UUID error: {0}")]
    UuidError(#[from] uuid::Error),
    
    #[error("Bincode error: {0}")]
    BincodeError(#[from] bincode::Error),
}

impl MultisigError {
    /// Check if error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            MultisigError::InvalidThreshold => false,
            MultisigError::InvalidSignatureCount => false,
            MultisigError::InvalidTimeout => false,
            MultisigError::NoParticipants => false,
            MultisigError::InvalidSignature => false,
            MultisigError::InvalidThresholdSignature => false,
            MultisigError::InvalidSocialSignature => false,
            MultisigError::DuplicateSignature(_) => false,
            MultisigError::RecoverySessionNotFound(_) => false,
            MultisigError::RecoverySessionExpired => false,
            MultisigError::RecoverySessionCancelled => false,
            MultisigError::RecoverySessionCompleted => false,
            MultisigError::InsufficientSignatures { .. } => true,
            MultisigError::SecretSharingFailed(_) => true,
            MultisigError::SecretReconstructionFailed(_) => true,
            MultisigError::ThresholdAggregationFailed(_) => true,
            MultisigError::SocialRecoveryFailed(_) => true,
            MultisigError::TimeLockNotMet => true,
            MultisigError::TimeLockExpired => false,
            MultisigError::EmergencyRecoveryNotAuthorized => false,
            MultisigError::IdentityRecoveryFailed(_) => true,
            MultisigError::KeyDerivationFailed(_) => true,
            MultisigError::EncryptionFailed(_) => true,
            MultisigError::DecryptionFailed(_) => true,
            MultisigError::SerializationError(_) => true,
            MultisigError::DeserializationError(_) => true,
            MultisigError::StorageError(_) => true,
            MultisigError::NetworkError(_) => true,
            MultisigError::ConfigurationError(_) => false,
            MultisigError::ParticipantNotFound(_) => false,
            MultisigError::TrustedContactNotFound(_) => false,
            MultisigError::ShareNotFound(_) => false,
            MultisigError::InvalidShare(_) => false,
            MultisigError::ShareVerificationFailed(_) => true,
            MultisigError::QuIDError(_) => true,
            MultisigError::WalletError(_) => true,
            MultisigError::JsonError(_) => true,
            MultisigError::IoError(_) => true,
            MultisigError::UuidError(_) => true,
            MultisigError::BincodeError(_) => true,
        }
    }
    
    /// Get error category
    pub fn category(&self) -> MultisigErrorCategory {
        match self {
            MultisigError::InvalidThreshold | MultisigError::InvalidSignatureCount | MultisigError::InvalidTimeout => MultisigErrorCategory::Validation,
            MultisigError::NoParticipants => MultisigErrorCategory::Validation,
            MultisigError::InvalidSignature | MultisigError::InvalidThresholdSignature | MultisigError::InvalidSocialSignature => MultisigErrorCategory::Signature,
            MultisigError::DuplicateSignature(_) => MultisigErrorCategory::Signature,
            MultisigError::RecoverySessionNotFound(_) | MultisigError::RecoverySessionExpired | MultisigError::RecoverySessionCancelled | MultisigError::RecoverySessionCompleted => MultisigErrorCategory::Session,
            MultisigError::InsufficientSignatures { .. } => MultisigErrorCategory::Signature,
            MultisigError::SecretSharingFailed(_) | MultisigError::SecretReconstructionFailed(_) => MultisigErrorCategory::SecretSharing,
            MultisigError::ThresholdAggregationFailed(_) => MultisigErrorCategory::Threshold,
            MultisigError::SocialRecoveryFailed(_) => MultisigErrorCategory::Social,
            MultisigError::TimeLockNotMet | MultisigError::TimeLockExpired => MultisigErrorCategory::TimeLock,
            MultisigError::EmergencyRecoveryNotAuthorized => MultisigErrorCategory::Authorization,
            MultisigError::IdentityRecoveryFailed(_) => MultisigErrorCategory::Recovery,
            MultisigError::KeyDerivationFailed(_) => MultisigErrorCategory::Cryptography,
            MultisigError::EncryptionFailed(_) | MultisigError::DecryptionFailed(_) => MultisigErrorCategory::Cryptography,
            MultisigError::SerializationError(_) | MultisigError::DeserializationError(_) => MultisigErrorCategory::Serialization,
            MultisigError::StorageError(_) => MultisigErrorCategory::Storage,
            MultisigError::NetworkError(_) => MultisigErrorCategory::Network,
            MultisigError::ConfigurationError(_) => MultisigErrorCategory::Configuration,
            MultisigError::ParticipantNotFound(_) | MultisigError::TrustedContactNotFound(_) => MultisigErrorCategory::Participant,
            MultisigError::ShareNotFound(_) | MultisigError::InvalidShare(_) | MultisigError::ShareVerificationFailed(_) => MultisigErrorCategory::Share,
            MultisigError::QuIDError(_) => MultisigErrorCategory::QuID,
            MultisigError::WalletError(_) => MultisigErrorCategory::Wallet,
            MultisigError::JsonError(_) => MultisigErrorCategory::Serialization,
            MultisigError::IoError(_) => MultisigErrorCategory::IO,
            MultisigError::UuidError(_) => MultisigErrorCategory::UUID,
            MultisigError::BincodeError(_) => MultisigErrorCategory::Serialization,
        }
    }
}

/// Multi-signature error categories
#[derive(Debug, Clone, PartialEq)]
pub enum MultisigErrorCategory {
    Validation,
    Signature,
    Session,
    SecretSharing,
    Threshold,
    Social,
    TimeLock,
    Authorization,
    Recovery,
    Cryptography,
    Serialization,
    Storage,
    Network,
    Configuration,
    Participant,
    Share,
    QuID,
    Wallet,
    IO,
    UUID,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_error_categories() {
        let error = MultisigError::InvalidThreshold;
        assert_eq!(error.category(), MultisigErrorCategory::Validation);
        assert!(!error.is_recoverable());
        
        let error = MultisigError::InsufficientSignatures { have: 1, need: 2 };
        assert_eq!(error.category(), MultisigErrorCategory::Signature);
        assert!(error.is_recoverable());
        
        let error = MultisigError::SecretSharingFailed("test".to_string());
        assert_eq!(error.category(), MultisigErrorCategory::SecretSharing);
        assert!(error.is_recoverable());
        
        let error = MultisigError::TimeLockNotMet;
        assert_eq!(error.category(), MultisigErrorCategory::TimeLock);
        assert!(error.is_recoverable());
    }
    
    #[test]
    fn test_insufficient_signatures_error() {
        let error = MultisigError::InsufficientSignatures { have: 2, need: 3 };
        assert_eq!(error.category(), MultisigErrorCategory::Signature);
        assert!(error.is_recoverable());
        
        let error_string = error.to_string();
        assert!(error_string.contains("have 2"));
        assert!(error_string.contains("need 3"));
    }
    
    #[test]
    fn test_duplicate_signature_error() {
        let signer_id = "test_signer_123";
        let error = MultisigError::DuplicateSignature(signer_id.to_string());
        assert_eq!(error.category(), MultisigErrorCategory::Signature);
        assert!(!error.is_recoverable());
        
        let error_string = error.to_string();
        assert!(error_string.contains(signer_id));
    }
}