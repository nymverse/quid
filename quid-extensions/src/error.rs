//! Error types for QuID network adapters

use thiserror::Error;

/// Result type for adapter operations
pub type AdapterResult<T> = Result<T, AdapterError>;

/// Comprehensive error types for network adapter operations
#[derive(Error, Debug, Clone)]
pub enum AdapterError {
    /// Invalid network identifier
    #[error("Invalid network identifier: {0}")]
    InvalidNetwork(String),

    /// Adapter not found for the specified network
    #[error("No adapter found for network: {0}")]
    AdapterNotFound(String),

    /// Key derivation failed
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// Signature generation failed
    #[error("Signature generation failed: {0}")]
    SignatureFailed(String),

    /// Signature verification failed
    #[error("Signature verification failed: {0}")]
    VerificationFailed(String),

    /// Invalid authentication request
    #[error("Invalid authentication request: {0}")]
    InvalidRequest(String),

    /// Invalid authentication response
    #[error("Invalid authentication response: {0}")]
    InvalidResponse(String),

    /// Adapter configuration error
    #[error("Adapter configuration error: {0}")]
    ConfigurationError(String),

    /// Network-specific error
    #[error("Network error for {network}: {message}")]
    NetworkError { network: String, message: String },

    /// Cryptographic operation failed
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Operation timed out
    #[error("Operation timed out after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },

    /// Generic adapter error
    #[error("Adapter error: {0}")]
    Generic(String),
}

impl AdapterError {
    /// Create a new network-specific error
    pub fn network_error(network: &str, message: &str) -> Self {
        Self::NetworkError {
            network: network.to_string(),
            message: message.to_string(),
        }
    }

    /// Create a new timeout error
    pub fn timeout(timeout_ms: u64) -> Self {
        Self::Timeout { timeout_ms }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_error_creation() {
        let error = AdapterError::InvalidNetwork("test".to_string());
        assert!(error.to_string().contains("Invalid network identifier: test"));
    }

    #[test]
    fn test_network_error_helper() {
        let error = AdapterError::network_error("bitcoin", "connection failed");
        match error {
            AdapterError::NetworkError { network, message } => {
                assert_eq!(network, "bitcoin");
                assert_eq!(message, "connection failed");
            }
            _ => panic!("Expected NetworkError"),
        }
    }

    #[test]
    fn test_timeout_error_helper() {
        let error = AdapterError::timeout(5000);
        match error {
            AdapterError::Timeout { timeout_ms } => {
                assert_eq!(timeout_ms, 5000);
            }
            _ => panic!("Expected Timeout"),
        }
    }
}