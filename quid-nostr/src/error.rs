//! Error types for Nostr integration

use quid_core::QuIDError;

/// Result type for Nostr operations
pub type NostrResult<T> = std::result::Result<T, NostrError>;

/// Nostr integration error types
#[derive(thiserror::Error, Debug)]
pub enum NostrError {
    #[error("Event creation failed: {0}")]
    EventCreationFailed(String),
    
    #[error("Signing error: {0}")]
    SigningError(String),
    
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    
    #[error("Invalid event kind")]
    InvalidEventKind,
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    
    #[error("Relay error: {0}")]
    RelayError(String),
    
    #[error("Subscription failed: {0}")]
    SubscriptionFailed(String),
    
    #[error("Publish failed: {0}")]
    PublishFailed(String),
    
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    
    #[error("Decryption error: {0}")]
    DecryptionError(String),
    
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
    
    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),
    
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    
    #[error("Invalid event ID: {0}")]
    InvalidEventId(String),
    
    #[error("Filter error: {0}")]
    FilterError(String),
    
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("NIP not supported: {0}")]
    NipNotSupported(String),
    
    #[error("Lightning Network error: {0}")]
    LightningError(String),
    
    #[error("Zap payment failed: {0}")]
    ZapPaymentFailed(String),
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    
    #[error("Authorization failed: {0}")]
    AuthorizationFailed(String),
    
    #[error("Timeout error: {0}")]
    TimeoutError(String),
    
    #[error("Protocol error: {0}")]
    ProtocolError(String),
    
    #[error("QuID error: {0}")]
    QuIDError(#[from] QuIDError),
    
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),
    
    #[error("WebSocket error: {0}")]
    WebSocketError(String),
    
    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),
    
    #[error("Hex decode error: {0}")]
    HexError(#[from] hex::FromHexError),
    
    #[error("URL parse error: {0}")]
    UrlError(#[from] url::ParseError),
}

impl NostrError {
    /// Check if error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            NostrError::NetworkError(_) => true,
            NostrError::ConnectionFailed(_) => true,
            NostrError::RelayError(_) => true,
            NostrError::TimeoutError(_) => true,
            NostrError::RateLimitExceeded => true,
            _ => false,
        }
    }
    
    /// Check if error is authentication related
    pub fn is_auth_error(&self) -> bool {
        matches!(
            self,
            NostrError::AuthenticationFailed(_) | NostrError::AuthorizationFailed(_)
        )
    }
    
    /// Check if error is network related
    pub fn is_network_error(&self) -> bool {
        matches!(
            self,
            NostrError::NetworkError(_) |
            NostrError::ConnectionFailed(_) |
            NostrError::HttpError(_) |
            NostrError::WebSocketError(_) |
            NostrError::TimeoutError(_)
        )
    }
    
    /// Check if error is cryptographic
    pub fn is_crypto_error(&self) -> bool {
        matches!(
            self,
            NostrError::SigningError(_) |
            NostrError::VerificationFailed(_) |
            NostrError::EncryptionError(_) |
            NostrError::DecryptionError(_) |
            NostrError::InvalidSignature(_) |
            NostrError::InvalidPublicKey(_) |
            NostrError::InvalidPrivateKey(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_error_classification() {
        let network_err = NostrError::NetworkError("connection lost".to_string());
        assert!(network_err.is_recoverable());
        assert!(network_err.is_network_error());
        assert!(!network_err.is_auth_error());
        assert!(!network_err.is_crypto_error());
        
        let auth_err = NostrError::AuthenticationFailed("invalid token".to_string());
        assert!(!auth_err.is_recoverable());
        assert!(auth_err.is_auth_error());
        assert!(!auth_err.is_network_error());
        assert!(!auth_err.is_crypto_error());
        
        let crypto_err = NostrError::SigningError("invalid key".to_string());
        assert!(!crypto_err.is_recoverable());
        assert!(!crypto_err.is_auth_error());
        assert!(!crypto_err.is_network_error());
        assert!(crypto_err.is_crypto_error());
        
        let rate_limit_err = NostrError::RateLimitExceeded;
        assert!(rate_limit_err.is_recoverable());
    }
    
    #[test]
    fn test_error_display() {
        let err = NostrError::EventCreationFailed("missing content".to_string());
        assert_eq!(err.to_string(), "Event creation failed: missing content");
        
        let err = NostrError::InvalidEventKind;
        assert_eq!(err.to_string(), "Invalid event kind");
        
        let err = NostrError::RateLimitExceeded;
        assert_eq!(err.to_string(), "Rate limit exceeded");
    }
    
    #[test]
    fn test_error_conversion() {
        let json_err = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
        let nostr_err: NostrError = json_err.into();
        assert!(matches!(nostr_err, NostrError::JsonError(_)));
        
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let nostr_err: NostrError = io_err.into();
        assert!(matches!(nostr_err, NostrError::IoError(_)));
    }
}