//! Error types for QuID exchange integration

use quid_core::QuIDError;
use quid_wallet::WalletError;

/// Result type for exchange operations
pub type ExchangeResult<T> = std::result::Result<T, ExchangeError>;

/// Exchange error types
#[derive(thiserror::Error, Debug)]
pub enum ExchangeError {
    #[error("Exchange not found: {0}")]
    ExchangeNotFound(String),
    
    #[error("Exchange connection failed: {0}")]
    ConnectionFailed(String),
    
    #[error("Exchange authentication failed: {0}")]
    AuthenticationFailed(String),
    
    #[error("Unsupported exchange: {0}")]
    UnsupportedExchange(String),
    
    #[error("API key derivation failed: {0}")]
    APIKeyDerivationFailed(String),
    
    #[error("Invalid API credentials: {0}")]
    InvalidCredentials(String),
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("Trading pair not found: {0}")]
    TradingPairNotFound(String),
    
    #[error("Order placement failed: {0}")]
    OrderPlacementFailed(String),
    
    #[error("Order cancellation failed: {0}")]
    OrderCancellationFailed(String),
    
    #[error("Order not found: {0}")]
    OrderNotFound(String),
    
    #[error("Insufficient balance: asset={asset}, required={required}, available={available}")]
    InsufficientBalance {
        asset: String,
        required: f64,
        available: f64,
    },
    
    #[error("Invalid order: {0}")]
    InvalidOrder(String),
    
    #[error("Trading not available: {0}")]
    TradingNotAvailable(String),
    
    #[error("Withdrawal failed: {0}")]
    WithdrawalFailed(String),
    
    #[error("Deposit failed: {0}")]
    DepositFailed(String),
    
    #[error("API request failed: {0}")]
    APIRequestFailed(String),
    
    #[error("Response parsing failed: {0}")]
    ResponseParsingFailed(String),
    
    #[error("Invalid response format: {0}")]
    InvalidResponseFormat(String),
    
    #[error("Exchange maintenance: {0}")]
    ExchangeMaintenance(String),
    
    #[error("Exchange service unavailable: {0}")]
    ServiceUnavailable(String),
    
    #[error("Portfolio synchronization failed: {0}")]
    PortfolioSyncFailed(String),
    
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("Security validation failed: {0}")]
    SecurityValidationFailed(String),
    
    #[error("API signature verification failed: {0}")]
    SignatureVerificationFailed(String),
    
    #[error("Timestamp validation failed: {0}")]
    TimestampValidationFailed(String),
    
    #[error("Network connectivity issue: {0}")]
    NetworkError(String),
    
    #[error("Timeout occurred: {0}")]
    Timeout(String),
    
    #[error("QuID error: {0}")]
    QuIDError(#[from] QuIDError),
    
    #[error("Wallet error: {0}")]
    WalletError(#[from] WalletError),
    
    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),
    
    #[error("JSON serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("URL parsing error: {0}")]
    UrlParsingError(#[from] url::ParseError),
    
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("UUID error: {0}")]
    UuidError(#[from] uuid::Error),
    
    #[error("Base64 decode error: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),
}

impl ExchangeError {
    /// Check if error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            ExchangeError::ExchangeNotFound(_) => false,
            ExchangeError::UnsupportedExchange(_) => false,
            ExchangeError::InvalidCredentials(_) => false,
            ExchangeError::ConfigurationError(_) => false,
            ExchangeError::SecurityValidationFailed(_) => false,
            ExchangeError::ConnectionFailed(_) => true,
            ExchangeError::RateLimitExceeded => true,
            ExchangeError::NetworkError(_) => true,
            ExchangeError::Timeout(_) => true,
            ExchangeError::ServiceUnavailable(_) => true,
            ExchangeError::ExchangeMaintenance(_) => true,
            ExchangeError::APIRequestFailed(_) => true,
            _ => false,
        }
    }
    
    /// Get error category
    pub fn category(&self) -> ExchangeErrorCategory {
        match self {
            ExchangeError::ExchangeNotFound(_) => ExchangeErrorCategory::NotFound,
            ExchangeError::ConnectionFailed(_) => ExchangeErrorCategory::Connection,
            ExchangeError::AuthenticationFailed(_) | ExchangeError::InvalidCredentials(_) => ExchangeErrorCategory::Authentication,
            ExchangeError::UnsupportedExchange(_) => ExchangeErrorCategory::Unsupported,
            ExchangeError::APIKeyDerivationFailed(_) => ExchangeErrorCategory::APIKey,
            ExchangeError::RateLimitExceeded => ExchangeErrorCategory::RateLimit,
            ExchangeError::TradingPairNotFound(_) => ExchangeErrorCategory::TradingPair,
            ExchangeError::OrderPlacementFailed(_) | ExchangeError::OrderCancellationFailed(_) | ExchangeError::OrderNotFound(_) => ExchangeErrorCategory::Order,
            ExchangeError::InsufficientBalance { .. } => ExchangeErrorCategory::Balance,
            ExchangeError::InvalidOrder(_) => ExchangeErrorCategory::Order,
            ExchangeError::TradingNotAvailable(_) => ExchangeErrorCategory::Trading,
            ExchangeError::WithdrawalFailed(_) => ExchangeErrorCategory::Withdrawal,
            ExchangeError::DepositFailed(_) => ExchangeErrorCategory::Deposit,
            ExchangeError::APIRequestFailed(_) | ExchangeError::ResponseParsingFailed(_) | ExchangeError::InvalidResponseFormat(_) => ExchangeErrorCategory::API,
            ExchangeError::ExchangeMaintenance(_) | ExchangeError::ServiceUnavailable(_) => ExchangeErrorCategory::Service,
            ExchangeError::PortfolioSyncFailed(_) => ExchangeErrorCategory::Portfolio,
            ExchangeError::ConfigurationError(_) => ExchangeErrorCategory::Configuration,
            ExchangeError::SecurityValidationFailed(_) | ExchangeError::SignatureVerificationFailed(_) => ExchangeErrorCategory::Security,
            ExchangeError::TimestampValidationFailed(_) => ExchangeErrorCategory::Timestamp,
            ExchangeError::NetworkError(_) => ExchangeErrorCategory::Network,
            ExchangeError::Timeout(_) => ExchangeErrorCategory::Timeout,
            ExchangeError::QuIDError(_) => ExchangeErrorCategory::QuID,
            ExchangeError::WalletError(_) => ExchangeErrorCategory::Wallet,
            ExchangeError::HttpError(_) => ExchangeErrorCategory::HTTP,
            ExchangeError::SerializationError(_) => ExchangeErrorCategory::Serialization,
            ExchangeError::UrlParsingError(_) => ExchangeErrorCategory::UrlParsing,
            ExchangeError::IoError(_) => ExchangeErrorCategory::IO,
            ExchangeError::UuidError(_) => ExchangeErrorCategory::UUID,
            ExchangeError::Base64DecodeError(_) => ExchangeErrorCategory::Base64,
        }
    }
    
    /// Get retry delay in milliseconds
    pub fn retry_delay_ms(&self) -> Option<u64> {
        if !self.is_recoverable() {
            return None;
        }
        
        match self {
            ExchangeError::RateLimitExceeded => Some(60_000), // 1 minute
            ExchangeError::NetworkError(_) => Some(5_000), // 5 seconds
            ExchangeError::Timeout(_) => Some(10_000), // 10 seconds
            ExchangeError::ServiceUnavailable(_) => Some(30_000), // 30 seconds
            ExchangeError::ExchangeMaintenance(_) => Some(300_000), // 5 minutes
            ExchangeError::ConnectionFailed(_) => Some(15_000), // 15 seconds
            ExchangeError::APIRequestFailed(_) => Some(5_000), // 5 seconds
            _ => Some(1_000), // 1 second default
        }
    }
}

/// Exchange error categories for handling
#[derive(Debug, Clone, PartialEq)]
pub enum ExchangeErrorCategory {
    NotFound,
    Connection,
    Authentication,
    Unsupported,
    APIKey,
    RateLimit,
    TradingPair,
    Order,
    Balance,
    Trading,
    Withdrawal,
    Deposit,
    API,
    Service,
    Portfolio,
    Configuration,
    Security,
    Timestamp,
    Network,
    Timeout,
    QuID,
    Wallet,
    HTTP,
    Serialization,
    UrlParsing,
    IO,
    UUID,
    Base64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_error_categories() {
        let error = ExchangeError::ExchangeNotFound("test".to_string());
        assert_eq!(error.category(), ExchangeErrorCategory::NotFound);
        assert!(!error.is_recoverable());
        
        let error = ExchangeError::ConnectionFailed("test".to_string());
        assert_eq!(error.category(), ExchangeErrorCategory::Connection);
        assert!(error.is_recoverable());
        
        let error = ExchangeError::RateLimitExceeded;
        assert_eq!(error.category(), ExchangeErrorCategory::RateLimit);
        assert!(error.is_recoverable());
        assert_eq!(error.retry_delay_ms(), Some(60_000));
    }
    
    #[test]
    fn test_insufficient_balance_error() {
        let error = ExchangeError::InsufficientBalance {
            asset: "BTC".to_string(),
            required: 1.0,
            available: 0.5,
        };
        assert_eq!(error.category(), ExchangeErrorCategory::Balance);
        assert!(!error.is_recoverable());
    }
    
    #[test]
    fn test_retry_delays() {
        let error = ExchangeError::RateLimitExceeded;
        assert_eq!(error.retry_delay_ms(), Some(60_000));
        
        let error = ExchangeError::NetworkError("connection failed".to_string());
        assert_eq!(error.retry_delay_ms(), Some(5_000));
        
        let error = ExchangeError::UnsupportedExchange("test".to_string());
        assert_eq!(error.retry_delay_ms(), None);
    }
}