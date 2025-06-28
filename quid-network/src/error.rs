//! Error types for the QuID network layer

use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("DHT operation failed: {0}")]
    DHTError(String),
    
    #[error("Content not found: {0}")]
    ContentNotFound(String),
    
    #[error("Invalid content: {0}")]
    InvalidContent(String),
    
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    
    #[error("Network connection failed: {0}")]
    ConnectionFailed(String),
    
    #[error("Peer not found: {0}")]
    PeerNotFound(String),
    
    #[error("Sync error: {0}")]
    SyncError(String),
    
    #[error("Storage error: {0}")]
    StorageError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Timeout: {0}")]
    Timeout(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
}
