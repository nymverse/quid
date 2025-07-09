//! Configuration for Nostr integration

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Main configuration for Nostr integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrConfig {
    /// Client configuration
    pub client_config: ClientConfig,
    /// Relay configuration
    pub relay_config: RelayConfig,
    /// Cryptography configuration
    pub crypto_config: CryptoConfig,
    /// Network configuration
    pub network_config: NetworkConfig,
    /// Storage configuration
    pub storage_config: StorageConfig,
}

/// Client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Default user agent
    pub user_agent: String,
    /// Auto-connect to relays
    pub auto_connect: bool,
    /// Default relays to connect to
    pub default_relays: Vec<String>,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Reconnection attempts
    pub reconnection_attempts: u32,
    /// Reconnection delay in seconds
    pub reconnection_delay: u64,
    /// Event cache size
    pub event_cache_size: usize,
    /// Enable event verification
    pub verify_events: bool,
    /// Enable metrics collection
    pub enable_metrics: bool,
}

/// Relay configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    /// Bind address for relay server
    pub bind_address: String,
    /// Port for relay server
    pub port: u16,
    /// Enable relay functionality
    pub enable_relay: bool,
    /// Maximum connections per relay
    pub max_connections: u32,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Maximum message size in bytes
    pub max_message_size: usize,
    /// Rate limiting configuration
    pub rate_limiting: RateLimitConfig,
    /// Storage backend
    pub storage_backend: StorageBackend,
    /// Event retention policy
    pub retention_policy: RetentionPolicy,
    /// Enable authentication
    pub enable_auth: bool,
    /// Supported NIPs
    pub supported_nips: Vec<u16>,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Enable rate limiting
    pub enabled: bool,
    /// Requests per minute
    pub requests_per_minute: u32,
    /// Burst size
    pub burst_size: u32,
    /// Cleanup interval in seconds
    pub cleanup_interval: u64,
}

/// Storage backend enumeration
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum StorageBackend {
    /// In-memory storage
    Memory,
    /// SQLite database
    SQLite,
    /// PostgreSQL database
    PostgreSQL,
    /// MongoDB
    MongoDB,
}

/// Event retention policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Maximum events to store
    pub max_events: Option<u64>,
    /// Maximum age of events in days
    pub max_age_days: Option<u32>,
    /// Cleanup interval in hours
    pub cleanup_interval_hours: u32,
    /// Event kinds to never delete
    pub permanent_kinds: Vec<u16>,
}

/// Cryptography configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    /// Enable quantum-resistant signatures
    pub quantum_resistant: bool,
    /// Signature algorithm
    pub signature_algorithm: SignatureAlgorithm,
    /// Encryption algorithm for DMs
    pub encryption_algorithm: EncryptionAlgorithm,
    /// Key derivation iterations
    pub key_derivation_iterations: u32,
    /// Enable signature verification
    pub verify_signatures: bool,
    /// Enable event ID verification
    pub verify_event_ids: bool,
}

/// Signature algorithm enumeration
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// Schnorr signatures (standard Nostr)
    Schnorr,
    /// ECDSA signatures
    ECDSA,
    /// QuID quantum-resistant signatures
    QuIDSignature,
}

/// Encryption algorithm enumeration
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    /// AES-256-GCM
    AES256GCM,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305,
    /// QuID quantum-resistant encryption
    QuIDEncryption,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// WebSocket configuration
    pub websocket_config: WebSocketConfig,
    /// HTTP configuration
    pub http_config: HttpConfig,
    /// Proxy configuration
    pub proxy_config: Option<ProxyConfig>,
    /// DNS configuration
    pub dns_config: DnsConfig,
    /// TLS configuration
    pub tls_config: TlsConfig,
}

/// WebSocket configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketConfig {
    /// Ping interval in seconds
    pub ping_interval: u64,
    /// Pong timeout in seconds
    pub pong_timeout: u64,
    /// Maximum frame size
    pub max_frame_size: usize,
    /// Enable compression
    pub enable_compression: bool,
    /// Close timeout in seconds
    pub close_timeout: u64,
}

/// HTTP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    /// Request timeout in seconds
    pub request_timeout: u64,
    /// Connect timeout in seconds
    pub connect_timeout: u64,
    /// Pool max idle per host
    pub pool_max_idle_per_host: usize,
    /// Pool idle timeout in seconds
    pub pool_idle_timeout: u64,
    /// Enable keep-alive
    pub enable_keep_alive: bool,
    /// User agent
    pub user_agent: String,
}

/// Proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Proxy type
    pub proxy_type: ProxyType,
    /// Proxy address
    pub address: String,
    /// Proxy port
    pub port: u16,
    /// Username (optional)
    pub username: Option<String>,
    /// Password (optional)
    pub password: Option<String>,
}

/// Proxy type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ProxyType {
    /// HTTP proxy
    HTTP,
    /// HTTPS proxy
    HTTPS,
    /// SOCKS4 proxy
    SOCKS4,
    /// SOCKS5 proxy
    SOCKS5,
}

/// DNS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// DNS servers
    pub servers: Vec<String>,
    /// DNS timeout in seconds
    pub timeout: u64,
    /// Enable DNS over HTTPS
    pub enable_doh: bool,
    /// Enable DNS over TLS
    pub enable_dot: bool,
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Enable TLS verification
    pub verify_certificates: bool,
    /// Accepted TLS versions
    pub accepted_versions: Vec<TlsVersion>,
    /// Certificate authorities file
    pub ca_file: Option<PathBuf>,
    /// Client certificate file
    pub cert_file: Option<PathBuf>,
    /// Client private key file
    pub key_file: Option<PathBuf>,
}

/// TLS version enumeration
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum TlsVersion {
    /// TLS 1.2
    TLS12,
    /// TLS 1.3
    TLS13,
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Storage directory
    pub storage_dir: PathBuf,
    /// Database URL (for SQL backends)
    pub database_url: Option<String>,
    /// Maximum database size in MB
    pub max_db_size_mb: Option<u64>,
    /// Enable WAL mode for SQLite
    pub enable_wal: bool,
    /// Cache size in MB
    pub cache_size_mb: u64,
    /// Enable compression
    pub enable_compression: bool,
    /// Backup configuration
    pub backup_config: BackupConfig,
}

/// Backup configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    /// Enable automatic backups
    pub enabled: bool,
    /// Backup interval in hours
    pub interval_hours: u32,
    /// Maximum backup files to keep
    pub max_backups: u32,
    /// Backup directory
    pub backup_dir: PathBuf,
    /// Enable compression
    pub compress_backups: bool,
}

impl Default for NostrConfig {
    fn default() -> Self {
        Self {
            client_config: ClientConfig::default(),
            relay_config: RelayConfig::default(),
            crypto_config: CryptoConfig::default(),
            network_config: NetworkConfig::default(),
            storage_config: StorageConfig::default(),
        }
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            user_agent: "QuID-Nostr/1.0".to_string(),
            auto_connect: true,
            default_relays: vec![
                "wss://relay.damus.io".to_string(),
                "wss://nostr-pub.wellorder.net".to_string(),
                "wss://relay.nostr.info".to_string(),
            ],
            connection_timeout: 30,
            reconnection_attempts: 5,
            reconnection_delay: 5,
            event_cache_size: 10000,
            verify_events: true,
            enable_metrics: false,
        }
    }
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0".to_string(),
            port: 8080,
            enable_relay: false,
            max_connections: 1000,
            connection_timeout: 60,
            max_message_size: 1024 * 1024, // 1MB
            rate_limiting: RateLimitConfig::default(),
            storage_backend: StorageBackend::SQLite,
            retention_policy: RetentionPolicy::default(),
            enable_auth: false,
            supported_nips: vec![1, 2, 4, 9, 11, 12, 15, 16, 20, 28, 33, 40, 42, 50, 51, 57],
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_minute: 100,
            burst_size: 20,
            cleanup_interval: 300, // 5 minutes
        }
    }
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            max_events: Some(1_000_000),
            max_age_days: Some(365),
            cleanup_interval_hours: 24,
            permanent_kinds: vec![0, 3], // Metadata and contacts
        }
    }
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            quantum_resistant: true,
            signature_algorithm: SignatureAlgorithm::QuIDSignature,
            encryption_algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
            key_derivation_iterations: 100_000,
            verify_signatures: true,
            verify_event_ids: true,
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            websocket_config: WebSocketConfig::default(),
            http_config: HttpConfig::default(),
            proxy_config: None,
            dns_config: DnsConfig::default(),
            tls_config: TlsConfig::default(),
        }
    }
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            ping_interval: 30,
            pong_timeout: 10,
            max_frame_size: 16 * 1024 * 1024, // 16MB
            enable_compression: true,
            close_timeout: 10,
        }
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            request_timeout: 30,
            connect_timeout: 10,
            pool_max_idle_per_host: 10,
            pool_idle_timeout: 90,
            enable_keep_alive: true,
            user_agent: "QuID-Nostr/1.0".to_string(),
        }
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            servers: vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()],
            timeout: 5,
            enable_doh: false,
            enable_dot: false,
        }
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            verify_certificates: true,
            accepted_versions: vec![TlsVersion::TLS12, TlsVersion::TLS13],
            ca_file: None,
            cert_file: None,
            key_file: None,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            storage_dir: PathBuf::from("./quid-nostr-data"),
            database_url: None,
            max_db_size_mb: Some(1024), // 1GB
            enable_wal: true,
            cache_size_mb: 256,
            enable_compression: true,
            backup_config: BackupConfig::default(),
        }
    }
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_hours: 24,
            max_backups: 7,
            backup_dir: PathBuf::from("./quid-nostr-backups"),
            compress_backups: true,
        }
    }
}

impl NostrConfig {
    /// Load configuration from file
    pub fn load_from_file(path: &PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }
    
    /// Save configuration to file
    pub fn save_to_file(&self, path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
    
    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        // Validate network configuration
        if self.network_config.websocket_config.ping_interval == 0 {
            return Err("WebSocket ping interval cannot be zero".to_string());
        }
        
        if self.network_config.http_config.request_timeout == 0 {
            return Err("HTTP request timeout cannot be zero".to_string());
        }
        
        // Validate relay configuration
        if self.relay_config.port == 0 {
            return Err("Relay port cannot be zero".to_string());
        }
        
        if self.relay_config.max_connections == 0 {
            return Err("Max connections cannot be zero".to_string());
        }
        
        // Validate client configuration
        if self.client_config.event_cache_size == 0 {
            return Err("Event cache size cannot be zero".to_string());
        }
        
        // Validate storage configuration
        if self.storage_config.cache_size_mb == 0 {
            return Err("Cache size cannot be zero".to_string());
        }
        
        Ok(())
    }
    
    /// Get timeout duration for connections
    pub fn connection_timeout(&self) -> Duration {
        Duration::from_secs(self.client_config.connection_timeout)
    }
    
    /// Get reconnection delay duration
    pub fn reconnection_delay(&self) -> Duration {
        Duration::from_secs(self.client_config.reconnection_delay)
    }
    
    /// Check if quantum-resistant features are enabled
    pub fn is_quantum_resistant(&self) -> bool {
        self.crypto_config.quantum_resistant
    }
    
    /// Check if relay functionality is enabled
    pub fn is_relay_enabled(&self) -> bool {
        self.relay_config.enable_relay
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[test]
    fn test_default_config() {
        let config = NostrConfig::default();
        assert!(config.validate().is_ok());
        assert!(config.is_quantum_resistant());
        assert!(!config.is_relay_enabled());
    }
    
    #[test]
    fn test_config_serialization() {
        let config = NostrConfig::default();
        let serialized = toml::to_string(&config).unwrap();
        let deserialized: NostrConfig = toml::from_str(&serialized).unwrap();
        
        assert_eq!(config.client_config.user_agent, deserialized.client_config.user_agent);
        assert_eq!(config.relay_config.port, deserialized.relay_config.port);
    }
    
    #[test]
    fn test_config_file_operations() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("config.toml");
        
        let config = NostrConfig::default();
        config.save_to_file(&config_path).unwrap();
        
        let loaded_config = NostrConfig::load_from_file(&config_path).unwrap();
        assert_eq!(config.client_config.user_agent, loaded_config.client_config.user_agent);
    }
    
    #[test]
    fn test_config_validation() {
        let mut config = NostrConfig::default();
        
        // Valid configuration
        assert!(config.validate().is_ok());
        
        // Invalid configuration - zero ping interval
        config.network_config.websocket_config.ping_interval = 0;
        assert!(config.validate().is_err());
        
        // Fix and test another invalid case
        config.network_config.websocket_config.ping_interval = 30;
        config.relay_config.port = 0;
        assert!(config.validate().is_err());
    }
    
    #[test]
    fn test_duration_helpers() {
        let config = NostrConfig::default();
        
        assert_eq!(config.connection_timeout(), Duration::from_secs(30));
        assert_eq!(config.reconnection_delay(), Duration::from_secs(5));
    }
    
    #[test]
    fn test_feature_flags() {
        let config = NostrConfig::default();
        
        assert!(config.is_quantum_resistant());
        assert!(!config.is_relay_enabled());
        
        assert_eq!(config.crypto_config.signature_algorithm, SignatureAlgorithm::QuIDSignature);
        assert_eq!(config.relay_config.storage_backend, StorageBackend::SQLite);
    }
}