//! Configuration for QuID exchange integration

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use crate::types::{ExchangeType, ExchangeSettings, RateLimitConfig, PortfolioSyncSettings};

/// Exchange configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeConfig {
    /// Exchange-specific settings
    pub exchanges: HashMap<ExchangeType, ExchangeSettings>,
    /// Security configuration
    pub security: SecurityConfig,
    /// API configuration
    pub api: APIConfig,
    /// Portfolio synchronization settings
    pub portfolio: PortfolioSyncSettings,
    /// Storage configuration
    pub storage: StorageConfig,
    /// Rate limiting configuration
    pub rate_limiting: GlobalRateLimitConfig,
    /// Trading configuration
    pub trading: TradingConfig,
    /// Notification configuration
    pub notifications: NotificationConfig,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// API key encryption enabled
    pub encrypt_api_keys: bool,
    /// Require signature verification for all requests
    pub require_signature_verification: bool,
    /// Maximum API key age in days
    pub max_api_key_age_days: u32,
    /// Enable IP whitelisting
    pub ip_whitelist_enabled: bool,
    /// Allowed IP addresses
    pub allowed_ips: Vec<String>,
    /// Session timeout in seconds
    pub session_timeout: u64,
    /// Enable audit logging
    pub audit_logging: bool,
    /// Secure storage path
    pub secure_storage_path: PathBuf,
}

/// API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct APIConfig {
    /// Default timeout for API requests
    pub default_timeout_ms: u64,
    /// Maximum retry attempts
    pub max_retries: u32,
    /// Retry delay multiplier
    pub retry_delay_multiplier: f64,
    /// Enable request/response logging
    pub enable_logging: bool,
    /// Log level for API requests
    pub log_level: String,
    /// User agent for requests
    pub user_agent: String,
    /// Connection pool settings
    pub connection_pool: ConnectionPoolConfig,
}

/// Connection pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionPoolConfig {
    /// Maximum connections per host
    pub max_connections_per_host: u32,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Idle connection timeout in seconds
    pub idle_timeout: u64,
    /// Keep-alive timeout in seconds
    pub keep_alive_timeout: u64,
}

/// Global rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalRateLimitConfig {
    /// Enable global rate limiting
    pub enabled: bool,
    /// Global requests per second
    pub global_requests_per_second: u32,
    /// Global requests per minute
    pub global_requests_per_minute: u32,
    /// Per-exchange rate limits
    pub per_exchange_limits: HashMap<ExchangeType, RateLimitConfig>,
    /// Rate limit enforcement strategy
    pub enforcement_strategy: RateLimitStrategy,
}

/// Rate limit enforcement strategy
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RateLimitStrategy {
    Block,
    Queue,
    Drop,
}

/// Trading configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TradingConfig {
    /// Default order type
    pub default_order_type: String,
    /// Default time in force
    pub default_time_in_force: String,
    /// Enable order validation
    pub enable_order_validation: bool,
    /// Maximum order size as percentage of portfolio
    pub max_order_size_percentage: f64,
    /// Minimum order value in USD
    pub min_order_value_usd: f64,
    /// Enable stop-loss orders
    pub enable_stop_loss: bool,
    /// Enable take-profit orders
    pub enable_take_profit: bool,
    /// Default slippage tolerance
    pub default_slippage_tolerance: f64,
    /// Risk management settings
    pub risk_management: RiskManagementConfig,
}

/// Risk management configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskManagementConfig {
    /// Enable risk management
    pub enabled: bool,
    /// Maximum daily loss percentage
    pub max_daily_loss_percentage: f64,
    /// Maximum position size percentage
    pub max_position_size_percentage: f64,
    /// Enable portfolio diversification checks
    pub enable_diversification_checks: bool,
    /// Maximum concentration per asset
    pub max_concentration_percentage: f64,
    /// Cool-down period after loss in seconds
    pub loss_cooldown_seconds: u64,
}

/// Notification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    /// Enable notifications
    pub enabled: bool,
    /// Notification types
    pub types: Vec<NotificationType>,
    /// Webhook configuration
    pub webhook: Option<WebhookConfig>,
    /// Email configuration
    pub email: Option<EmailConfig>,
}

/// Notification types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NotificationType {
    OrderFilled,
    OrderCancelled,
    OrderRejected,
    BalanceChange,
    PriceAlert,
    SystemAlert,
    SecurityAlert,
}

/// Webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Webhook URL
    pub url: String,
    /// Secret for webhook verification
    pub secret: String,
    /// Timeout for webhook requests
    pub timeout_ms: u64,
    /// Maximum retry attempts
    pub max_retries: u32,
}

/// Email configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    /// SMTP server
    pub smtp_server: String,
    /// SMTP port
    pub smtp_port: u16,
    /// Username
    pub username: String,
    /// Password
    pub password: String,
    /// From address
    pub from_address: String,
    /// To addresses
    pub to_addresses: Vec<String>,
    /// Enable TLS
    pub enable_tls: bool,
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Base directory for storage
    pub base_directory: PathBuf,
    /// Enable encryption
    pub enable_encryption: bool,
    /// Encryption key derivation
    pub key_derivation: KeyDerivationConfig,
    /// Backup configuration
    pub backup: BackupConfig,
    /// Data retention policy
    pub retention: RetentionConfig,
}

/// Key derivation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDerivationConfig {
    /// Algorithm for key derivation
    pub algorithm: String,
    /// Salt for key derivation
    pub salt: String,
    /// Number of iterations
    pub iterations: u32,
    /// Key length
    pub key_length: u32,
}

/// Backup configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    /// Enable automatic backups
    pub enabled: bool,
    /// Backup interval in seconds
    pub interval_seconds: u64,
    /// Backup directory
    pub backup_directory: PathBuf,
    /// Maximum number of backups to keep
    pub max_backups: u32,
    /// Compression enabled
    pub compression_enabled: bool,
    /// Encryption enabled for backups
    pub encryption_enabled: bool,
}

/// Data retention configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionConfig {
    /// Trade history retention in days
    pub trade_history_days: u32,
    /// Order history retention in days
    pub order_history_days: u32,
    /// Balance history retention in days
    pub balance_history_days: u32,
    /// API log retention in days
    pub api_log_days: u32,
    /// Audit log retention in days
    pub audit_log_days: u32,
}

impl Default for ExchangeConfig {
    fn default() -> Self {
        Self {
            exchanges: HashMap::new(),
            security: SecurityConfig::default(),
            api: APIConfig::default(),
            portfolio: PortfolioSyncSettings::default(),
            storage: StorageConfig::default(),
            rate_limiting: GlobalRateLimitConfig::default(),
            trading: TradingConfig::default(),
            notifications: NotificationConfig::default(),
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            encrypt_api_keys: true,
            require_signature_verification: true,
            max_api_key_age_days: 90,
            ip_whitelist_enabled: false,
            allowed_ips: Vec::new(),
            session_timeout: 3600, // 1 hour
            audit_logging: true,
            secure_storage_path: dirs::home_dir()
                .unwrap_or_default()
                .join(".quid")
                .join("exchange")
                .join("secure"),
        }
    }
}

impl Default for APIConfig {
    fn default() -> Self {
        Self {
            default_timeout_ms: 30000, // 30 seconds
            max_retries: 3,
            retry_delay_multiplier: 2.0,
            enable_logging: true,
            log_level: "info".to_string(),
            user_agent: "QuID-Exchange/1.0".to_string(),
            connection_pool: ConnectionPoolConfig::default(),
        }
    }
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_connections_per_host: 10,
            connection_timeout: 30,
            idle_timeout: 90,
            keep_alive_timeout: 30,
        }
    }
}

impl Default for PortfolioSyncSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            sync_interval_seconds: 300, // 5 minutes
            auto_sync_on_trade: true,
            include_history: true,
            history_days: 30,
        }
    }
}

impl Default for GlobalRateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            global_requests_per_second: 10,
            global_requests_per_minute: 600,
            per_exchange_limits: HashMap::new(),
            enforcement_strategy: RateLimitStrategy::Queue,
        }
    }
}

impl Default for TradingConfig {
    fn default() -> Self {
        Self {
            default_order_type: "LIMIT".to_string(),
            default_time_in_force: "GTC".to_string(),
            enable_order_validation: true,
            max_order_size_percentage: 10.0,
            min_order_value_usd: 10.0,
            enable_stop_loss: true,
            enable_take_profit: true,
            default_slippage_tolerance: 0.1,
            risk_management: RiskManagementConfig::default(),
        }
    }
}

impl Default for RiskManagementConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_daily_loss_percentage: 5.0,
            max_position_size_percentage: 20.0,
            enable_diversification_checks: true,
            max_concentration_percentage: 50.0,
            loss_cooldown_seconds: 3600, // 1 hour
        }
    }
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            types: vec![
                NotificationType::OrderFilled,
                NotificationType::OrderCancelled,
                NotificationType::SecurityAlert,
            ],
            webhook: None,
            email: None,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            base_directory: dirs::home_dir()
                .unwrap_or_default()
                .join(".quid")
                .join("exchange"),
            enable_encryption: true,
            key_derivation: KeyDerivationConfig::default(),
            backup: BackupConfig::default(),
            retention: RetentionConfig::default(),
        }
    }
}

impl Default for KeyDerivationConfig {
    fn default() -> Self {
        Self {
            algorithm: "pbkdf2".to_string(),
            salt: "quid-exchange-salt".to_string(),
            iterations: 100_000,
            key_length: 32,
        }
    }
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_seconds: 86400, // 24 hours
            backup_directory: dirs::home_dir()
                .unwrap_or_default()
                .join(".quid")
                .join("exchange")
                .join("backups"),
            max_backups: 7,
            compression_enabled: true,
            encryption_enabled: true,
        }
    }
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            trade_history_days: 365,
            order_history_days: 365,
            balance_history_days: 90,
            api_log_days: 30,
            audit_log_days: 730, // 2 years
        }
    }
}

impl ExchangeConfig {
    /// Load configuration from file
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, std::io::Error> {
        let content = std::fs::read_to_string(path)?;
        let config: ExchangeConfig = toml::from_str(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(config)
    }
    
    /// Save configuration to file
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), std::io::Error> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        
        // Create parent directory if it doesn't exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        std::fs::write(path, content)
    }
    
    /// Get default configuration directory
    pub fn default_config_dir() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_default()
            .join("quid")
            .join("exchange")
    }
    
    /// Get default configuration file path
    pub fn default_config_path() -> PathBuf {
        Self::default_config_dir().join("config.toml")
    }
    
    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        // Validate security settings
        if self.security.max_api_key_age_days == 0 {
            return Err("API key age cannot be zero".to_string());
        }
        
        if self.security.session_timeout == 0 {
            return Err("Session timeout cannot be zero".to_string());
        }
        
        // Validate API settings
        if self.api.default_timeout_ms == 0 {
            return Err("API timeout cannot be zero".to_string());
        }
        
        if self.api.max_retries == 0 {
            return Err("Max retries cannot be zero".to_string());
        }
        
        // Validate trading settings
        if self.trading.max_order_size_percentage <= 0.0 || self.trading.max_order_size_percentage > 100.0 {
            return Err("Max order size percentage must be between 0 and 100".to_string());
        }
        
        if self.trading.min_order_value_usd <= 0.0 {
            return Err("Min order value must be positive".to_string());
        }
        
        // Validate risk management settings
        if self.trading.risk_management.enabled {
            if self.trading.risk_management.max_daily_loss_percentage <= 0.0 {
                return Err("Max daily loss percentage must be positive".to_string());
            }
            
            if self.trading.risk_management.max_position_size_percentage <= 0.0 || 
               self.trading.risk_management.max_position_size_percentage > 100.0 {
                return Err("Max position size percentage must be between 0 and 100".to_string());
            }
        }
        
        // Validate storage settings
        if self.storage.base_directory.to_str().map_or(true, |s| s.is_empty()) {
            return Err("Storage base directory cannot be empty".to_string());
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[test]
    fn test_default_config() {
        let config = ExchangeConfig::default();
        assert!(config.security.encrypt_api_keys);
        assert!(config.security.require_signature_verification);
        assert!(config.api.enable_logging);
        assert!(config.trading.enable_order_validation);
        assert!(config.storage.enable_encryption);
    }
    
    #[test]
    fn test_config_validation() {
        let config = ExchangeConfig::default();
        assert!(config.validate().is_ok());
        
        let mut invalid_config = ExchangeConfig::default();
        invalid_config.security.max_api_key_age_days = 0;
        assert!(invalid_config.validate().is_err());
        
        invalid_config = ExchangeConfig::default();
        invalid_config.trading.max_order_size_percentage = 150.0;
        assert!(invalid_config.validate().is_err());
    }
    
    #[test]
    fn test_config_file_operations() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("test_config.toml");
        
        let original_config = ExchangeConfig::default();
        original_config.save_to_file(&config_path).unwrap();
        
        let loaded_config = ExchangeConfig::load_from_file(&config_path).unwrap();
        
        assert_eq!(original_config.security.encrypt_api_keys, loaded_config.security.encrypt_api_keys);
        assert_eq!(original_config.api.default_timeout_ms, loaded_config.api.default_timeout_ms);
        assert_eq!(original_config.trading.default_order_type, loaded_config.trading.default_order_type);
    }
    
    #[test]
    fn test_notification_types() {
        let config = NotificationConfig::default();
        assert!(config.types.contains(&NotificationType::OrderFilled));
        assert!(config.types.contains(&NotificationType::SecurityAlert));
        assert!(!config.enabled);
    }
    
    #[test]
    fn test_rate_limit_strategy() {
        let config = GlobalRateLimitConfig::default();
        assert_eq!(config.enforcement_strategy, RateLimitStrategy::Queue);
        assert!(config.enabled);
        assert_eq!(config.global_requests_per_second, 10);
    }
}