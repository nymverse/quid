//! QuID Desktop Integration Library
//!
//! This crate provides cross-platform desktop integration for QuID, including:
//! - System authentication flows
//! - Native UI components
//! - Secure storage integration
//! - Desktop notifications
//! - System tray integration
//! - Protocol handlers

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod auth;
pub mod integration;
pub mod notifications;
pub mod platform;
pub mod storage;
pub mod ui;

pub use auth::{AuthenticationFlow, AuthenticationRequest, AuthenticationResult};
pub use integration::{DesktopIntegration, SystemIntegration};
pub use notifications::{NotificationManager, QuIDNotification};
pub use platform::{Platform, PlatformCapabilities};
pub use storage::{DesktopStorage, StorageBackend};
pub use ui::{IdentityManager, UIComponent};

/// Desktop integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesktopConfig {
    /// Application name for system integration
    pub app_name: String,
    /// Enable system notifications
    pub enable_notifications: bool,
    /// Enable system tray integration
    pub enable_system_tray: bool,
    /// Enable protocol handlers (quid://)
    pub enable_protocol_handlers: bool,
    /// Storage backend preference
    pub storage_backend: StorageBackend,
    /// Platform-specific settings
    pub platform_settings: HashMap<String, String>,
}

impl Default for DesktopConfig {
    fn default() -> Self {
        Self {
            app_name: "QuID Universal Authentication".to_string(),
            enable_notifications: true,
            enable_system_tray: true,
            enable_protocol_handlers: true,
            storage_backend: StorageBackend::default(),
            platform_settings: HashMap::new(),
        }
    }
}

/// Main desktop integration manager
pub struct QuIDDesktop {
    config: DesktopConfig,
    integration: Box<dyn SystemIntegration>,
    auth_flow: AuthenticationFlow,
    notification_manager: NotificationManager,
    storage: DesktopStorage,
}

impl QuIDDesktop {
    /// Initialize QuID desktop integration
    pub async fn initialize(config: DesktopConfig) -> Result<Self> {
        let platform = Platform::detect();
        let integration = integration::create_integration(platform, &config).await?;
        let auth_flow = AuthenticationFlow::new(config.clone());
        let notification_manager = NotificationManager::new(&config)?;
        let storage = DesktopStorage::new(config.storage_backend.clone()).await?;

        Ok(Self {
            config,
            integration,
            auth_flow,
            notification_manager,
            storage,
        })
    }

    /// Get platform capabilities
    pub fn capabilities(&self) -> &PlatformCapabilities {
        self.integration.capabilities()
    }

    /// Start desktop integration services
    pub async fn start(&mut self) -> Result<()> {
        // Initialize system integration
        self.integration.initialize().await?;

        // Register protocol handlers
        if self.config.enable_protocol_handlers {
            self.integration.register_protocol_handler("quid").await?;
        }

        // Start system tray if enabled
        if self.config.enable_system_tray {
            self.integration.start_system_tray().await?;
        }

        // Initialize notifications
        if self.config.enable_notifications {
            self.notification_manager.initialize().await?;
        }

        Ok(())
    }

    /// Stop desktop integration services
    pub async fn stop(&mut self) -> Result<()> {
        self.integration.shutdown().await?;
        self.notification_manager.shutdown().await?;
        Ok(())
    }

    /// Handle authentication request
    pub async fn handle_auth_request(&mut self, request: AuthenticationRequest) -> Result<AuthenticationResult> {
        self.auth_flow.process_request(request).await
            .map_err(anyhow::Error::from)
    }

    /// Show identity management UI
    pub async fn show_identity_manager(&self) -> Result<()> {
        self.integration.show_identity_manager().await
            .map_err(anyhow::Error::from)
    }

    /// Send notification
    pub async fn notify(&self, notification: QuIDNotification) -> Result<()> {
        self.notification_manager.send(notification).await
            .map_err(anyhow::Error::from)
    }

    /// Get storage manager
    pub fn storage(&self) -> &DesktopStorage {
        &self.storage
    }

    /// Get mutable storage manager
    pub fn storage_mut(&mut self) -> &mut DesktopStorage {
        &mut self.storage
    }
}

/// Result type for desktop operations
pub type DesktopResult<T> = Result<T, DesktopError>;

/// Desktop integration errors
#[derive(Debug, thiserror::Error)]
pub enum DesktopError {
    #[error("Platform not supported: {0}")]
    UnsupportedPlatform(String),
    
    #[error("System integration error: {0}")]
    SystemIntegration(String),
    
    #[error("Authentication error: {0}")]
    Authentication(String),
    
    #[error("Storage error: {0}")]
    Storage(String),
    
    #[error("UI error: {0}")]
    UI(String),
    
    #[error("Notification error: {0}")]
    Notification(String),
    
    #[error("Configuration error: {0}")]
    Configuration(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DesktopConfig::default();
        assert_eq!(config.app_name, "QuID Universal Authentication");
        assert!(config.enable_notifications);
        assert!(config.enable_system_tray);
        assert!(config.enable_protocol_handlers);
    }

    #[test]
    fn test_config_serialization() {
        let config = DesktopConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: DesktopConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.app_name, deserialized.app_name);
    }
}