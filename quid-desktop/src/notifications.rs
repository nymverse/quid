//! Cross-platform notification system for QuID desktop integration

use crate::{DesktopConfig, DesktopError, DesktopResult};
#[cfg(feature = "notifications")]
use notify_rust::{Notification, NotificationHandle, Timeout};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, Instant};

/// QuID notification types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationType {
    /// Authentication request received
    AuthRequest,
    /// Authentication completed successfully  
    AuthSuccess,
    /// Authentication failed
    AuthFailure,
    /// Security alert
    SecurityAlert,
    /// System status update
    SystemStatus,
    /// Identity management
    IdentityManagement,
    /// General information
    Info,
}

/// QuID notification priority
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum NotificationPriority {
    Low,
    Normal,
    High,
    Critical,
}

/// QuID notification structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuIDNotification {
    /// Unique notification ID
    pub id: String,
    /// Notification type
    pub notification_type: NotificationType,
    /// Priority level
    pub priority: NotificationPriority,
    /// Notification title
    pub title: String,
    /// Notification body text
    pub body: String,
    /// Optional icon path or name
    pub icon: Option<String>,
    /// Actions available to user
    pub actions: Vec<NotificationAction>,
    /// Auto-dismiss timeout in seconds
    pub timeout_seconds: Option<u64>,
    /// Associated data
    pub metadata: HashMap<String, String>,
    /// Timestamp when notification was created
    pub timestamp: u64,
}

/// User action for notifications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationAction {
    /// Action identifier
    pub id: String,
    /// Display label
    pub label: String,
    /// Whether this is the default action
    pub is_default: bool,
}

impl QuIDNotification {
    /// Create new notification
    pub fn new(
        notification_type: NotificationType,
        priority: NotificationPriority,
        title: String,
        body: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            notification_type,
            priority,
            title,
            body,
            icon: None,
            actions: Vec::new(),
            timeout_seconds: Some(10), // Default 10 seconds
            metadata: HashMap::new(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Add action to notification
    pub fn with_action(mut self, action: NotificationAction) -> Self {
        self.actions.push(action);
        self
    }

    /// Set notification icon
    pub fn with_icon(mut self, icon: String) -> Self {
        self.icon = Some(icon);
        self
    }

    /// Set timeout
    pub fn with_timeout(mut self, seconds: u64) -> Self {
        self.timeout_seconds = Some(seconds);
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Create authentication request notification
    pub fn auth_request(app_name: &str, service: &str) -> Self {
        Self::new(
            NotificationType::AuthRequest,
            NotificationPriority::High,
            "🔐 Authentication Request".to_string(),
            format!("{} wants to authenticate with {}", app_name, service),
        )
        .with_action(NotificationAction {
            id: "approve".to_string(),
            label: "Approve".to_string(),
            is_default: true,
        })
        .with_action(NotificationAction {
            id: "deny".to_string(),
            label: "Deny".to_string(),
            is_default: false,
        })
        .with_timeout(30) // Auth requests need longer timeout
    }

    /// Create authentication success notification
    pub fn auth_success(service: &str) -> Self {
        Self::new(
            NotificationType::AuthSuccess,
            NotificationPriority::Normal,
            "✅ Authentication Successful".to_string(),
            format!("Successfully authenticated with {}", service),
        )
        .with_timeout(5)
    }

    /// Create authentication failure notification
    pub fn auth_failure(service: &str, reason: &str) -> Self {
        Self::new(
            NotificationType::AuthFailure,
            NotificationPriority::High,
            "❌ Authentication Failed".to_string(),
            format!("Failed to authenticate with {}: {}", service, reason),
        )
        .with_timeout(10)
    }

    /// Create security alert notification
    pub fn security_alert(message: &str) -> Self {
        Self::new(
            NotificationType::SecurityAlert,
            NotificationPriority::Critical,
            "🛡️ Security Alert".to_string(),
            message.to_string(),
        )
        .with_timeout(0) // Critical alerts don't auto-dismiss
    }
}

/// Notification manager for cross-platform desktop notifications
#[derive(Debug)]
pub struct NotificationManager {
    config: DesktopConfig,
    sender: mpsc::UnboundedSender<NotificationCommand>,
    active_notifications: std::sync::Arc<RwLock<HashMap<String, ActiveNotification>>>,
}

#[derive(Debug)]
struct ActiveNotification {
    notification: QuIDNotification,
    #[cfg(feature = "notifications")]
    handle: Option<NotificationHandle>,
    #[cfg(not(feature = "notifications"))]
    handle: Option<()>,
    created_at: Instant,
}

#[derive(Debug)]
enum NotificationCommand {
    Send(QuIDNotification),
    Dismiss(String),
    Clear,
    Shutdown,
}

impl NotificationManager {
    /// Create new notification manager
    pub fn new(config: &DesktopConfig) -> DesktopResult<Self> {
        let (sender, receiver) = mpsc::unbounded_channel();
        
        let manager = Self {
            config: config.clone(),
            sender,
            active_notifications: Arc::new(RwLock::new(HashMap::new())),
        };

        // Start background notification handler
        let active_notifications = manager.active_notifications.clone();
        tokio::spawn(Self::notification_handler(receiver, active_notifications));

        Ok(manager)
    }

    /// Initialize notification system
    pub async fn initialize(&mut self) -> DesktopResult<()> {
        // Test system notification capability
        if self.config.enable_notifications {
            #[cfg(feature = "notifications")]
            {
                let test_result = Notification::new()
                    .summary("QuID Desktop")
                    .body("Notification system initialized")
                    .timeout(Timeout::Milliseconds(1000))
                    .show();

                if test_result.is_err() {
                    return Err(DesktopError::Notification(
                        "Failed to initialize notification system".to_string()
                    ));
                }
            }
            #[cfg(not(feature = "notifications"))]
            {
                println!("🔔 Notification system initialized (console fallback)");
            }
        }

        // Start cleanup timer
        let active_notifications = std::sync::Arc::clone(&self.active_notifications);
        tokio::spawn(Self::cleanup_expired_notifications(active_notifications));

        Ok(())
    }

    /// Send notification
    pub async fn send(&self, notification: QuIDNotification) -> DesktopResult<()> {
        self.sender
            .send(NotificationCommand::Send(notification))
            .map_err(|e| DesktopError::Notification(format!("Failed to send notification: {}", e)))?;
        
        Ok(())
    }

    /// Dismiss specific notification
    pub async fn dismiss(&self, notification_id: &str) -> DesktopResult<()> {
        self.sender
            .send(NotificationCommand::Dismiss(notification_id.to_string()))
            .map_err(|e| DesktopError::Notification(format!("Failed to dismiss notification: {}", e)))?;
        
        Ok(())
    }

    /// Clear all notifications
    pub async fn clear_all(&self) -> DesktopResult<()> {
        self.sender
            .send(NotificationCommand::Clear)
            .map_err(|e| DesktopError::Notification(format!("Failed to clear notifications: {}", e)))?;
        
        Ok(())
    }

    /// Shutdown notification manager
    pub async fn shutdown(&self) -> DesktopResult<()> {
        self.sender
            .send(NotificationCommand::Shutdown)
            .map_err(|e| DesktopError::Notification(format!("Failed to shutdown notification manager: {}", e)))?;
        
        Ok(())
    }

    /// Get active notifications
    pub async fn active_notifications(&self) -> Vec<QuIDNotification> {
        let active = self.active_notifications.read().await;
        active.values().map(|n| n.notification.clone()).collect()
    }

    /// Background notification handler
    async fn notification_handler(
        mut receiver: mpsc::UnboundedReceiver<NotificationCommand>,
        active_notifications: std::sync::Arc<RwLock<HashMap<String, ActiveNotification>>>,
    ) {
        while let Some(command) = receiver.recv().await {
            match command {
                NotificationCommand::Send(notification) => {
                    Self::handle_send_notification(notification, &active_notifications).await;
                }
                NotificationCommand::Dismiss(id) => {
                    Self::handle_dismiss_notification(&id, &active_notifications).await;
                }
                NotificationCommand::Clear => {
                    Self::handle_clear_notifications(&active_notifications).await;
                }
                NotificationCommand::Shutdown => {
                    Self::handle_clear_notifications(&active_notifications).await;
                    break;
                }
            }
        }
    }

    async fn handle_send_notification(
        notification: QuIDNotification,
        active_notifications: &std::sync::Arc<RwLock<HashMap<String, ActiveNotification>>>,
    ) {
        #[cfg(feature = "notifications")]
        {
            let mut builder = Notification::new();
            builder.summary(&notification.title);
            builder.body(&notification.body);

            // Set timeout
            match notification.timeout_seconds {
                Some(0) => builder.timeout(Timeout::Never),
                Some(seconds) => builder.timeout(Timeout::Milliseconds(seconds as u32 * 1000)),
                None => builder.timeout(Timeout::Default),
            };

            // Set icon if provided
            if let Some(ref icon) = notification.icon {
                builder.icon(icon);
            } else {
                // Set default icon based on notification type
                let default_icon = match notification.notification_type {
                    NotificationType::AuthRequest => "dialog-password",
                    NotificationType::AuthSuccess => "dialog-information",
                    NotificationType::AuthFailure => "dialog-error",
                    NotificationType::SecurityAlert => "dialog-warning",
                    NotificationType::SystemStatus => "system-run",
                    NotificationType::IdentityManagement => "system-users",
                    NotificationType::Info => "dialog-information",
                };
                builder.icon(default_icon);
            }

            // Set urgency based on priority
            let urgency = match notification.priority {
                NotificationPriority::Low => notify_rust::Urgency::Low,
                NotificationPriority::Normal => notify_rust::Urgency::Normal,
                NotificationPriority::High => notify_rust::Urgency::Critical,
                NotificationPriority::Critical => notify_rust::Urgency::Critical,
            };
            builder.urgency(urgency);

            // Add actions
            for action in &notification.actions {
                builder.action(&action.id, &action.label);
            }

            // Show notification
            match builder.show() {
                Ok(handle) => {
                    let mut active = active_notifications.write().await;
                    active.insert(
                        notification.id.clone(),
                        ActiveNotification {
                            notification,
                            handle: Some(handle),
                            created_at: Instant::now(),
                        },
                    );
                }
                Err(e) => {
                    eprintln!("Failed to show notification: {}", e);
                }
            }
        }
        
        #[cfg(not(feature = "notifications"))]
        {
            // Console fallback
            println!("🔔 Notification: {}", notification.title);
            println!("   {}", notification.body);
            if !notification.actions.is_empty() {
                println!("   Actions: {:?}", notification.actions.iter().map(|a| &a.label).collect::<Vec<_>>());
            }
            
            let mut active = active_notifications.write().await;
            active.insert(
                notification.id.clone(),
                ActiveNotification {
                    notification,
                    handle: Some(()),
                    created_at: Instant::now(),
                },
            );
        }
    }

    async fn handle_dismiss_notification(
        id: &str,
        active_notifications: &std::sync::Arc<RwLock<HashMap<String, ActiveNotification>>>,
    ) {
        let mut active = active_notifications.write().await;
        if let Some(active_notification) = active.remove(id) {
            #[cfg(feature = "notifications")]
            {
                if let Some(handle) = active_notification.handle {
                    let _ = handle.close();
                }
            }
            #[cfg(not(feature = "notifications"))]
            {
                println!("🔔 Dismissed notification: {}", active_notification.notification.title);
            }
        }
    }

    async fn handle_clear_notifications(
        active_notifications: &std::sync::Arc<RwLock<HashMap<String, ActiveNotification>>>,
    ) {
        let mut active = active_notifications.write().await;
        for (_, active_notification) in active.drain() {
            #[cfg(feature = "notifications")]
            {
                if let Some(handle) = active_notification.handle {
                    let _ = handle.close();
                }
            }
            #[cfg(not(feature = "notifications"))]
            {
                println!("🔔 Cleared notification: {}", active_notification.notification.title);
            }
        }
    }

    /// Background task to cleanup expired notifications
    async fn cleanup_expired_notifications(
        active_notifications: std::sync::Arc<RwLock<HashMap<String, ActiveNotification>>>,
    ) {
        let mut cleanup_interval = interval(Duration::from_secs(30));
        
        loop {
            cleanup_interval.tick().await;
            
            let mut to_remove = Vec::new();
            {
                let active = active_notifications.read().await;
                let now = Instant::now();
                
                for (id, notification) in active.iter() {
                    if let Some(timeout_secs) = notification.notification.timeout_seconds {
                        if timeout_secs > 0 {
                            let expires_at = notification.created_at + Duration::from_secs(timeout_secs);
                            if now >= expires_at {
                                to_remove.push(id.clone());
                            }
                        }
                    }
                }
            }
            
            if !to_remove.is_empty() {
                let mut active = active_notifications.write().await;
                for id in to_remove {
                    if let Some(active_notification) = active.remove(&id) {
                        #[cfg(feature = "notifications")]
                        {
                            if let Some(handle) = active_notification.handle {
                                let _ = handle.close();
                            }
                        }
                        #[cfg(not(feature = "notifications"))]
                        {
                            println!("🔔 Expired notification: {}", active_notification.notification.title);
                        }
                    }
                }
            }
        }
    }
}

// Add missing uuid dependency to support notification IDs
mod uuid_support {
    pub struct Uuid;
    
    impl Uuid {
        pub fn new_v4() -> UuidValue {
            // Simple UUID v4 implementation using random numbers
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let mut bytes = [0u8; 16];
            rng.fill(&mut bytes);
            
            // Set version (4) and variant bits
            bytes[6] = (bytes[6] & 0x0f) | 0x40;
            bytes[8] = (bytes[8] & 0x3f) | 0x80;
            
            UuidValue { bytes }
        }
    }
    
    pub struct UuidValue {
        bytes: [u8; 16],
    }
    
    impl UuidValue {
        pub fn to_string(&self) -> String {
            format!(
                "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3],
                self.bytes[4], self.bytes[5],
                self.bytes[6], self.bytes[7],
                self.bytes[8], self.bytes[9],
                self.bytes[10], self.bytes[11], self.bytes[12], self.bytes[13], self.bytes[14], self.bytes[15]
            )
        }
    }
}

// Use our simple UUID implementation
// Simple UUID fallback for notification IDs
mod uuid_fallback {
    pub struct Uuid;
    impl Uuid {
        pub fn new_v4() -> Self { Self }
        pub fn to_string(&self) -> String {
            format!("notification-{}", rand::random::<u64>())
        }
    }
}

use uuid_fallback::Uuid;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notification_creation() {
        let notification = QuIDNotification::new(
            NotificationType::AuthRequest,
            NotificationPriority::High,
            "Test".to_string(),
            "Test body".to_string(),
        );

        assert_eq!(notification.title, "Test");
        assert_eq!(notification.body, "Test body");
        assert!(matches!(notification.notification_type, NotificationType::AuthRequest));
        assert!(matches!(notification.priority, NotificationPriority::High));
        assert!(!notification.id.is_empty());
    }

    #[test]
    fn test_auth_request_notification() {
        let notification = QuIDNotification::auth_request("TestApp", "example.com");
        
        assert!(notification.title.contains("Authentication Request"));
        assert!(notification.body.contains("TestApp"));
        assert!(notification.body.contains("example.com"));
        assert_eq!(notification.actions.len(), 2);
        assert_eq!(notification.timeout_seconds, Some(30));
    }

    #[test]
    fn test_notification_builder() {
        let notification = QuIDNotification::new(
            NotificationType::Info,
            NotificationPriority::Normal,
            "Test".to_string(),
            "Body".to_string(),
        )
        .with_icon("test-icon".to_string())
        .with_timeout(60)
        .with_metadata("key".to_string(), "value".to_string())
        .with_action(NotificationAction {
            id: "test".to_string(),
            label: "Test Action".to_string(),
            is_default: true,
        });

        assert_eq!(notification.icon, Some("test-icon".to_string()));
        assert_eq!(notification.timeout_seconds, Some(60));
        assert_eq!(notification.metadata.get("key"), Some(&"value".to_string()));
        assert_eq!(notification.actions.len(), 1);
    }

    #[tokio::test]
    async fn test_notification_manager_creation() {
        let config = DesktopConfig::default();
        let manager = NotificationManager::new(&config);
        assert!(manager.is_ok());
    }

    #[test]
    fn test_notification_priorities() {
        let low = QuIDNotification::new(
            NotificationType::Info,
            NotificationPriority::Low,
            "Low".to_string(),
            "Body".to_string(),
        );

        let critical = QuIDNotification::new(
            NotificationType::SecurityAlert,
            NotificationPriority::Critical,
            "Critical".to_string(),
            "Body".to_string(),
        );

        assert!(matches!(low.priority, NotificationPriority::Low));
        assert!(matches!(critical.priority, NotificationPriority::Critical));
    }
}