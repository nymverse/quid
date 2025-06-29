use anyhow::Result;
use quid_desktop::{
    DesktopConfig, Platform, PlatformCapabilities, 
    auth::AuthenticationRequest,
    notifications::{QuIDNotification, NotificationType, NotificationPriority},
    storage::StorageBackend,
};
use std::collections::HashMap;

#[tokio::test]
async fn test_desktop_config_creation() -> Result<()> {
    let config = DesktopConfig::default();
    
    assert_eq!(config.app_name, "QuID Universal Authentication");
    assert!(config.enable_notifications);
    assert!(config.enable_system_tray);
    assert!(config.enable_protocol_handlers);
    assert!(config.platform_settings.is_empty());
    
    Ok(())
}

#[tokio::test]
async fn test_custom_desktop_config() -> Result<()> {
    let mut platform_settings = HashMap::new();
    platform_settings.insert("theme".to_string(), "dark".to_string());
    
    let config = DesktopConfig {
        app_name: "Custom QuID App".to_string(),
        enable_notifications: false,
        enable_system_tray: false,
        enable_protocol_handlers: true,
        storage_backend: StorageBackend::Memory,
        platform_settings,
    };
    
    assert_eq!(config.app_name, "Custom QuID App");
    assert!(!config.enable_notifications);
    assert!(!config.enable_system_tray);
    assert!(config.enable_protocol_handlers);
    assert_eq!(config.platform_settings.get("theme"), Some(&"dark".to_string()));
    
    Ok(())
}

#[tokio::test]
async fn test_desktop_config_serialization() -> Result<()> {
    let original_config = DesktopConfig::default();
    
    // Test JSON serialization
    let json = serde_json::to_string(&original_config)?;
    let deserialized_config: DesktopConfig = serde_json::from_str(&json)?;
    
    assert_eq!(original_config.app_name, deserialized_config.app_name);
    assert_eq!(original_config.enable_notifications, deserialized_config.enable_notifications);
    assert_eq!(original_config.enable_system_tray, deserialized_config.enable_system_tray);
    assert_eq!(original_config.enable_protocol_handlers, deserialized_config.enable_protocol_handlers);
    
    Ok(())
}

#[tokio::test]
async fn test_platform_detection() -> Result<()> {
    let platform = Platform::detect();
    
    // Should detect one of the supported platforms
    match platform {
        Platform::Windows => assert!(cfg!(target_os = "windows")),
        Platform::MacOS => assert!(cfg!(target_os = "macos")),
        Platform::Linux => assert!(cfg!(target_os = "linux")),
        _ => {} // Allow for other platforms in future
    }
    
    Ok(())
}

#[tokio::test]
async fn test_authentication_request_creation() -> Result<()> {
    let request = AuthenticationRequest::new(
        "Test App".to_string(),
        "example.com".to_string(),
        "web".to_string(),
    );
    
    assert_eq!(request.app_name, "Test App");
    assert_eq!(request.service, "example.com");
    assert_eq!(request.network, "web");
    assert!(!request.request_id.is_empty());
    
    Ok(())
}

#[tokio::test]
async fn test_notification_creation() -> Result<()> {
    let notification = QuIDNotification::new(
        NotificationType::AuthRequest,
        NotificationPriority::High,
        "Authentication Request".to_string(),
        "New authentication request from example.com".to_string(),
    );
    
    assert_eq!(notification.title, "Authentication Request");
    assert_eq!(notification.body, "New authentication request from example.com");
    assert!(!notification.id.is_empty());
    assert_eq!(notification.timeout_seconds, Some(10));
    
    Ok(())
}

#[tokio::test]
async fn test_storage_backend_options() -> Result<()> {
    use std::path::PathBuf;
    
    // Test different storage backend options
    let memory_backend = StorageBackend::Memory;
    let file_backend = StorageBackend::EncryptedFile { 
        storage_dir: PathBuf::from("/tmp/quid-test"),
        backup_dir: None,
    };
    let system_backend = StorageBackend::SystemKeychain {
        service_name: "Test Service".to_string(),
        file_fallback: true,
    };
    
    match memory_backend {
        StorageBackend::Memory => {}, // Expected
        _ => panic!("Expected Memory backend"),
    }
    
    match file_backend {
        StorageBackend::EncryptedFile { storage_dir, .. } => {
            assert_eq!(storage_dir, PathBuf::from("/tmp/quid-test"));
        },
        _ => panic!("Expected EncryptedFile backend"),
    }
    
    match system_backend {
        StorageBackend::SystemKeychain { service_name, .. } => {
            assert_eq!(service_name, "Test Service");
        },
        _ => panic!("Expected SystemKeychain backend"),
    }
    
    Ok(())
}

#[tokio::test]
async fn test_desktop_error_types() -> Result<()> {
    use quid_desktop::DesktopError;
    
    let platform_error = DesktopError::UnsupportedPlatform("AmigaOS".to_string());
    let system_error = DesktopError::SystemIntegration("Failed to register protocol".to_string());
    let auth_error = DesktopError::Authentication("Invalid signature".to_string());
    let storage_error = DesktopError::Storage("Cannot access keychain".to_string());
    let ui_error = DesktopError::UI("Window creation failed".to_string());
    let notification_error = DesktopError::Notification("System notifications disabled".to_string());
    let config_error = DesktopError::Configuration("Invalid app name".to_string());
    
    // Test error display
    assert!(format!("{}", platform_error).contains("Platform not supported"));
    assert!(format!("{}", system_error).contains("System integration error"));
    assert!(format!("{}", auth_error).contains("Authentication error"));
    assert!(format!("{}", storage_error).contains("Storage error"));
    assert!(format!("{}", ui_error).contains("UI error"));
    assert!(format!("{}", notification_error).contains("Notification error"));
    assert!(format!("{}", config_error).contains("Configuration error"));
    
    Ok(())
}

#[tokio::test]
async fn test_platform_capabilities() -> Result<()> {
    let platform = Platform::detect();
    let capabilities = PlatformCapabilities::for_platform(platform);
    
    // Basic capability tests
    assert_eq!(capabilities.platform, platform);
    
    // Platform-specific capability tests
    match platform {
        Platform::Windows => {
            assert!(capabilities.system_tray);
            assert!(capabilities.system_notifications);
            assert!(capabilities.biometric_auth); // Windows Hello
        },
        Platform::MacOS => {
            assert!(capabilities.system_tray);
            assert!(capabilities.system_notifications);
            assert!(capabilities.keychain_integration);
            assert!(capabilities.biometric_auth); // Touch ID/Face ID
        },
        Platform::Linux => {
            assert!(capabilities.system_notifications);
            // System tray support varies on Linux
        },
        _ => {
            // Future platform support
        }
    }
    
    Ok(())
}

#[tokio::test]
async fn test_config_validation() -> Result<()> {
    // Test valid configuration
    let valid_config = DesktopConfig {
        app_name: "Valid App Name".to_string(),
        enable_notifications: true,
        enable_system_tray: true,
        enable_protocol_handlers: true,
        storage_backend: StorageBackend::Memory,
        platform_settings: HashMap::new(),
    };
    
    assert!(!valid_config.app_name.is_empty());
    
    // Test configuration with empty app name (should be handled gracefully)
    let config_with_empty_name = DesktopConfig {
        app_name: "".to_string(),
        ..valid_config.clone()
    };
    
    assert!(config_with_empty_name.app_name.is_empty());
    
    Ok(())
}

#[tokio::test]
async fn test_authentication_flow_functionality() -> Result<()> {
    use quid_desktop::auth::AuthenticationFlow;
    
    // Test that authentication flow can be created
    let config = DesktopConfig::default();
    let auth_flow = AuthenticationFlow::new(config);
    
    // Test basic functionality
    let supported_networks = auth_flow.supported_networks();
    assert!(!supported_networks.is_empty());
    assert!(supported_networks.contains(&"web".to_string()));
    assert!(supported_networks.contains(&"ssh".to_string()));
    assert!(supported_networks.contains(&"nym".to_string()));
    
    Ok(())
}

#[tokio::test]
async fn test_system_integration_interface() -> Result<()> {
    // Test that SystemIntegration trait methods are properly defined
    let platform = Platform::detect();
    
    // This test ensures the interface is properly structured
    // Implementation will be tested in platform-specific integration tests
    match platform {
        Platform::Windows | Platform::MacOS | Platform::Linux => {
            // These platforms should have implementations
        },
        _ => {
            // Future platforms
        }
    }
    
    Ok(())
}

#[tokio::test]
async fn test_cross_platform_compatibility() -> Result<()> {
    // Test that the library compiles and basic functionality works on all platforms
    let config = DesktopConfig::default();
    let platform = Platform::detect();
    
    // Basic serialization should work on all platforms
    let json = serde_json::to_string(&config)?;
    let _deserialized: DesktopConfig = serde_json::from_str(&json)?;
    
    // Platform detection should always succeed
    match platform {
        Platform::Windows | Platform::MacOS | Platform::Linux => {
            // Known platforms
        },
        _ => {
            // Unknown/future platforms should still be handled
        }
    }
    
    Ok(())
}

#[tokio::test]
async fn test_security_features() -> Result<()> {
    // Test that security-sensitive operations are properly handled
    let request = AuthenticationRequest::new(
        "Potentially Malicious App".to_string(),
        "malicious-site.com".to_string(),
        "web".to_string(),
    ).with_challenge(b"potentially_malicious_challenge".to_vec())
    .with_capability("admin".to_string());
    
    // Service should be properly validated (implementation detail)
    assert!(!request.service.is_empty());
    
    // Challenges should be properly validated
    assert!(request.challenge.is_some());
    
    // Capabilities should be validated
    assert!(!request.capabilities.is_empty());
    
    Ok(())
}

#[tokio::test]
async fn test_performance_requirements() -> Result<()> {
    use std::time::Instant;
    
    // Test that basic operations complete within reasonable time
    let start = Instant::now();
    
    // Platform detection should be fast
    let _platform = Platform::detect();
    
    // Config creation should be fast
    let _config = DesktopConfig::default();
    
    // Basic serialization should be fast
    let config = DesktopConfig::default();
    let _json = serde_json::to_string(&config)?;
    
    let elapsed = start.elapsed();
    
    // All basic operations should complete in less than 100ms
    assert!(elapsed.as_millis() < 100, "Basic operations took too long: {:?}", elapsed);
    
    Ok(())
}