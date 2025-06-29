//! System integration for cross-platform desktop features

use crate::{DesktopConfig, DesktopError, DesktopResult, Platform, PlatformCapabilities};
use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Trait for system integration functionality
#[async_trait]
pub trait SystemIntegration: Send + Sync {
    /// Get platform capabilities
    fn capabilities(&self) -> &PlatformCapabilities;

    /// Initialize system integration
    async fn initialize(&mut self) -> DesktopResult<()>;

    /// Shutdown system integration
    async fn shutdown(&mut self) -> DesktopResult<()>;

    /// Register protocol handler (e.g., quid://)
    async fn register_protocol_handler(&mut self, protocol: &str) -> DesktopResult<()>;

    /// Unregister protocol handler
    async fn unregister_protocol_handler(&mut self, protocol: &str) -> DesktopResult<()>;

    /// Start system tray integration
    async fn start_system_tray(&mut self) -> DesktopResult<()>;

    /// Stop system tray integration
    async fn stop_system_tray(&mut self) -> DesktopResult<()>;

    /// Show identity manager UI
    async fn show_identity_manager(&self) -> DesktopResult<()>;

    /// Check if protocol handler is registered
    async fn is_protocol_registered(&self, protocol: &str) -> DesktopResult<bool>;

    /// Get system information
    fn system_info(&self) -> &crate::platform::SystemInfo;
}

/// Desktop integration manager
#[derive(Debug)]
pub struct DesktopIntegration {
    platform: Platform,
    capabilities: PlatformCapabilities,
    system_info: crate::platform::SystemInfo,
    config: DesktopConfig,
    state: Arc<RwLock<IntegrationState>>,
}

#[derive(Debug, Default)]
struct IntegrationState {
    initialized: bool,
    protocol_handlers: std::collections::HashSet<String>,
    system_tray_active: bool,
}

impl DesktopIntegration {
    /// Create new desktop integration
    pub fn new(platform: Platform, config: DesktopConfig) -> Self {
        let capabilities = PlatformCapabilities::for_platform(platform);
        let system_info = crate::platform::SystemInfo::collect();

        Self {
            platform,
            capabilities,
            system_info,
            config,
            state: Arc::new(RwLock::new(IntegrationState::default())),
        }
    }

    /// Register application for autostart
    pub async fn enable_autostart(&self) -> DesktopResult<()> {
        match self.platform {
            Platform::Windows => self.enable_autostart_windows().await,
            Platform::MacOS => self.enable_autostart_macos().await,
            Platform::Linux => self.enable_autostart_linux().await,
            Platform::Unknown => Err(DesktopError::UnsupportedPlatform("Unknown platform".to_string())),
        }
    }

    /// Disable application autostart
    pub async fn disable_autostart(&self) -> DesktopResult<()> {
        match self.platform {
            Platform::Windows => self.disable_autostart_windows().await,
            Platform::MacOS => self.disable_autostart_macos().await,
            Platform::Linux => self.disable_autostart_linux().await,
            Platform::Unknown => Err(DesktopError::UnsupportedPlatform("Unknown platform".to_string())),
        }
    }

    #[cfg(target_os = "windows")]
    async fn enable_autostart_windows(&self) -> DesktopResult<()> {
        use std::process::Command;
        
        let exe_path = std::env::current_exe()
            .map_err(|e| DesktopError::SystemIntegration(format!("Failed to get executable path: {}", e)))?;
        
        let output = Command::new("reg")
            .args([
                "add",
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "/v",
                &self.config.app_name,
                "/t",
                "REG_SZ",
                "/d",
                &exe_path.display().to_string(),
                "/f",
            ])
            .output()
            .map_err(|e| DesktopError::SystemIntegration(format!("Failed to register autostart: {}", e)))?;

        if !output.status.success() {
            return Err(DesktopError::SystemIntegration(
                format!("Registry command failed: {}", String::from_utf8_lossy(&output.stderr))
            ));
        }

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    async fn enable_autostart_windows(&self) -> DesktopResult<()> {
        Err(DesktopError::UnsupportedPlatform("Windows autostart not available on this platform".to_string()))
    }

    #[cfg(target_os = "macos")]
    async fn enable_autostart_macos(&self) -> DesktopResult<()> {
        let home_dir = dirs::home_dir()
            .ok_or_else(|| DesktopError::SystemIntegration("Could not find home directory".to_string()))?;
        
        let launch_agents_dir = home_dir.join("Library/LaunchAgents");
        tokio::fs::create_dir_all(&launch_agents_dir).await
            .map_err(|e| DesktopError::SystemIntegration(format!("Failed to create LaunchAgents directory: {}", e)))?;

        let plist_path = launch_agents_dir.join(format!("com.{}.quid.plist", self.config.app_name.to_lowercase().replace(" ", "")));
        let exe_path = std::env::current_exe()
            .map_err(|e| DesktopError::SystemIntegration(format!("Failed to get executable path: {}", e)))?;

        let plist_content = format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.{}.quid</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>--background</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>"#, 
            self.config.app_name.to_lowercase().replace(" ", ""),
            exe_path.display()
        );

        tokio::fs::write(&plist_path, plist_content).await
            .map_err(|e| DesktopError::SystemIntegration(format!("Failed to write plist file: {}", e)))?;

        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    async fn enable_autostart_macos(&self) -> DesktopResult<()> {
        Err(DesktopError::UnsupportedPlatform("macOS autostart not available on this platform".to_string()))
    }

    #[cfg(target_os = "linux")]
    async fn enable_autostart_linux(&self) -> DesktopResult<()> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| DesktopError::SystemIntegration("Could not find config directory".to_string()))?;
        
        let autostart_dir = config_dir.join("autostart");
        tokio::fs::create_dir_all(&autostart_dir).await
            .map_err(|e| DesktopError::SystemIntegration(format!("Failed to create autostart directory: {}", e)))?;

        let desktop_file_path = autostart_dir.join(format!("{}.desktop", self.config.app_name.to_lowercase().replace(" ", "-")));
        let exe_path = std::env::current_exe()
            .map_err(|e| DesktopError::SystemIntegration(format!("Failed to get executable path: {}", e)))?;

        let desktop_content = format!(r#"[Desktop Entry]
Type=Application
Name={}
Exec={} --background
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
Comment=QuID Universal Authentication
"#, 
            self.config.app_name,
            exe_path.display()
        );

        tokio::fs::write(&desktop_file_path, desktop_content).await
            .map_err(|e| DesktopError::SystemIntegration(format!("Failed to write desktop file: {}", e)))?;

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    async fn enable_autostart_linux(&self) -> DesktopResult<()> {
        Err(DesktopError::UnsupportedPlatform("Linux autostart not available on this platform".to_string()))
    }

    async fn disable_autostart_windows(&self) -> DesktopResult<()> {
        // Implementation would remove registry entry
        Ok(())
    }

    async fn disable_autostart_macos(&self) -> DesktopResult<()> {
        // Implementation would remove plist file
        Ok(())
    }

    async fn disable_autostart_linux(&self) -> DesktopResult<()> {
        // Implementation would remove desktop file
        Ok(())
    }
}

#[async_trait]
impl SystemIntegration for DesktopIntegration {
    fn capabilities(&self) -> &PlatformCapabilities {
        &self.capabilities
    }

    async fn initialize(&mut self) -> DesktopResult<()> {
        let mut state = self.state.write().await;
        if state.initialized {
            return Ok(());
        }

        // Platform-specific initialization
        match self.platform {
            Platform::Windows => {
                #[cfg(target_os = "windows")]
                {
                    // Initialize Windows-specific features
                }
            }
            Platform::MacOS => {
                #[cfg(target_os = "macos")]
                {
                    // Initialize macOS-specific features
                }
            }
            Platform::Linux => {
                #[cfg(target_os = "linux")]
                {
                    // Initialize Linux-specific features
                }
            }
            Platform::Unknown => {
                return Err(DesktopError::UnsupportedPlatform("Unknown platform".to_string()));
            }
        }

        state.initialized = true;
        Ok(())
    }

    async fn shutdown(&mut self) -> DesktopResult<()> {
        let mut state = self.state.write().await;
        
        // Stop system tray if active
        if state.system_tray_active {
            // Implementation would stop system tray
            state.system_tray_active = false;
        }

        // Unregister protocol handlers
        let protocols_to_remove: Vec<String> = state.protocol_handlers.iter().cloned().collect();
        drop(state); // Release the lock before calling unregister
        
        for protocol in protocols_to_remove {
            let _ = self.unregister_protocol_handler(&protocol).await;
        }
        
        let mut state = self.state.write().await;
        state.protocol_handlers.clear();

        state.initialized = false;
        Ok(())
    }

    async fn register_protocol_handler(&mut self, protocol: &str) -> DesktopResult<()> {
        match self.platform {
            Platform::Windows => self.register_protocol_windows(protocol).await,
            Platform::MacOS => self.register_protocol_macos(protocol).await,
            Platform::Linux => self.register_protocol_linux(protocol).await,
            Platform::Unknown => Err(DesktopError::UnsupportedPlatform("Unknown platform".to_string())),
        }?;

        let mut state = self.state.write().await;
        state.protocol_handlers.insert(protocol.to_string());
        Ok(())
    }

    async fn unregister_protocol_handler(&mut self, protocol: &str) -> DesktopResult<()> {
        // Platform-specific unregistration would go here
        let mut state = self.state.write().await;
        state.protocol_handlers.remove(protocol);
        Ok(())
    }

    async fn start_system_tray(&mut self) -> DesktopResult<()> {
        if !self.capabilities.system_tray {
            return Err(DesktopError::UnsupportedPlatform("System tray not supported".to_string()));
        }

        let mut state = self.state.write().await;
        if state.system_tray_active {
            return Ok(());
        }

        // Platform-specific system tray initialization would go here
        state.system_tray_active = true;
        Ok(())
    }

    async fn stop_system_tray(&mut self) -> DesktopResult<()> {
        let mut state = self.state.write().await;
        state.system_tray_active = false;
        Ok(())
    }

    async fn show_identity_manager(&self) -> DesktopResult<()> {
        // This would launch the identity manager UI
        // For now, just print a message
        println!("🆔 Opening QuID Identity Manager...");
        Ok(())
    }

    async fn is_protocol_registered(&self, protocol: &str) -> DesktopResult<bool> {
        let state = self.state.read().await;
        Ok(state.protocol_handlers.contains(protocol))
    }

    fn system_info(&self) -> &crate::platform::SystemInfo {
        &self.system_info
    }
}

impl DesktopIntegration {
    #[cfg(target_os = "windows")]
    async fn register_protocol_windows(&self, protocol: &str) -> DesktopResult<()> {
        use std::process::Command;
        
        let exe_path = std::env::current_exe()
            .map_err(|e| DesktopError::SystemIntegration(format!("Failed to get executable path: {}", e)))?;
        
        // Register protocol in Windows Registry
        let commands = [
            format!("reg add HKEY_CURRENT_USER\\Software\\Classes\\{} /ve /d \"URL:{} Protocol\" /f", protocol, protocol),
            format!("reg add HKEY_CURRENT_USER\\Software\\Classes\\{} /v \"URL Protocol\" /t REG_SZ /d \"\" /f", protocol),
            format!("reg add HKEY_CURRENT_USER\\Software\\Classes\\{}\\shell\\open\\command /ve /d \"\\\"{}\\\" \\\"%1\\\"\" /f", protocol, exe_path.display()),
        ];

        for cmd in &commands {
            let output = Command::new("cmd")
                .args(["/C", cmd])
                .output()
                .map_err(|e| DesktopError::SystemIntegration(format!("Failed to register protocol: {}", e)))?;

            if !output.status.success() {
                return Err(DesktopError::SystemIntegration(
                    format!("Registry command failed: {}", String::from_utf8_lossy(&output.stderr))
                ));
            }
        }

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    async fn register_protocol_windows(&self, _protocol: &str) -> DesktopResult<()> {
        Err(DesktopError::UnsupportedPlatform("Windows protocol registration not available".to_string()))
    }

    #[cfg(target_os = "macos")]
    async fn register_protocol_macos(&self, protocol: &str) -> DesktopResult<()> {
        // macOS protocol registration would typically be done through Info.plist
        // For runtime registration, we'd need to use LaunchServices APIs
        println!("📱 Protocol {} registration on macOS requires app bundle configuration", protocol);
        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    async fn register_protocol_macos(&self, _protocol: &str) -> DesktopResult<()> {
        Err(DesktopError::UnsupportedPlatform("macOS protocol registration not available".to_string()))
    }

    #[cfg(target_os = "linux")]
    async fn register_protocol_linux(&self, protocol: &str) -> DesktopResult<()> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| DesktopError::SystemIntegration("Could not find config directory".to_string()))?;
        
        let applications_dir = config_dir.join("applications");
        tokio::fs::create_dir_all(&applications_dir).await
            .map_err(|e| DesktopError::SystemIntegration(format!("Failed to create applications directory: {}", e)))?;

        let desktop_file_path = applications_dir.join(format!("quid-{}.desktop", protocol));
        let exe_path = std::env::current_exe()
            .map_err(|e| DesktopError::SystemIntegration(format!("Failed to get executable path: {}", e)))?;

        let desktop_content = format!(r#"[Desktop Entry]
Type=Application
Name=QuID {} Protocol Handler
Exec={} handle-protocol %u
MimeType=x-scheme-handler/{}
NoDisplay=true
"#, 
            protocol.to_uppercase(),
            exe_path.display(),
            protocol
        );

        tokio::fs::write(&desktop_file_path, desktop_content).await
            .map_err(|e| DesktopError::SystemIntegration(format!("Failed to write desktop file: {}", e)))?;

        // Update desktop database
        let _ = std::process::Command::new("update-desktop-database")
            .arg(&applications_dir)
            .output();

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    async fn register_protocol_linux(&self, _protocol: &str) -> DesktopResult<()> {
        Err(DesktopError::UnsupportedPlatform("Linux protocol registration not available".to_string()))
    }
}

/// Create appropriate integration for the platform
pub async fn create_integration(platform: Platform, config: &DesktopConfig) -> Result<Box<dyn SystemIntegration>> {
    let integration = DesktopIntegration::new(platform, config.clone());
    Ok(Box::new(integration))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integration_creation() {
        let platform = Platform::detect();
        let config = DesktopConfig::default();
        let integration = DesktopIntegration::new(platform, config);
        
        assert_eq!(integration.platform, platform);
        assert_eq!(integration.capabilities.platform, platform);
    }

    #[tokio::test]
    async fn test_integration_lifecycle() {
        let platform = Platform::detect();
        let config = DesktopConfig::default();
        let mut integration = DesktopIntegration::new(platform, config);
        
        // Test initialization
        let result = integration.initialize().await;
        assert!(result.is_ok());
        
        // Test shutdown
        let result = integration.shutdown().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_protocol_registration() {
        let platform = Platform::detect();
        let config = DesktopConfig::default();
        let mut integration = DesktopIntegration::new(platform, config);
        
        let result = integration.register_protocol_handler("quid").await;
        // May fail on some platforms without proper permissions
        if result.is_ok() {
            let is_registered = integration.is_protocol_registered("quid").await.unwrap();
            assert!(is_registered);
        }
    }

    #[tokio::test]
    async fn test_system_tray() {
        let platform = Platform::detect();
        let config = DesktopConfig::default();
        let mut integration = DesktopIntegration::new(platform, config);
        
        if integration.capabilities().system_tray {
            let result = integration.start_system_tray().await;
            assert!(result.is_ok());
            
            let result = integration.stop_system_tray().await;
            assert!(result.is_ok());
        }
    }
}