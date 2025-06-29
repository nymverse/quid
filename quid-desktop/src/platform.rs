//! Platform detection and capabilities

use serde::{Deserialize, Serialize};
use std::fmt;

/// Supported desktop platforms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Platform {
    Windows,
    MacOS,
    Linux,
    Unknown,
}

impl Platform {
    /// Detect the current platform
    pub fn detect() -> Self {
        #[cfg(target_os = "windows")]
        return Platform::Windows;
        
        #[cfg(target_os = "macos")]
        return Platform::MacOS;
        
        #[cfg(target_os = "linux")]
        return Platform::Linux;
        
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        return Platform::Unknown;
    }

    /// Get platform name as string
    pub fn name(&self) -> &'static str {
        match self {
            Platform::Windows => "Windows",
            Platform::MacOS => "macOS",
            Platform::Linux => "Linux",
            Platform::Unknown => "Unknown",
        }
    }

    /// Check if platform supports system keychain
    pub fn supports_keychain(&self) -> bool {
        matches!(self, Platform::Windows | Platform::MacOS | Platform::Linux)
    }

    /// Check if platform supports system notifications
    pub fn supports_notifications(&self) -> bool {
        matches!(self, Platform::Windows | Platform::MacOS | Platform::Linux)
    }

    /// Check if platform supports system tray
    pub fn supports_system_tray(&self) -> bool {
        matches!(self, Platform::Windows | Platform::MacOS | Platform::Linux)
    }

    /// Check if platform supports protocol handlers
    pub fn supports_protocol_handlers(&self) -> bool {
        matches!(self, Platform::Windows | Platform::MacOS | Platform::Linux)
    }

    /// Check if platform supports native UI
    pub fn supports_native_ui(&self) -> bool {
        matches!(self, Platform::Windows | Platform::MacOS | Platform::Linux)
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Platform-specific capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformCapabilities {
    pub platform: Platform,
    pub keychain_integration: bool,
    pub system_notifications: bool,
    pub system_tray: bool,
    pub protocol_handlers: bool,
    pub native_ui: bool,
    pub biometric_auth: bool,
    pub hardware_security: bool,
    pub secure_enclave: bool,
    pub features: Vec<String>,
}

impl PlatformCapabilities {
    /// Get capabilities for the current platform
    pub fn for_platform(platform: Platform) -> Self {
        let mut capabilities = Self {
            platform,
            keychain_integration: platform.supports_keychain(),
            system_notifications: platform.supports_notifications(),
            system_tray: platform.supports_system_tray(),
            protocol_handlers: platform.supports_protocol_handlers(),
            native_ui: platform.supports_native_ui(),
            biometric_auth: false,
            hardware_security: false,
            secure_enclave: false,
            features: Vec::new(),
        };

        // Platform-specific features
        match platform {
            Platform::Windows => {
                capabilities.biometric_auth = true; // Windows Hello
                capabilities.hardware_security = true; // TPM
                capabilities.features.extend([
                    "Windows Hello".to_string(),
                    "TPM Integration".to_string(),
                    "Registry Integration".to_string(),
                    "WinRT APIs".to_string(),
                ]);
            }
            Platform::MacOS => {
                capabilities.biometric_auth = true; // Touch ID / Face ID
                capabilities.hardware_security = true; // Secure Enclave
                capabilities.secure_enclave = true;
                capabilities.features.extend([
                    "Touch ID".to_string(),
                    "Face ID".to_string(),
                    "Secure Enclave".to_string(),
                    "Keychain Services".to_string(),
                    "Cocoa APIs".to_string(),
                ]);
            }
            Platform::Linux => {
                capabilities.features.extend([
                    "D-Bus Integration".to_string(),
                    "FreeDesktop Standards".to_string(),
                    "Keyring Integration".to_string(),
                    "X11/Wayland Support".to_string(),
                ]);
            }
            Platform::Unknown => {
                // Minimal capabilities for unknown platforms
            }
        }

        capabilities
    }

    /// Get a list of supported authentication methods
    pub fn auth_methods(&self) -> Vec<String> {
        let mut methods = vec!["Password".to_string(), "QuID".to_string()];
        
        if self.biometric_auth {
            match self.platform {
                Platform::Windows => methods.push("Windows Hello".to_string()),
                Platform::MacOS => {
                    methods.push("Touch ID".to_string());
                    methods.push("Face ID".to_string());
                }
                _ => methods.push("Biometric".to_string()),
            }
        }
        
        if self.hardware_security {
            methods.push("Hardware Security".to_string());
        }
        
        methods
    }

    /// Get platform-specific storage locations
    pub fn storage_locations(&self) -> Vec<String> {
        match self.platform {
            Platform::Windows => vec![
                "%APPDATA%\\QuID".to_string(),
                "%LOCALAPPDATA%\\QuID".to_string(),
                "Windows Credential Manager".to_string(),
            ],
            Platform::MacOS => vec![
                "~/Library/Application Support/QuID".to_string(),
                "~/Library/Preferences/com.quid.app.plist".to_string(),
                "macOS Keychain".to_string(),
            ],
            Platform::Linux => vec![
                "~/.config/quid".to_string(),
                "~/.local/share/quid".to_string(),
                "Secret Service (libsecret)".to_string(),
            ],
            Platform::Unknown => vec!["./quid-data".to_string()],
        }
    }
}

/// System information for diagnostics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub platform: Platform,
    pub os_version: String,
    pub architecture: String,
    pub capabilities: PlatformCapabilities,
    pub runtime_info: RuntimeInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeInfo {
    pub process_id: u32,
    pub user_name: String,
    pub is_elevated: bool,
    pub working_directory: String,
    pub executable_path: String,
}

impl SystemInfo {
    /// Collect comprehensive system information
    pub fn collect() -> Self {
        let platform = Platform::detect();
        let capabilities = PlatformCapabilities::for_platform(platform);
        
        Self {
            platform,
            os_version: Self::get_os_version(),
            architecture: Self::get_architecture(),
            capabilities,
            runtime_info: RuntimeInfo {
                process_id: std::process::id(),
                user_name: Self::get_user_name(),
                is_elevated: Self::is_process_elevated(),
                working_directory: std::env::current_dir()
                    .unwrap_or_default()
                    .display()
                    .to_string(),
                executable_path: std::env::current_exe()
                    .unwrap_or_default()
                    .display()
                    .to_string(),
            },
        }
    }

    fn get_os_version() -> String {
        #[cfg(target_os = "windows")]
        {
            // On Windows, we could use WinAPI to get detailed version
            "Windows".to_string()
        }
        #[cfg(target_os = "macos")]
        {
            // On macOS, we could use system_profiler or similar
            "macOS".to_string()
        }
        #[cfg(target_os = "linux")]
        {
            // On Linux, we could read /etc/os-release
            std::fs::read_to_string("/etc/os-release")
                .unwrap_or_else(|_| "Linux".to_string())
                .lines()
                .find(|line| line.starts_with("PRETTY_NAME="))
                .and_then(|line| line.split('=').nth(1))
                .map(|s| s.trim_matches('"').to_string())
                .unwrap_or_else(|| "Linux".to_string())
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            "Unknown".to_string()
        }
    }

    fn get_architecture() -> String {
        std::env::consts::ARCH.to_string()
    }

    fn get_user_name() -> String {
        std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "unknown".to_string())
    }

    fn is_process_elevated() -> bool {
        #[cfg(target_os = "windows")]
        {
            // On Windows, check if running as administrator
            false // Placeholder
        }
        #[cfg(not(target_os = "windows"))]
        {
            // On Unix-like systems, check if running as root
            unsafe { libc::geteuid() == 0 }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_detection() {
        let platform = Platform::detect();
        assert_ne!(platform, Platform::Unknown);
    }

    #[test]
    fn test_platform_capabilities() {
        let platform = Platform::detect();
        let capabilities = PlatformCapabilities::for_platform(platform);
        
        assert_eq!(capabilities.platform, platform);
        assert!(!capabilities.features.is_empty());
    }

    #[test]
    fn test_auth_methods() {
        let capabilities = PlatformCapabilities::for_platform(Platform::MacOS);
        let methods = capabilities.auth_methods();
        
        assert!(methods.contains(&"Password".to_string()));
        assert!(methods.contains(&"QuID".to_string()));
    }

    #[test]
    fn test_storage_locations() {
        let capabilities = PlatformCapabilities::for_platform(Platform::Linux);
        let locations = capabilities.storage_locations();
        
        assert!(!locations.is_empty());
        assert!(locations.iter().any(|loc| loc.contains(".config")));
    }

    #[test]
    fn test_system_info() {
        let info = SystemInfo::collect();
        
        assert_ne!(info.platform, Platform::Unknown);
        assert!(!info.os_version.is_empty());
        assert!(!info.architecture.is_empty());
        assert!(info.runtime_info.process_id > 0);
    }
}