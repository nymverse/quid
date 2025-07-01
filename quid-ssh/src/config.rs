//! Configuration management for QuID SSH integration

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use crate::server::{SSHServerConfig, AuthorizedUsersConfig, UserConfig};
use crate::client::SSHClientConfig;
use crate::{QuIDSSHError, QuIDSSHResult};

/// Complete QuID SSH configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuIDSSHConfig {
    /// Client configuration
    pub client: ClientSettings,
    /// Server configuration (optional)
    pub server: Option<ServerSettings>,
}

/// Client settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSettings {
    /// Directory to store QuID SSH keys
    pub key_directory: Option<PathBuf>,
    /// Default username for connections
    pub default_username: Option<String>,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Authentication timeout in seconds
    pub auth_timeout: u64,
    /// SSH agent socket path
    pub ssh_agent_socket: Option<PathBuf>,
    /// Known hosts file for QuID keys
    pub known_hosts_file: Option<PathBuf>,
    /// Client configuration file path
    pub config_file: Option<PathBuf>,
}

impl Default for ClientSettings {
    fn default() -> Self {
        Self {
            key_directory: None,
            default_username: None,
            connection_timeout: 30,
            auth_timeout: 30,
            ssh_agent_socket: None,
            known_hosts_file: None,
            config_file: None,
        }
    }
}

/// Server settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    /// Server bind address
    pub bind_address: SocketAddr,
    /// Host key directory
    pub host_key_directory: Option<PathBuf>,
    /// Maximum concurrent connections
    pub max_connections: u32,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Authentication timeout in seconds
    pub auth_timeout: u64,
    /// Authorized users configuration
    pub authorized_users: AuthorizedUsersConfig,
    /// Server banner
    pub banner: Option<String>,
    /// Message of the day
    pub motd: Option<String>,
    /// Enable SFTP subsystem
    pub enable_sftp: bool,
    /// Enable port forwarding
    pub enable_port_forwarding: bool,
    /// Log file path
    pub log_file: Option<PathBuf>,
    /// PID file path
    pub pid_file: Option<PathBuf>,
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:2222".parse().unwrap(),
            host_key_directory: None,
            max_connections: 100,
            connection_timeout: 300,
            auth_timeout: 60,
            authorized_users: AuthorizedUsersConfig::default(),
            banner: Some("QuID SSH Server - Quantum-Resistant Authentication".to_string()),
            motd: None,
            enable_sftp: true,
            enable_port_forwarding: false,
            log_file: None,
            pid_file: None,
        }
    }
}

impl QuIDSSHConfig {
    /// Load configuration from file
    pub fn load_from_file(path: &std::path::Path) -> QuIDSSHResult<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| QuIDSSHError::ConfigurationError(format!("Failed to read config file: {}", e)))?;

        let config: QuIDSSHConfig = if path.extension() == Some(std::ffi::OsStr::new("json")) {
            serde_json::from_str(&content)
                .map_err(|e| QuIDSSHError::ConfigurationError(format!("Failed to parse JSON config: {}", e)))?
        } else {
            toml::from_str(&content)
                .map_err(|e| QuIDSSHError::ConfigurationError(format!("Failed to parse TOML config: {}", e)))?
        };

        config.validate()?;
        Ok(config)
    }

    /// Save configuration to file
    pub fn save_to_file(&self, path: &std::path::Path) -> QuIDSSHResult<()> {
        let content = if path.extension() == Some(std::ffi::OsStr::new("json")) {
            serde_json::to_string_pretty(self)
                .map_err(|e| QuIDSSHError::ConfigurationError(format!("Failed to serialize JSON: {}", e)))?
        } else {
            toml::to_string_pretty(self)
                .map_err(|e| QuIDSSHError::ConfigurationError(format!("Failed to serialize TOML: {}", e)))?
        };

        std::fs::write(path, content)
            .map_err(|e| QuIDSSHError::ConfigurationError(format!("Failed to write config file: {}", e)))?;

        Ok(())
    }

    /// Create default configuration
    pub fn default() -> Self {
        Self {
            client: ClientSettings::default(),
            server: Some(ServerSettings::default()),
        }
    }

    /// Create client-only configuration
    pub fn client_only() -> Self {
        Self {
            client: ClientSettings::default(),
            server: None,
        }
    }

    /// Validate configuration
    pub fn validate(&self) -> QuIDSSHResult<()> {
        // Validate client settings
        if self.client.connection_timeout == 0 {
            return Err(QuIDSSHError::ConfigurationError(
                "Client connection timeout must be greater than 0".to_string()
            ));
        }

        if self.client.auth_timeout == 0 {
            return Err(QuIDSSHError::ConfigurationError(
                "Client auth timeout must be greater than 0".to_string()
            ));
        }

        // Validate server settings if present
        if let Some(server) = &self.server {
            if server.max_connections == 0 {
                return Err(QuIDSSHError::ConfigurationError(
                    "Server max connections must be greater than 0".to_string()
                ));
            }

            if server.connection_timeout == 0 {
                return Err(QuIDSSHError::ConfigurationError(
                    "Server connection timeout must be greater than 0".to_string()
                ));
            }

            if server.auth_timeout == 0 {
                return Err(QuIDSSHError::ConfigurationError(
                    "Server auth timeout must be greater than 0".to_string()
                ));
            }
        }

        Ok(())
    }

    /// Convert to SSH client config
    pub fn to_ssh_client_config(&self) -> SSHClientConfig {
        SSHClientConfig {
            default_username: self.client.default_username.clone(),
            connection_timeout: self.client.connection_timeout,
            auth_timeout: self.client.auth_timeout,
            ..Default::default()
        }
    }

    /// Convert to SSH server config
    pub fn to_ssh_server_config(&self) -> Option<SSHServerConfig> {
        self.server.as_ref().map(|server| SSHServerConfig {
            bind_address: server.bind_address,
            max_connections: server.max_connections,
            connection_timeout: server.connection_timeout,
            auth_timeout: server.auth_timeout,
            authorized_users: server.authorized_users.clone(),
            banner: server.banner.clone(),
            motd: server.motd.clone(),
            enable_sftp: server.enable_sftp,
            enable_port_forwarding: server.enable_port_forwarding,
            ..Default::default()
        })
    }

    /// Get default config file paths
    pub fn get_default_config_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        // User config
        if let Some(home) = dirs::home_dir() {
            paths.push(home.join(".quid").join("ssh").join("config.toml"));
            paths.push(home.join(".quid").join("ssh").join("config.json"));
        }

        // System config
        paths.push(PathBuf::from("/etc/quid/ssh/config.toml"));
        paths.push(PathBuf::from("/etc/quid/ssh/config.json"));

        paths
    }

    /// Load configuration from default locations
    pub fn load_default() -> QuIDSSHResult<Self> {
        let config_paths = Self::get_default_config_paths();

        for path in config_paths {
            if path.exists() {
                return Self::load_from_file(&path);
            }
        }

        // No config file found, return default
        Ok(Self::default())
    }

    /// Create example configuration file
    pub fn create_example_config(path: &std::path::Path) -> QuIDSSHResult<()> {
        let mut config = Self::default();

        // Add example settings
        config.client.default_username = Some("alice".to_string());
        config.client.key_directory = Some(PathBuf::from("~/.ssh/quid"));

        if let Some(server) = &mut config.server {
            server.bind_address = "0.0.0.0:2222".parse().unwrap();
            server.banner = Some("Welcome to QuID SSH Server".to_string());
            server.motd = Some("This server uses quantum-resistant authentication".to_string());

            // Add example user
            let mut user_config = UserConfig::default();
            user_config.quid_identities = vec!["identity-123".to_string()];
            user_config.shell = Some("/bin/bash".to_string());
            
            server.authorized_users.users.insert("alice".to_string(), user_config);
        }

        config.save_to_file(path)
    }
}

/// Configuration management utilities
pub struct ConfigManager;

impl ConfigManager {
    /// Initialize configuration directory
    pub fn init_config_dir() -> QuIDSSHResult<PathBuf> {
        let config_dir = if let Some(home) = dirs::home_dir() {
            home.join(".quid").join("ssh")
        } else {
            PathBuf::from("/etc/quid/ssh")
        };

        std::fs::create_dir_all(&config_dir)
            .map_err(|e| QuIDSSHError::ConfigurationError(format!("Failed to create config directory: {}", e)))?;

        Ok(config_dir)
    }

    /// Get configuration directory
    pub fn get_config_dir() -> PathBuf {
        if let Some(home) = dirs::home_dir() {
            home.join(".quid").join("ssh")
        } else {
            PathBuf::from("/etc/quid/ssh")
        }
    }

    /// Migrate old configuration format
    pub fn migrate_config(old_path: &std::path::Path, new_path: &std::path::Path) -> QuIDSSHResult<()> {
        if !old_path.exists() {
            return Ok(());
        }

        // Read old config (assume it's in a simpler format)
        let old_content = std::fs::read_to_string(old_path)
            .map_err(|e| QuIDSSHError::ConfigurationError(format!("Failed to read old config: {}", e)))?;

        // Parse and convert to new format
        let new_config = Self::convert_old_config(&old_content)?;

        // Save new config
        new_config.save_to_file(new_path)?;

        // Backup old config
        let backup_path = old_path.with_extension("bak");
        std::fs::rename(old_path, backup_path)
            .map_err(|e| QuIDSSHError::ConfigurationError(format!("Failed to backup old config: {}", e)))?;

        Ok(())
    }

    /// Convert old configuration format
    fn convert_old_config(content: &str) -> QuIDSSHResult<QuIDSSHConfig> {
        // This is a placeholder for configuration migration
        // In a real implementation, you would parse the old format
        // and convert it to the new structure
        
        let mut config = QuIDSSHConfig::default();
        
        // Parse simple key=value format
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            if let Some((key, value)) = line.split_once('=') {
                match key.trim() {
                    "bind_address" => {
                        if let Some(server) = &mut config.server {
                            server.bind_address = value.trim().parse()
                                .map_err(|_| QuIDSSHError::ConfigurationError("Invalid bind address".to_string()))?;
                        }
                    }
                    "max_connections" => {
                        if let Some(server) = &mut config.server {
                            server.max_connections = value.trim().parse()
                                .map_err(|_| QuIDSSHError::ConfigurationError("Invalid max connections".to_string()))?;
                        }
                    }
                    "default_username" => {
                        config.client.default_username = Some(value.trim().to_string());
                    }
                    _ => {
                        // Unknown setting, ignore
                    }
                }
            }
        }
        
        Ok(config)
    }

    /// Validate file permissions
    pub fn validate_permissions(path: &std::path::Path) -> QuIDSSHResult<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            
            let metadata = std::fs::metadata(path)
                .map_err(|e| QuIDSSHError::ConfigurationError(format!("Failed to read file metadata: {}", e)))?;
            
            let permissions = metadata.permissions();
            let mode = permissions.mode();
            
            // Check if file is readable by others (should not be for security files)
            if mode & 0o044 != 0 {
                return Err(QuIDSSHError::ConfigurationError(
                    format!("File {} has insecure permissions (readable by others)", path.display())
                ));
            }
        }
        
        Ok(())
    }

    /// Set secure file permissions
    pub fn set_secure_permissions(path: &std::path::Path) -> QuIDSSHResult<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| QuIDSSHError::ConfigurationError(format!("Failed to set file permissions: {}", e)))?;
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_config_validation() {
        let mut config = QuIDSSHConfig::default();
        assert!(config.validate().is_ok());

        // Test invalid client timeout
        config.client.connection_timeout = 0;
        assert!(config.validate().is_err());

        // Reset and test invalid server timeout
        config.client.connection_timeout = 30;
        if let Some(server) = &mut config.server {
            server.max_connections = 0;
        }
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_serialization() {
        let config = QuIDSSHConfig::default();
        
        // Test TOML serialization
        let toml_str = toml::to_string(&config).unwrap();
        let parsed_config: QuIDSSHConfig = toml::from_str(&toml_str).unwrap();
        assert!(parsed_config.validate().is_ok());

        // Test JSON serialization
        let json_str = serde_json::to_string(&config).unwrap();
        let parsed_config: QuIDSSHConfig = serde_json::from_str(&json_str).unwrap();
        assert!(parsed_config.validate().is_ok());
    }

    #[test]
    fn test_config_file_operations() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");

        let config = QuIDSSHConfig::default();
        
        // Test save
        assert!(config.save_to_file(&config_path).is_ok());
        assert!(config_path.exists());

        // Test load
        let loaded_config = QuIDSSHConfig::load_from_file(&config_path).unwrap();
        assert!(loaded_config.validate().is_ok());
    }

    #[test]
    fn test_client_only_config() {
        let config = QuIDSSHConfig::client_only();
        assert!(config.server.is_none());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_conversion() {
        let config = QuIDSSHConfig::default();
        
        let client_config = config.to_ssh_client_config();
        assert_eq!(client_config.connection_timeout, config.client.connection_timeout);

        let server_config = config.to_ssh_server_config().unwrap();
        assert_eq!(server_config.bind_address, config.server.as_ref().unwrap().bind_address);
    }
}