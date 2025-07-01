//! QuID SSH Integration
//!
//! This crate provides SSH client and server integration for QuID quantum-resistant authentication.
//! It allows seamless SSH authentication using QuID identities instead of traditional SSH keys.

pub mod client;
pub mod server;
pub mod keys;
pub mod config;
pub mod migration;
pub mod certificate;

// Re-export commonly used types
pub use client::{QuIDSSHClient, SSHClientConfig, ConnectionResult};
pub use server::{QuIDSSHServer, SSHServerConfig, AuthenticationHandler};
pub use keys::{QuIDSSHKey, SSHKeyType, KeyConversion};
pub use config::{QuIDSSHConfig, ServerSettings, ClientSettings};
pub use migration::{SSHKeyMigrator, MigrationOptions, MigrationResult};
pub use certificate::{CertificateAuthority, SSHCertificate, CertificateOptions};

use anyhow::Result;
use quid_core::{QuIDClient, QuIDIdentity};

/// QuID SSH integration error types
#[derive(thiserror::Error, Debug)]
pub enum QuIDSSHError {
    #[error("SSH connection failed: {0}")]
    ConnectionFailed(String),
    
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    
    #[error("Key conversion failed: {0}")]
    KeyConversionFailed(String),
    
    #[error("Certificate generation failed: {0}")]
    CertificateGenerationFailed(String),
    
    #[error("Migration failed: {0}")]
    MigrationFailed(String),
    
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("QuID core error: {0}")]
    QuIDCoreError(#[from] quid_core::QuIDError),
    
    #[error("SSH protocol error: {0}")]
    SSHProtocolError(String),
    
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Result type for QuID SSH operations
pub type QuIDSSHResult<T> = Result<T, QuIDSSHError>;

/// Initialize QuID SSH integration with given configuration
pub async fn initialize_quid_ssh(config: QuIDSSHConfig) -> QuIDSSHResult<()> {
    tracing::info!("Initializing QuID SSH integration");
    
    // Validate configuration
    config.validate()?;
    
    // Initialize SSH key directories if they don't exist
    if let Some(key_dir) = &config.client.key_directory {
        std::fs::create_dir_all(key_dir)
            .map_err(|e| QuIDSSHError::ConfigurationError(format!("Failed to create key directory: {}", e)))?;
    }
    
    if let Some(server_config) = &config.server {
        if let Some(host_key_dir) = &server_config.host_key_directory {
            std::fs::create_dir_all(host_key_dir)
                .map_err(|e| QuIDSSHError::ConfigurationError(format!("Failed to create host key directory: {}", e)))?;
        }
    }
    
    tracing::info!("QuID SSH integration initialized successfully");
    Ok(())
}

/// Get the default QuID SSH configuration directory
pub fn get_default_config_dir() -> std::path::PathBuf {
    if let Some(home) = dirs::home_dir() {
        home.join(".quid").join("ssh")
    } else {
        std::path::PathBuf::from("/etc/quid/ssh")
    }
}

/// Get the default SSH directory for QuID keys
pub fn get_default_ssh_dir() -> std::path::PathBuf {
    if let Some(home) = dirs::home_dir() {
        home.join(".ssh").join("quid")
    } else {
        std::path::PathBuf::from("/var/lib/quid/ssh")
    }
}

/// Convert a QuID identity to an SSH public key format
pub async fn identity_to_ssh_public_key(
    quid_client: &QuIDClient,
    identity: &QuIDIdentity,
) -> QuIDSSHResult<String> {
    let quid_key = QuIDSSHKey::from_identity(quid_client, identity).await?;
    quid_key.to_ssh_public_key()
}

/// Verify an SSH signature using QuID
pub async fn verify_ssh_signature(
    quid_client: &QuIDClient,
    identity: &QuIDIdentity,
    signature: &[u8],
    data: &[u8],
) -> QuIDSSHResult<bool> {
    let quid_key = QuIDSSHKey::from_identity(quid_client, identity).await?;
    quid_key.verify_signature(signature, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_default_directories() {
        let config_dir = get_default_config_dir();
        assert!(config_dir.to_string_lossy().contains("quid"));
        assert!(config_dir.to_string_lossy().contains("ssh"));

        let ssh_dir = get_default_ssh_dir();
        assert!(ssh_dir.to_string_lossy().contains("ssh"));
        assert!(ssh_dir.to_string_lossy().contains("quid"));
    }

    #[tokio::test]
    async fn test_initialize_quid_ssh() {
        let temp_dir = TempDir::new().unwrap();
        let config = QuIDSSHConfig {
            client: ClientSettings {
                key_directory: Some(temp_dir.path().join("keys")),
                ..Default::default()
            },
            server: None,
        };

        let result = initialize_quid_ssh(config).await;
        assert!(result.is_ok());
        assert!(temp_dir.path().join("keys").exists());
    }
}