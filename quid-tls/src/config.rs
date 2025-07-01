//! Configuration management for QuID TLS integration

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::{QuIDTLSError, QuIDTLSResult};

/// Complete QuID TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuIDTLSConfig {
    /// TLS settings
    pub tls: TLSSettings,
    /// PKI configuration
    pub pki: PKIConfig,
}

/// TLS connection settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TLSSettings {
    /// Supported TLS versions
    pub supported_versions: Vec<String>,
    /// Cipher suites
    pub cipher_suites: Vec<String>,
    /// Certificate verification mode
    pub verify_mode: CertificateVerification,
    /// Client certificate requirement
    pub require_client_cert: bool,
}

/// PKI configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PKIConfig {
    /// Certificate directory
    pub certificate_directory: Option<PathBuf>,
    /// CA directory
    pub ca_directory: Option<PathBuf>,
    /// Private key storage (QuID identities)
    pub identity_storage: Option<PathBuf>,
}

/// Certificate verification modes
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CertificateVerification {
    /// Full verification required
    Required,
    /// Optional verification
    Optional,
    /// No verification (insecure)
    None,
}

impl Default for QuIDTLSConfig {
    fn default() -> Self {
        Self {
            tls: TLSSettings::default(),
            pki: PKIConfig::default(),
        }
    }
}

impl Default for TLSSettings {
    fn default() -> Self {
        Self {
            supported_versions: vec!["1.3".to_string(), "1.2".to_string()],
            cipher_suites: vec![
                "TLS_AES_256_GCM_SHA384".to_string(),
                "TLS_CHACHA20_POLY1305_SHA256".to_string(),
                "TLS_AES_128_GCM_SHA256".to_string(),
            ],
            verify_mode: CertificateVerification::Required,
            require_client_cert: false,
        }
    }
}

impl Default for PKIConfig {
    fn default() -> Self {
        Self {
            certificate_directory: None,
            ca_directory: None,
            identity_storage: None,
        }
    }
}

impl QuIDTLSConfig {
    /// Validate configuration
    pub fn validate(&self) -> QuIDTLSResult<()> {
        if self.tls.supported_versions.is_empty() {
            return Err(QuIDTLSError::ConfigurationError(
                "At least one TLS version must be supported".to_string()
            ));
        }

        if self.tls.cipher_suites.is_empty() {
            return Err(QuIDTLSError::ConfigurationError(
                "At least one cipher suite must be configured".to_string()
            ));
        }

        Ok(())
    }

    /// Load configuration from file
    pub fn load_from_file(path: &std::path::Path) -> QuIDTLSResult<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| QuIDTLSError::ConfigurationError(format!("Failed to read config file: {}", e)))?;

        let config: QuIDTLSConfig = if path.extension() == Some(std::ffi::OsStr::new("json")) {
            serde_json::from_str(&content)
                .map_err(|e| QuIDTLSError::ConfigurationError(format!("Failed to parse JSON config: {}", e)))?
        } else {
            toml::from_str(&content)
                .map_err(|e| QuIDTLSError::ConfigurationError(format!("Failed to parse TOML config: {}", e)))?
        };

        config.validate()?;
        Ok(config)
    }

    /// Save configuration to file
    pub fn save_to_file(&self, path: &std::path::Path) -> QuIDTLSResult<()> {
        let content = if path.extension() == Some(std::ffi::OsStr::new("json")) {
            serde_json::to_string_pretty(self)
                .map_err(|e| QuIDTLSError::ConfigurationError(format!("Failed to serialize JSON: {}", e)))?
        } else {
            toml::to_string_pretty(self)
                .map_err(|e| QuIDTLSError::ConfigurationError(format!("Failed to serialize TOML: {}", e)))?
        };

        std::fs::write(path, content)
            .map_err(|e| QuIDTLSError::ConfigurationError(format!("Failed to write config file: {}", e)))?;

        Ok(())
    }
}