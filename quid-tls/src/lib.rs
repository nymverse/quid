//! QuID TLS and PKI Integration
//!
//! This crate provides TLS and PKI functionality using QuID quantum-resistant authentication,
//! including X.509 certificate generation with ML-DSA signatures and TLS client certificate authentication.

pub mod cert;
pub mod client;
pub mod server;
pub mod config;
pub mod pki;
pub mod x509;

// Re-export commonly used types
pub use cert::{QuIDCertificate, CertificateBuilder, CertificateOptions};
pub use client::{QuIDTLSClient, TLSClientConfig, ClientConnectionResult};
pub use server::{QuIDTLSServer, TLSServerConfig, ServerAuthHandler};
pub use config::{QuIDTLSConfig, TLSSettings, PKIConfig};
pub use pki::{PKIManager, CertificateAuthority, CertificateChain};
pub use x509::{X509Certificate, X509CertificateBuilder, MLDSASignature};

use anyhow::Result;
use quid_core::{QuIDClient, QuIDIdentity};

/// QuID TLS integration error types
#[derive(thiserror::Error, Debug)]
pub enum QuIDTLSError {
    #[error("TLS connection failed: {0}")]
    ConnectionFailed(String),
    
    #[error("Certificate generation failed: {0}")]
    CertificateGenerationFailed(String),
    
    #[error("Certificate validation failed: {0}")]
    CertificateValidationFailed(String),
    
    #[error("TLS handshake failed: {0}")]
    HandshakeFailed(String),
    
    #[error("PKI operation failed: {0}")]
    PKIOperationFailed(String),
    
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("Encoding error: {0}")]
    EncodingError(String),
    
    #[error("QuID core error: {0}")]
    QuIDCoreError(#[from] quid_core::QuIDError),
    
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("TLS error: {0}")]
    TLSError(#[from] rustls::Error),
    
    #[error("X.509 parsing error: {0}")]
    X509ParseError(String),
}

/// Result type for QuID TLS operations
pub type QuIDTLSResult<T> = Result<T, QuIDTLSError>;

/// Initialize QuID TLS integration with given configuration
pub async fn initialize_quid_tls(config: QuIDTLSConfig) -> QuIDTLSResult<()> {
    tracing::info!("Initializing QuID TLS integration");
    
    // Validate configuration
    config.validate()?;
    
    // Initialize certificate directories if they don't exist
    if let Some(cert_dir) = &config.pki.certificate_directory {
        std::fs::create_dir_all(cert_dir)
            .map_err(|e| QuIDTLSError::ConfigurationError(format!("Failed to create certificate directory: {}", e)))?;
    }
    
    if let Some(ca_dir) = &config.pki.ca_directory {
        std::fs::create_dir_all(ca_dir)
            .map_err(|e| QuIDTLSError::ConfigurationError(format!("Failed to create CA directory: {}", e)))?;
    }
    
    tracing::info!("QuID TLS integration initialized successfully");
    Ok(())
}

/// Get the default QuID TLS configuration directory
pub fn get_default_config_dir() -> std::path::PathBuf {
    if let Some(home) = dirs::home_dir() {
        home.join(".quid").join("tls")
    } else {
        std::path::PathBuf::from("/etc/quid/tls")
    }
}

/// Get the default certificate directory for QuID TLS
pub fn get_default_cert_dir() -> std::path::PathBuf {
    if let Some(home) = dirs::home_dir() {
        home.join(".quid").join("tls").join("certs")
    } else {
        std::path::PathBuf::from("/var/lib/quid/tls/certs")
    }
}

/// Convert a QuID identity to an X.509 certificate with ML-DSA signature
pub async fn identity_to_x509_cert(
    quid_client: &QuIDClient,
    identity: &QuIDIdentity,
    subject: &str,
    options: CertificateOptions,
) -> QuIDTLSResult<X509Certificate> {
    let cert_builder = X509CertificateBuilder::new(quid_client, identity);
    cert_builder.build_certificate(subject, options).await
}

/// Verify an X.509 certificate signed with QuID ML-DSA
pub async fn verify_x509_cert(
    quid_client: &QuIDClient,
    certificate: &X509Certificate,
    ca_identity: &QuIDIdentity,
) -> QuIDTLSResult<bool> {
    certificate.verify_signature(quid_client, ca_identity).await
}

/// Create a new Certificate Authority using QuID
pub async fn create_ca(
    quid_client: &QuIDClient,
    ca_identity: &QuIDIdentity,
    ca_subject: &str,
    validity_days: u32,
) -> QuIDTLSResult<CertificateAuthority> {
    CertificateAuthority::new(quid_client, ca_identity, ca_subject, validity_days).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_default_directories() {
        let config_dir = get_default_config_dir();
        assert!(config_dir.to_string_lossy().contains("quid"));
        assert!(config_dir.to_string_lossy().contains("tls"));

        let cert_dir = get_default_cert_dir();
        assert!(cert_dir.to_string_lossy().contains("quid"));
        assert!(cert_dir.to_string_lossy().contains("tls"));
        assert!(cert_dir.to_string_lossy().contains("certs"));
    }

    #[tokio::test]
    async fn test_initialize_quid_tls() {
        let temp_dir = TempDir::new().unwrap();
        let config = QuIDTLSConfig {
            pki: PKIConfig {
                certificate_directory: Some(temp_dir.path().join("certs")),
                ca_directory: Some(temp_dir.path().join("ca")),
                ..Default::default()
            },
            ..Default::default()
        };

        let result = initialize_quid_tls(config).await;
        assert!(result.is_ok());
        assert!(temp_dir.path().join("certs").exists());
        assert!(temp_dir.path().join("ca").exists());
    }
}