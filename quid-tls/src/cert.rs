//! QuID certificate management and generation
//!
//! This module provides high-level certificate generation and management functionality
//! using QuID identities with quantum-resistant signatures.

use anyhow::Result;
use chrono::{DateTime, Utc, Duration};
use quid_core::{QuIDClient, QuIDIdentity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use crate::x509::{X509Certificate, X509CertificateBuilder, CertificateFormat};
use crate::{QuIDTLSError, QuIDTLSResult};

/// Certificate generation options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateOptions {
    /// Certificate issuer (CA) name
    pub issuer: String,
    /// Certificate validity duration
    pub validity_duration: Duration,
    /// Whether this is a CA certificate
    pub is_ca: bool,
    /// Path length constraint for CA certificates
    pub path_length: Option<u8>,
    /// Key usage flags
    pub key_usage: KeyUsage,
    /// Extended key usage flags
    pub extended_key_usage: ExtendedKeyUsage,
    /// Subject alternative names
    pub subject_alt_names: SubjectAlternativeNames,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl Default for CertificateOptions {
    fn default() -> Self {
        Self {
            issuer: "QuID Certificate Authority".to_string(),
            validity_duration: Duration::days(365),
            is_ca: false,
            path_length: None,
            key_usage: KeyUsage::default(),
            extended_key_usage: ExtendedKeyUsage::default(),
            subject_alt_names: SubjectAlternativeNames::default(),
            metadata: HashMap::new(),
        }
    }
}

impl CertificateOptions {
    /// Create options for a server certificate
    pub fn server_cert(dns_names: Vec<String>, validity_days: u32) -> Self {
        Self {
            validity_duration: Duration::days(validity_days as i64),
            key_usage: KeyUsage {
                digital_signature: true,
                key_encipherment: true,
                ..Default::default()
            },
            extended_key_usage: ExtendedKeyUsage {
                server_auth: true,
                ..Default::default()
            },
            subject_alt_names: SubjectAlternativeNames {
                dns_names,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Create options for a client certificate
    pub fn client_cert(validity_days: u32) -> Self {
        Self {
            validity_duration: Duration::days(validity_days as i64),
            key_usage: KeyUsage {
                digital_signature: true,
                key_agreement: true,
                ..Default::default()
            },
            extended_key_usage: ExtendedKeyUsage {
                client_auth: true,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Create options for a CA certificate
    pub fn ca_cert(validity_days: u32, path_length: Option<u8>) -> Self {
        Self {
            validity_duration: Duration::days(validity_days as i64),
            is_ca: true,
            path_length,
            key_usage: KeyUsage {
                key_cert_sign: true,
                crl_sign: true,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Create options for a code signing certificate
    pub fn code_signing_cert(validity_days: u32) -> Self {
        Self {
            validity_duration: Duration::days(validity_days as i64),
            key_usage: KeyUsage {
                digital_signature: true,
                ..Default::default()
            },
            extended_key_usage: ExtendedKeyUsage {
                code_signing: true,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Add DNS name to subject alternative names
    pub fn add_dns_name(mut self, dns_name: &str) -> Self {
        self.subject_alt_names.dns_names.push(dns_name.to_string());
        self
    }

    /// Add IP address to subject alternative names
    pub fn add_ip_address(mut self, ip: IpAddr) -> Self {
        self.subject_alt_names.ip_addresses.push(ip);
        self
    }

    /// Add email address to subject alternative names
    pub fn add_email(mut self, email: &str) -> Self {
        self.subject_alt_names.email_addresses.push(email.to_string());
        self
    }

    /// Set issuer name
    pub fn with_issuer(mut self, issuer: &str) -> Self {
        self.issuer = issuer.to_string();
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }
}

/// Key usage extension flags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyUsage {
    pub digital_signature: bool,
    pub key_encipherment: bool,
    pub key_agreement: bool,
    pub key_cert_sign: bool,
    pub crl_sign: bool,
}

impl Default for KeyUsage {
    fn default() -> Self {
        Self {
            digital_signature: false,
            key_encipherment: false,
            key_agreement: false,
            key_cert_sign: false,
            crl_sign: false,
        }
    }
}

/// Extended key usage extension flags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedKeyUsage {
    pub server_auth: bool,
    pub client_auth: bool,
    pub code_signing: bool,
    pub email_protection: bool,
    pub time_stamping: bool,
}

impl Default for ExtendedKeyUsage {
    fn default() -> Self {
        Self {
            server_auth: false,
            client_auth: false,
            code_signing: false,
            email_protection: false,
            time_stamping: false,
        }
    }
}

/// Subject alternative names
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SubjectAlternativeNames {
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<IpAddr>,
    pub email_addresses: Vec<String>,
}

/// QuID certificate wrapper with additional functionality
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuIDCertificate {
    /// The underlying X.509 certificate
    pub x509: X509Certificate,
    /// Certificate chain (if any)
    pub chain: Vec<X509Certificate>,
    /// Private key reference (QuID identity)
    pub private_key_identity: QuIDIdentity,
    /// Creation metadata
    pub created_at: DateTime<Utc>,
    /// Certificate usage purpose
    pub purpose: CertificatePurpose,
}

/// Certificate purpose types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CertificatePurpose {
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    CertificateAuthority,
    TimeStamping,
}

impl QuIDCertificate {
    /// Create a new QuID certificate
    pub fn new(
        x509: X509Certificate,
        private_key_identity: QuIDIdentity,
        purpose: CertificatePurpose,
    ) -> Self {
        Self {
            x509,
            chain: Vec::new(),
            private_key_identity,
            created_at: Utc::now(),
            purpose,
        }
    }

    /// Add certificate to chain
    pub fn add_to_chain(mut self, cert: X509Certificate) -> Self {
        self.chain.push(cert);
        self
    }

    /// Verify the certificate chain
    pub async fn verify_chain(&self, quid_client: &QuIDClient, trusted_roots: &[QuIDIdentity]) -> QuIDTLSResult<bool> {
        // Start with the certificate itself
        let mut current_cert = &self.x509;
        
        // Verify each certificate in the chain
        for next_cert in &self.chain {
            // Verify current certificate was signed by next certificate
            let signer_identity = &next_cert.signer_identity;
            if !current_cert.verify_signature(quid_client, signer_identity).await? {
                return Ok(false);
            }
            current_cert = next_cert;
        }
        
        // Verify the root certificate against trusted roots
        let root_signer = &current_cert.signer_identity;
        let is_trusted = trusted_roots.iter().any(|root| root.id == root_signer.id);
        
        Ok(is_trusted)
    }

    /// Check if certificate is valid for TLS server authentication
    pub fn is_valid_for_server_auth(&self, hostname: &str) -> bool {
        if self.purpose != CertificatePurpose::ServerAuth {
            return false;
        }

        if !self.x509.validity.is_valid() {
            return false;
        }

        // Check if hostname matches certificate
        self.matches_hostname(hostname)
    }

    /// Check if certificate is valid for TLS client authentication
    pub fn is_valid_for_client_auth(&self) -> bool {
        self.purpose == CertificatePurpose::ClientAuth && self.x509.validity.is_valid()
    }

    /// Check if hostname matches certificate
    fn matches_hostname(&self, hostname: &str) -> bool {
        // Check subject CN (simplified)
        if self.x509.subject.contains(&format!("CN={}", hostname)) {
            return true;
        }

        // Check Subject Alternative Names
        for ext in &self.x509.extensions {
            if let crate::x509::X509Extension::SubjectAltName { dns_names, .. } = ext {
                for dns_name in dns_names {
                    if dns_name == hostname || self.matches_wildcard(dns_name, hostname) {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Check wildcard DNS name matching
    fn matches_wildcard(&self, pattern: &str, hostname: &str) -> bool {
        if pattern.starts_with("*.") {
            let suffix = &pattern[2..];
            hostname.ends_with(suffix) && hostname.len() > suffix.len()
        } else {
            pattern == hostname
        }
    }

    /// Export certificate to file
    pub fn export_to_file(&self, path: &Path, format: CertificateFormat, include_chain: bool) -> QuIDTLSResult<()> {
        match format {
            CertificateFormat::PEM => {
                let mut pem_data = self.x509.to_pem()?;
                
                if include_chain {
                    for cert in &self.chain {
                        pem_data.push_str(&cert.to_pem()?);
                    }
                }
                
                std::fs::write(path, pem_data)?;
            }
            CertificateFormat::DER => {
                if include_chain && !self.chain.is_empty() {
                    return Err(QuIDTLSError::EncodingError(
                        "DER format does not support certificate chains".to_string()
                    ));
                }
                
                let der_data = self.x509.to_der()?;
                std::fs::write(path, der_data)?;
            }
        }

        Ok(())
    }

    /// Get certificate fingerprint
    pub fn fingerprint(&self) -> QuIDTLSResult<String> {
        self.x509.fingerprint()
    }

    /// Get certificate summary information
    pub fn summary(&self) -> CertificateSummary {
        CertificateSummary {
            subject: self.x509.subject.clone(),
            issuer: self.x509.issuer.clone(),
            serial_number: hex::encode(&self.x509.serial_number),
            not_before: self.x509.validity.not_before,
            not_after: self.x509.validity.not_after,
            is_valid: self.x509.validity.is_valid(),
            purpose: self.purpose.clone(),
            signature_algorithm: self.x509.signature_algorithm.name().to_string(),
            key_size: self.get_key_size(),
        }
    }

    /// Get key size based on algorithm
    fn get_key_size(&self) -> u32 {
        match self.x509.signature_algorithm {
            crate::x509::MLDSAAlgorithm::MLDSA44 => 1312,  // ML-DSA-44 public key size
            crate::x509::MLDSAAlgorithm::MLDSA65 => 1952,  // ML-DSA-65 public key size
            crate::x509::MLDSAAlgorithm::MLDSA87 => 2592,  // ML-DSA-87 public key size
        }
    }
}

/// Certificate summary information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateSummary {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub is_valid: bool,
    pub purpose: CertificatePurpose,
    pub signature_algorithm: String,
    pub key_size: u32,
}

/// Certificate builder for QuID certificates
pub struct CertificateBuilder<'a> {
    quid_client: &'a QuIDClient,
    identity: &'a QuIDIdentity,
    options: CertificateOptions,
}

impl<'a> CertificateBuilder<'a> {
    /// Create a new certificate builder
    pub fn new(quid_client: &'a QuIDClient, identity: &'a QuIDIdentity) -> Self {
        Self {
            quid_client,
            identity,
            options: CertificateOptions::default(),
        }
    }

    /// Set certificate options
    pub fn with_options(mut self, options: CertificateOptions) -> Self {
        self.options = options;
        self
    }

    /// Build a server certificate
    pub fn server_cert(mut self, dns_names: Vec<String>, validity_days: u32) -> Self {
        self.options = CertificateOptions::server_cert(dns_names, validity_days);
        self
    }

    /// Build a client certificate
    pub fn client_cert(mut self, validity_days: u32) -> Self {
        self.options = CertificateOptions::client_cert(validity_days);
        self
    }

    /// Build a CA certificate
    pub fn ca_cert(mut self, validity_days: u32, path_length: Option<u8>) -> Self {
        self.options = CertificateOptions::ca_cert(validity_days, path_length);
        self
    }

    /// Generate the certificate
    pub async fn build(self, subject: &str) -> QuIDTLSResult<QuIDCertificate> {
        let x509_builder = X509CertificateBuilder::new(self.quid_client, self.identity);
        let x509_cert = x509_builder.build_certificate(subject, self.options.clone()).await?;

        let purpose = if self.options.is_ca {
            CertificatePurpose::CertificateAuthority
        } else if self.options.extended_key_usage.server_auth {
            CertificatePurpose::ServerAuth
        } else if self.options.extended_key_usage.client_auth {
            CertificatePurpose::ClientAuth
        } else if self.options.extended_key_usage.code_signing {
            CertificatePurpose::CodeSigning
        } else if self.options.extended_key_usage.email_protection {
            CertificatePurpose::EmailProtection
        } else if self.options.extended_key_usage.time_stamping {
            CertificatePurpose::TimeStamping
        } else {
            CertificatePurpose::ClientAuth // Default
        };

        Ok(QuIDCertificate::new(x509_cert, self.identity.clone(), purpose))
    }
}

/// Certificate store for managing QuID certificates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateStore {
    /// Stored certificates
    pub certificates: HashMap<String, QuIDCertificate>,
    /// Trusted root certificates
    pub trusted_roots: Vec<QuIDIdentity>,
    /// Store metadata
    pub metadata: HashMap<String, String>,
}

impl CertificateStore {
    /// Create a new certificate store
    pub fn new() -> Self {
        Self {
            certificates: HashMap::new(),
            trusted_roots: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Add certificate to store
    pub fn add_certificate(&mut self, alias: String, certificate: QuIDCertificate) {
        self.certificates.insert(alias, certificate);
    }

    /// Get certificate by alias
    pub fn get_certificate(&self, alias: &str) -> Option<&QuIDCertificate> {
        self.certificates.get(alias)
    }

    /// Remove certificate by alias
    pub fn remove_certificate(&mut self, alias: &str) -> Option<QuIDCertificate> {
        self.certificates.remove(alias)
    }

    /// List all certificate aliases
    pub fn list_certificates(&self) -> Vec<String> {
        self.certificates.keys().cloned().collect()
    }

    /// Add trusted root identity
    pub fn add_trusted_root(&mut self, root_identity: QuIDIdentity) {
        self.trusted_roots.push(root_identity);
    }

    /// Find certificates by purpose
    pub fn find_by_purpose(&self, purpose: CertificatePurpose) -> Vec<(&String, &QuIDCertificate)> {
        self.certificates
            .iter()
            .filter(|(_, cert)| cert.purpose == purpose)
            .collect()
    }

    /// Find valid certificates for hostname
    pub fn find_for_hostname(&self, hostname: &str) -> Vec<(&String, &QuIDCertificate)> {
        self.certificates
            .iter()
            .filter(|(_, cert)| cert.is_valid_for_server_auth(hostname))
            .collect()
    }

    /// Save store to file
    pub fn save_to_file(&self, path: &Path) -> QuIDTLSResult<()> {
        let json_data = serde_json::to_string_pretty(self)
            .map_err(|e| QuIDTLSError::EncodingError(format!("Failed to serialize store: {}", e)))?;
        
        std::fs::write(path, json_data)?;

        // Set secure permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }

    /// Load store from file
    pub fn load_from_file(path: &Path) -> QuIDTLSResult<Self> {
        let json_data = std::fs::read_to_string(path)?;
        let store: CertificateStore = serde_json::from_str(&json_data)
            .map_err(|e| QuIDTLSError::EncodingError(format!("Failed to deserialize store: {}", e)))?;
        
        Ok(store)
    }
}

impl Default for CertificateStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_certificate_options() {
        let server_opts = CertificateOptions::server_cert(
            vec!["example.com".to_string(), "www.example.com".to_string()],
            365
        );
        
        assert!(server_opts.extended_key_usage.server_auth);
        assert!(!server_opts.extended_key_usage.client_auth);
        assert!(server_opts.key_usage.digital_signature);
        assert!(server_opts.key_usage.key_encipherment);
        assert_eq!(server_opts.subject_alt_names.dns_names.len(), 2);

        let client_opts = CertificateOptions::client_cert(30);
        assert!(!client_opts.extended_key_usage.server_auth);
        assert!(client_opts.extended_key_usage.client_auth);
        assert!(client_opts.key_usage.digital_signature);
        assert!(client_opts.key_usage.key_agreement);

        let ca_opts = CertificateOptions::ca_cert(3650, Some(3));
        assert!(ca_opts.is_ca);
        assert_eq!(ca_opts.path_length, Some(3));
        assert!(ca_opts.key_usage.key_cert_sign);
        assert!(ca_opts.key_usage.crl_sign);
    }

    #[test]
    fn test_certificate_options_builder() {
        let opts = CertificateOptions::default()
            .add_dns_name("test.example.com")
            .add_ip_address(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
            .add_email("admin@example.com")
            .with_issuer("Test CA")
            .with_metadata("environment", "testing");

        assert_eq!(opts.subject_alt_names.dns_names.len(), 1);
        assert_eq!(opts.subject_alt_names.ip_addresses.len(), 1);
        assert_eq!(opts.subject_alt_names.email_addresses.len(), 1);
        assert_eq!(opts.issuer, "Test CA");
        assert_eq!(opts.metadata.get("environment"), Some(&"testing".to_string()));
    }

    #[test]
    fn test_certificate_store() {
        let mut store = CertificateStore::new();
        
        // Test empty store
        assert_eq!(store.list_certificates().len(), 0);
        assert!(store.get_certificate("test").is_none());
        
        // Test adding certificates would require actual QuID certificates
        // which need a running QuID client, so we'll skip that for unit tests
    }

    #[test]
    fn test_wildcard_matching() {
        // This would test the wildcard matching logic
        // For now, we'll create a minimal test structure
        let cert = QuIDCertificate {
            x509: create_dummy_x509_cert(),
            chain: Vec::new(),
            private_key_identity: create_dummy_identity(),
            created_at: Utc::now(),
            purpose: CertificatePurpose::ServerAuth,
        };

        // These tests would require proper X.509 certificate creation
        // which is complex for unit tests
    }

    // Helper functions for tests
    fn create_dummy_x509_cert() -> X509Certificate {
        use crate::x509::*;
        X509Certificate::new(
            vec![1, 2, 3, 4],
            MLDSAAlgorithm::MLDSA44,
            "CN=Test CA".to_string(),
            CertificateValidity::from_duration(Duration::days(30)),
            "CN=test.example.com".to_string(),
            vec![0; 32],
            Vec::new(),
            MLDSASignature::new(MLDSAAlgorithm::MLDSA44, vec![0; 64], vec![0; 32]),
            create_dummy_identity(),
        )
    }

    fn create_dummy_identity() -> QuIDIdentity {
        QuIDIdentity {
            id: "test-identity-123".to_string(),
            name: "test".to_string(),
            security_level: quid_core::SecurityLevel::Level1,
            created_at: Utc::now(),
            contexts: vec!["test".to_string()],
            metadata: None,
        }
    }
}