//! PKI management functionality for QuID

use chrono::{DateTime, Utc, Duration};
use quid_core::{QuIDClient, QuIDIdentity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use crate::{
    QuIDTLSError, QuIDTLSResult,
    cert::{QuIDCertificate, CertificateBuilder, CertificateOptions, CertificatePurpose},
    x509::X509Certificate,
};

/// PKI Manager for QuID certificates
pub struct PKIManager {
    quid_client: Arc<QuIDClient>,
    certificate_store: CertificateStore,
    ca_certificates: HashMap<String, CertificateAuthority>,
}

/// Certificate Authority implementation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateAuthority {
    /// CA identity
    pub identity: QuIDIdentity,
    /// CA certificate
    pub certificate: QuIDCertificate,
    /// CA configuration
    pub config: CAConfiguration,
    /// Certificate serial number counter
    pub next_serial: u64,
    /// Issued certificates
    pub issued_certificates: HashMap<String, QuIDCertificate>,
}

/// CA configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CAConfiguration {
    /// Default certificate validity period
    pub default_validity: Duration,
    /// Maximum certificate validity period
    pub max_validity: Duration,
    /// Certificate policies
    pub policies: Vec<CertificatePolicy>,
    /// Revocation checking
    pub check_revocation: bool,
}

/// Certificate policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificatePolicy {
    /// Policy OID
    pub oid: String,
    /// Policy name
    pub name: String,
    /// Policy description
    pub description: String,
}

/// Certificate chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateChain {
    /// End entity certificate
    pub end_entity: QuIDCertificate,
    /// Intermediate certificates
    pub intermediates: Vec<QuIDCertificate>,
    /// Root certificate
    pub root: QuIDCertificate,
}

/// Certificate store for PKI management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateStore {
    /// Stored certificates by alias
    pub certificates: HashMap<String, QuIDCertificate>,
    /// Certificate chains
    pub chains: HashMap<String, CertificateChain>,
    /// Trusted roots
    pub trusted_roots: Vec<QuIDIdentity>,
    /// Revoked certificates
    pub revoked_certificates: Vec<String>,
}

impl PKIManager {
    /// Create a new PKI manager
    pub fn new(quid_client: Arc<QuIDClient>) -> Self {
        Self {
            quid_client,
            certificate_store: CertificateStore::new(),
            ca_certificates: HashMap::new(),
        }
    }

    /// Create a new Certificate Authority
    pub async fn create_ca(
        &mut self,
        identity: &QuIDIdentity,
        subject: &str,
        validity_days: u32,
    ) -> QuIDTLSResult<String> {
        tracing::info!("Creating new CA with identity: {}", identity.name);

        let ca_options = CertificateOptions::ca_cert(validity_days, None)
            .with_issuer(subject); // Self-signed

        let ca_cert = CertificateBuilder::new(&self.quid_client, identity)
            .with_options(ca_options)
            .build(subject)
            .await?;

        let ca_config = CAConfiguration {
            default_validity: Duration::days(90),
            max_validity: Duration::days(validity_days as i64),
            policies: Vec::new(),
            check_revocation: true,
        };

        let ca = CertificateAuthority {
            identity: identity.clone(),
            certificate: ca_cert,
            config: ca_config,
            next_serial: 1,
            issued_certificates: HashMap::new(),
        };

        let ca_alias = format!("ca-{}", identity.name);
        self.ca_certificates.insert(ca_alias.clone(), ca);

        tracing::info!("CA created successfully: {}", ca_alias);
        Ok(ca_alias)
    }

    /// Issue a certificate using a CA
    pub async fn issue_certificate(
        &mut self,
        ca_alias: &str,
        subject_identity: &QuIDIdentity,
        subject: &str,
        options: CertificateOptions,
    ) -> QuIDTLSResult<String> {
        let ca = self.ca_certificates.get_mut(ca_alias)
            .ok_or_else(|| QuIDTLSError::PKIOperationFailed(format!("CA not found: {}", ca_alias)))?;

        tracing::info!("Issuing certificate for: {}", subject);

        // Validate request against CA policies
        self.validate_certificate_request(ca, &options)?;

        // Build certificate
        let certificate = CertificateBuilder::new(&self.quid_client, subject_identity)
            .with_options(options)
            .build(subject)
            .await?;

        // Generate certificate alias
        let cert_alias = format!("{}-{}", subject_identity.name, ca.next_serial);
        ca.next_serial += 1;

        // Store certificate
        ca.issued_certificates.insert(cert_alias.clone(), certificate.clone());
        self.certificate_store.certificates.insert(cert_alias.clone(), certificate);

        tracing::info!("Certificate issued successfully: {}", cert_alias);
        Ok(cert_alias)
    }

    /// Build certificate chain
    pub async fn build_chain(
        &self,
        cert_alias: &str,
        include_root: bool,
    ) -> QuIDTLSResult<CertificateChain> {
        let certificate = self.certificate_store.certificates.get(cert_alias)
            .ok_or_else(|| QuIDTLSError::PKIOperationFailed(format!("Certificate not found: {}", cert_alias)))?;

        // In a real implementation, this would traverse the certificate chain
        // For now, we'll create a simple chain
        let chain = CertificateChain {
            end_entity: certificate.clone(),
            intermediates: Vec::new(),
            root: certificate.clone(), // Placeholder
        };

        Ok(chain)
    }

    /// Verify certificate chain
    pub async fn verify_chain(
        &self,
        chain: &CertificateChain,
    ) -> QuIDTLSResult<bool> {
        // Verify end entity certificate
        let is_valid = chain.end_entity.verify_chain(
            &self.quid_client,
            &self.certificate_store.trusted_roots,
        ).await?;

        if !is_valid {
            return Ok(false);
        }

        // Check revocation status
        let cert_serial = hex::encode(&chain.end_entity.x509.serial_number);
        if self.certificate_store.revoked_certificates.contains(&cert_serial) {
            return Ok(false);
        }

        Ok(true)
    }

    /// Revoke certificate
    pub async fn revoke_certificate(
        &mut self,
        cert_alias: &str,
        reason: &str,
    ) -> QuIDTLSResult<()> {
        let certificate = self.certificate_store.certificates.get(cert_alias)
            .ok_or_else(|| QuIDTLSError::PKIOperationFailed(format!("Certificate not found: {}", cert_alias)))?;

        let cert_serial = hex::encode(&certificate.x509.serial_number);
        self.certificate_store.revoked_certificates.push(cert_serial);

        tracing::info!("Certificate revoked: {} (reason: {})", cert_alias, reason);
        Ok(())
    }

    /// List certificates
    pub fn list_certificates(&self) -> Vec<String> {
        self.certificate_store.certificates.keys().cloned().collect()
    }

    /// Get certificate
    pub fn get_certificate(&self, alias: &str) -> Option<&QuIDCertificate> {
        self.certificate_store.certificates.get(alias)
    }

    /// Save PKI state to file
    pub fn save_to_file(&self, path: &Path) -> QuIDTLSResult<()> {
        let pki_data = PKIData {
            certificate_store: self.certificate_store.clone(),
            ca_certificates: self.ca_certificates.clone(),
        };

        let json_data = serde_json::to_string_pretty(&pki_data)
            .map_err(|e| QuIDTLSError::EncodingError(format!("Failed to serialize PKI data: {}", e)))?;

        std::fs::write(path, json_data)?;
        Ok(())
    }

    /// Load PKI state from file
    pub fn load_from_file(&mut self, path: &Path) -> QuIDTLSResult<()> {
        let json_data = std::fs::read_to_string(path)?;
        let pki_data: PKIData = serde_json::from_str(&json_data)
            .map_err(|e| QuIDTLSError::EncodingError(format!("Failed to deserialize PKI data: {}", e)))?;

        self.certificate_store = pki_data.certificate_store;
        self.ca_certificates = pki_data.ca_certificates;

        Ok(())
    }

    /// Validate certificate request against CA policies
    fn validate_certificate_request(
        &self,
        ca: &CertificateAuthority,
        options: &CertificateOptions,
    ) -> QuIDTLSResult<()> {
        // Check validity period
        if options.validity_duration > ca.config.max_validity {
            return Err(QuIDTLSError::PKIOperationFailed(
                format!("Requested validity period exceeds CA maximum: {} > {}",
                    options.validity_duration, ca.config.max_validity)
            ));
        }

        // Additional policy checks would go here
        Ok(())
    }
}

impl CertificateAuthority {
    /// Create a new Certificate Authority
    pub async fn new(
        quid_client: &QuIDClient,
        identity: &QuIDIdentity,
        subject: &str,
        validity_days: u32,
    ) -> QuIDTLSResult<Self> {
        let ca_options = CertificateOptions::ca_cert(validity_days, None)
            .with_issuer(subject);

        let ca_cert = CertificateBuilder::new(quid_client, identity)
            .with_options(ca_options)
            .build(subject)
            .await?;

        let config = CAConfiguration {
            default_validity: Duration::days(90),
            max_validity: Duration::days(validity_days as i64),
            policies: Vec::new(),
            check_revocation: true,
        };

        Ok(Self {
            identity: identity.clone(),
            certificate: ca_cert,
            config,
            next_serial: 1,
            issued_certificates: HashMap::new(),
        })
    }

    /// Get CA certificate in PEM format
    pub fn get_ca_certificate_pem(&self) -> QuIDTLSResult<String> {
        self.certificate.x509.to_pem()
    }

    /// Get next serial number
    pub fn next_serial_number(&mut self) -> u64 {
        let serial = self.next_serial;
        self.next_serial += 1;
        serial
    }
}

impl CertificateStore {
    /// Create a new certificate store
    pub fn new() -> Self {
        Self {
            certificates: HashMap::new(),
            chains: HashMap::new(),
            trusted_roots: Vec::new(),
            revoked_certificates: Vec::new(),
        }
    }

    /// Add trusted root
    pub fn add_trusted_root(&mut self, root_identity: QuIDIdentity) {
        self.trusted_roots.push(root_identity);
    }

    /// Check if certificate is revoked
    pub fn is_revoked(&self, certificate: &QuIDCertificate) -> bool {
        let serial = hex::encode(&certificate.x509.serial_number);
        self.revoked_certificates.contains(&serial)
    }
}

impl Default for CertificateStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Serializable PKI data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PKIData {
    certificate_store: CertificateStore,
    ca_certificates: HashMap<String, CertificateAuthority>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_store() {
        let mut store = CertificateStore::new();
        
        let dummy_identity = QuIDIdentity {
            id: "test-root".to_string(),
            name: "test".to_string(),
            security_level: quid_core::SecurityLevel::Level1,
            created_at: Utc::now(),
            contexts: vec!["test".to_string()],
            metadata: None,
        };

        store.add_trusted_root(dummy_identity);
        assert_eq!(store.trusted_roots.len(), 1);
    }

    #[test]
    fn test_ca_configuration() {
        let config = CAConfiguration {
            default_validity: Duration::days(90),
            max_validity: Duration::days(365),
            policies: Vec::new(),
            check_revocation: true,
        };

        assert_eq!(config.default_validity, Duration::days(90));
        assert!(config.check_revocation);
    }
}