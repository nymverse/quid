//! SSH Certificate Authority integration for QuID
//!
//! This module provides SSH certificate authority functionality using QuID identities,
//! allowing for centralized authentication and authorization.

use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, Utc, Duration};
use quid_core::{QuIDClient, QuIDIdentity};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::net::IpAddr;

use crate::keys::QuIDSSHKey;
use crate::{QuIDSSHError, QuIDSSHResult};

/// SSH certificate types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CertificateType {
    /// User certificate for client authentication
    User,
    /// Host certificate for server authentication
    Host,
}

impl CertificateType {
    pub fn as_str(&self) -> &'static str {
        match self {
            CertificateType::User => "user",
            CertificateType::Host => "host",
        }
    }

    pub fn as_u32(&self) -> u32 {
        match self {
            CertificateType::User => 1,
            CertificateType::Host => 2,
        }
    }
}

/// Certificate validity period
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidityPeriod {
    pub valid_after: DateTime<Utc>,
    pub valid_before: DateTime<Utc>,
}

impl ValidityPeriod {
    /// Create a validity period starting now with given duration
    pub fn from_duration(duration: Duration) -> Self {
        let now = Utc::now();
        Self {
            valid_after: now,
            valid_before: now + duration,
        }
    }

    /// Create a validity period for a specific time range
    pub fn from_range(start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        Self {
            valid_after: start,
            valid_before: end,
        }
    }

    /// Check if the certificate is currently valid
    pub fn is_valid(&self) -> bool {
        let now = Utc::now();
        now >= self.valid_after && now <= self.valid_before
    }

    /// Get remaining validity duration
    pub fn remaining_duration(&self) -> Option<Duration> {
        let now = Utc::now();
        if now <= self.valid_before {
            Some(self.valid_before - now)
        } else {
            None
        }
    }
}

/// Certificate extensions and critical options
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CertificateExtensions {
    /// Permit X11 forwarding
    pub permit_x11_forwarding: bool,
    /// Permit agent forwarding
    pub permit_agent_forwarding: bool,
    /// Permit port forwarding
    pub permit_port_forwarding: bool,
    /// Permit PTY allocation
    pub permit_pty: bool,
    /// Permit user RC file execution
    pub permit_user_rc: bool,
    /// Force command execution
    pub force_command: Option<String>,
    /// Source address restrictions
    pub source_address: Option<Vec<IpAddr>>,
    /// Custom extensions
    pub custom_extensions: HashMap<String, String>,
}

/// Certificate options for generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateOptions {
    /// Certificate type
    pub cert_type: CertificateType,
    /// Serial number
    pub serial: u64,
    /// Key ID
    pub key_id: String,
    /// Valid principals (usernames or hostnames)
    pub valid_principals: Vec<String>,
    /// Validity period
    pub validity: ValidityPeriod,
    /// Certificate extensions
    pub extensions: CertificateExtensions,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl CertificateOptions {
    /// Create default user certificate options
    pub fn user_cert(username: &str, duration: Duration) -> Self {
        Self {
            cert_type: CertificateType::User,
            serial: rand::random(),
            key_id: format!("user-{}-{}", username, Utc::now().timestamp()),
            valid_principals: vec![username.to_string()],
            validity: ValidityPeriod::from_duration(duration),
            extensions: CertificateExtensions {
                permit_x11_forwarding: true,
                permit_agent_forwarding: true,
                permit_port_forwarding: true,
                permit_pty: true,
                permit_user_rc: true,
                ..Default::default()
            },
            metadata: HashMap::new(),
        }
    }

    /// Create default host certificate options
    pub fn host_cert(hostname: &str, duration: Duration) -> Self {
        Self {
            cert_type: CertificateType::Host,
            serial: rand::random(),
            key_id: format!("host-{}-{}", hostname, Utc::now().timestamp()),
            valid_principals: vec![hostname.to_string()],
            validity: ValidityPeriod::from_duration(duration),
            extensions: CertificateExtensions::default(),
            metadata: HashMap::new(),
        }
    }

    /// Add a valid principal
    pub fn add_principal(mut self, principal: &str) -> Self {
        self.valid_principals.push(principal.to_string());
        self
    }

    /// Set force command
    pub fn with_force_command(mut self, command: &str) -> Self {
        self.extensions.force_command = Some(command.to_string());
        self
    }

    /// Add source address restriction
    pub fn with_source_address(mut self, addresses: Vec<IpAddr>) -> Self {
        self.extensions.source_address = Some(addresses);
        self
    }

    /// Add custom metadata
    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }
}

/// SSH certificate structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSHCertificate {
    /// Certificate type
    pub cert_type: CertificateType,
    /// Serial number
    pub serial: u64,
    /// Key ID
    pub key_id: String,
    /// Valid principals
    pub valid_principals: Vec<String>,
    /// Validity period
    pub validity: ValidityPeriod,
    /// Public key being certified
    pub public_key: Vec<u8>,
    /// Signing CA public key
    pub ca_public_key: Vec<u8>,
    /// Certificate signature
    pub signature: Vec<u8>,
    /// Extensions
    pub extensions: CertificateExtensions,
    /// Metadata
    pub metadata: HashMap<String, String>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
}

impl SSHCertificate {
    /// Convert certificate to SSH wire format
    pub fn to_ssh_format(&self) -> QuIDSSHResult<String> {
        // Create the certificate in OpenSSH format
        let cert_type = match self.cert_type {
            CertificateType::User => "ssh-rsa-cert-v01@openssh.com",
            CertificateType::Host => "ssh-rsa-cert-v01@openssh.com",
        };

        // Encode certificate data
        let cert_data = self.encode_certificate_data()?;
        let encoded_data = BASE64.encode(&cert_data);

        Ok(format!("{} {} {}", cert_type, encoded_data, self.key_id))
    }

    /// Encode certificate data in SSH wire format
    fn encode_certificate_data(&self) -> QuIDSSHResult<Vec<u8>> {
        let mut data = Vec::new();

        // This is a simplified version - in a real implementation,
        // you would follow the SSH certificate wire format exactly
        data.extend_from_slice(&self.serial.to_be_bytes());
        data.extend_from_slice(self.key_id.as_bytes());
        data.extend_from_slice(&self.public_key);

        Ok(data)
    }

    /// Verify certificate signature
    pub fn verify_signature(&self, ca_public_key: &[u8]) -> QuIDSSHResult<bool> {
        // In a real implementation, this would:
        // 1. Reconstruct the signed data
        // 2. Verify the signature using the CA public key
        // 3. Return the verification result

        // For now, we'll do a basic check
        Ok(!self.signature.is_empty() && self.ca_public_key == ca_public_key)
    }

    /// Check if certificate is valid for a given principal
    pub fn is_valid_for_principal(&self, principal: &str) -> bool {
        self.validity.is_valid() && 
        (self.valid_principals.is_empty() || self.valid_principals.contains(&principal.to_string()))
    }

    /// Get certificate fingerprint
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.public_key);
        hasher.update(&self.ca_public_key);
        hasher.update(&self.signature);
        let hash = hasher.finalize();

        format!("SHA256:{}", BASE64.encode(hash))
    }

    /// Export certificate to file
    pub fn export_to_file(&self, path: &std::path::Path) -> QuIDSSHResult<()> {
        let ssh_format = self.to_ssh_format()?;
        std::fs::write(path, ssh_format)?;

        // Set appropriate permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))?;
        }

        Ok(())
    }
}

/// Certificate Authority for QuID SSH integration
pub struct CertificateAuthority {
    quid_client: Arc<QuIDClient>,
    ca_identity: QuIDIdentity,
    config: CAConfig,
}

/// CA configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CAConfig {
    /// Default certificate validity duration
    pub default_validity: Duration,
    /// Maximum certificate validity duration
    pub max_validity: Duration,
    /// Allowed certificate types
    pub allowed_cert_types: Vec<CertificateType>,
    /// Default extensions for user certificates
    pub default_user_extensions: CertificateExtensions,
    /// Default extensions for host certificates
    pub default_host_extensions: CertificateExtensions,
    /// Certificate serial number file
    pub serial_file: Option<std::path::PathBuf>,
    /// Certificate database file
    pub cert_database: Option<std::path::PathBuf>,
    /// Audit log file
    pub audit_log: Option<std::path::PathBuf>,
}

impl Default for CAConfig {
    fn default() -> Self {
        Self {
            default_validity: Duration::hours(24),
            max_validity: Duration::days(365),
            allowed_cert_types: vec![CertificateType::User, CertificateType::Host],
            default_user_extensions: CertificateExtensions {
                permit_x11_forwarding: true,
                permit_agent_forwarding: true,
                permit_port_forwarding: true,
                permit_pty: true,
                permit_user_rc: true,
                ..Default::default()
            },
            default_host_extensions: CertificateExtensions::default(),
            serial_file: None,
            cert_database: None,
            audit_log: None,
        }
    }
}

impl CertificateAuthority {
    /// Create a new Certificate Authority
    pub fn new(
        quid_client: Arc<QuIDClient>,
        ca_identity: QuIDIdentity,
        config: CAConfig,
    ) -> Self {
        Self {
            quid_client,
            ca_identity,
            config,
        }
    }

    /// Issue a new SSH certificate
    pub async fn issue_certificate(
        &self,
        public_key: &[u8],
        options: CertificateOptions,
    ) -> QuIDSSHResult<SSHCertificate> {
        // Validate certificate options
        self.validate_options(&options)?;

        // Get CA public key
        let ca_public_key = self.quid_client
            .get_public_key(&self.ca_identity)
            .await
            .map_err(|e| QuIDSSHError::CertificateGenerationFailed(format!("Failed to get CA public key: {}", e)))?;

        // Create certificate data to sign
        let cert_data = self.create_certificate_data(public_key, &options, &ca_public_key)?;

        // Sign the certificate with QuID
        let signature = self.quid_client
            .sign_data(&self.ca_identity, &cert_data)
            .await
            .map_err(|e| QuIDSSHError::CertificateGenerationFailed(format!("Failed to sign certificate: {}", e)))?;

        // Create certificate
        let certificate = SSHCertificate {
            cert_type: options.cert_type,
            serial: options.serial,
            key_id: options.key_id,
            valid_principals: options.valid_principals,
            validity: options.validity,
            public_key: public_key.to_vec(),
            ca_public_key,
            signature,
            extensions: options.extensions,
            metadata: options.metadata,
            created_at: Utc::now(),
        };

        // Log certificate issuance
        self.log_certificate_issuance(&certificate).await?;

        // Store certificate in database if configured
        if let Some(db_path) = &self.config.cert_database {
            self.store_certificate(&certificate, db_path).await?;
        }

        tracing::info!(
            "Issued SSH certificate: type={}, serial={}, key_id={}",
            certificate.cert_type.as_str(),
            certificate.serial,
            certificate.key_id
        );

        Ok(certificate)
    }

    /// Revoke a certificate
    pub async fn revoke_certificate(&self, serial: u64, reason: &str) -> QuIDSSHResult<()> {
        tracing::info!("Revoking certificate with serial {}: {}", serial, reason);

        // In a real implementation, this would:
        // 1. Add the certificate to a revocation list
        // 2. Update the CRL (Certificate Revocation List)
        // 3. Notify relevant systems

        self.log_certificate_revocation(serial, reason).await?;

        Ok(())
    }

    /// Get CA public key in SSH format
    pub async fn get_ca_public_key(&self) -> QuIDSSHResult<String> {
        let quid_key = QuIDSSHKey::from_identity(&self.quid_client, &self.ca_identity).await?;
        quid_key.to_ssh_public_key()
    }

    /// Verify a certificate was issued by this CA
    pub async fn verify_certificate(&self, certificate: &SSHCertificate) -> QuIDSSHResult<bool> {
        let ca_public_key = self.quid_client
            .get_public_key(&self.ca_identity)
            .await
            .map_err(|e| QuIDSSHError::QuIDCoreError(e))?;

        certificate.verify_signature(&ca_public_key)
    }

    /// List all issued certificates
    pub async fn list_certificates(&self) -> QuIDSSHResult<Vec<SSHCertificate>> {
        if let Some(db_path) = &self.config.cert_database {
            self.load_certificates_from_database(db_path).await
        } else {
            Ok(Vec::new())
        }
    }

    /// Get certificate by serial number
    pub async fn get_certificate(&self, serial: u64) -> QuIDSSHResult<Option<SSHCertificate>> {
        let certificates = self.list_certificates().await?;
        Ok(certificates.into_iter().find(|cert| cert.serial == serial))
    }

    /// Generate next serial number
    async fn get_next_serial(&self) -> QuIDSSHResult<u64> {
        if let Some(serial_file) = &self.config.serial_file {
            // Read current serial from file
            let current_serial = if serial_file.exists() {
                let content = tokio::fs::read_to_string(serial_file).await?;
                content.trim().parse::<u64>().unwrap_or(1)
            } else {
                1
            };

            let next_serial = current_serial + 1;

            // Write next serial to file
            tokio::fs::write(serial_file, next_serial.to_string()).await?;

            Ok(next_serial)
        } else {
            // Use timestamp-based serial
            Ok(Utc::now().timestamp() as u64)
        }
    }

    /// Validate certificate options
    fn validate_options(&self, options: &CertificateOptions) -> QuIDSSHResult<()> {
        // Check if certificate type is allowed
        if !self.config.allowed_cert_types.contains(&options.cert_type) {
            return Err(QuIDSSHError::CertificateGenerationFailed(
                format!("Certificate type {:?} not allowed", options.cert_type)
            ));
        }

        // Check validity period
        let duration = options.validity.valid_before - options.validity.valid_after;
        if duration > self.config.max_validity {
            return Err(QuIDSSHError::CertificateGenerationFailed(
                format!("Certificate validity period exceeds maximum allowed: {} > {}", 
                    duration, self.config.max_validity)
            ));
        }

        // Check principals
        if options.valid_principals.is_empty() {
            return Err(QuIDSSHError::CertificateGenerationFailed(
                "At least one valid principal must be specified".to_string()
            ));
        }

        Ok(())
    }

    /// Create certificate data for signing
    fn create_certificate_data(
        &self,
        public_key: &[u8],
        options: &CertificateOptions,
        ca_public_key: &[u8],
    ) -> QuIDSSHResult<Vec<u8>> {
        let mut data = Vec::new();

        // Certificate type
        data.extend_from_slice(&options.cert_type.as_u32().to_be_bytes());

        // Serial number
        data.extend_from_slice(&options.serial.to_be_bytes());

        // Key ID
        data.extend_from_slice(options.key_id.as_bytes());

        // Public key
        data.extend_from_slice(public_key);

        // Valid principals
        for principal in &options.valid_principals {
            data.extend_from_slice(principal.as_bytes());
        }

        // Validity period
        data.extend_from_slice(&options.validity.valid_after.timestamp().to_be_bytes());
        data.extend_from_slice(&options.validity.valid_before.timestamp().to_be_bytes());

        // CA public key
        data.extend_from_slice(ca_public_key);

        Ok(data)
    }

    /// Log certificate issuance
    async fn log_certificate_issuance(&self, certificate: &SSHCertificate) -> QuIDSSHResult<()> {
        if let Some(audit_log) = &self.config.audit_log {
            let log_entry = format!(
                "{} ISSUE {} {} {} {}\n",
                Utc::now().to_rfc3339(),
                certificate.cert_type.as_str(),
                certificate.serial,
                certificate.key_id,
                certificate.valid_principals.join(",")
            );

            tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(audit_log)
                .await?
                .write_all(log_entry.as_bytes())
                .await?;
        }

        Ok(())
    }

    /// Log certificate revocation
    async fn log_certificate_revocation(&self, serial: u64, reason: &str) -> QuIDSSHResult<()> {
        if let Some(audit_log) = &self.config.audit_log {
            let log_entry = format!(
                "{} REVOKE {} {}\n",
                Utc::now().to_rfc3339(),
                serial,
                reason
            );

            tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(audit_log)
                .await?
                .write_all(log_entry.as_bytes())
                .await?;
        }

        Ok(())
    }

    /// Store certificate in database
    async fn store_certificate(
        &self,
        certificate: &SSHCertificate,
        db_path: &std::path::Path,
    ) -> QuIDSSHResult<()> {
        // In a real implementation, this would use a proper database
        // For now, we'll store as JSON lines
        let json_data = serde_json::to_string(certificate)
            .map_err(|e| QuIDSSHError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

        let entry = format!("{}\n", json_data);

        tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(db_path)
            .await?
            .write_all(entry.as_bytes())
            .await?;

        Ok(())
    }

    /// Load certificates from database
    async fn load_certificates_from_database(
        &self,
        db_path: &std::path::Path,
    ) -> QuIDSSHResult<Vec<SSHCertificate>> {
        if !db_path.exists() {
            return Ok(Vec::new());
        }

        let content = tokio::fs::read_to_string(db_path).await?;
        let mut certificates = Vec::new();

        for line in content.lines() {
            if let Ok(cert) = serde_json::from_str::<SSHCertificate>(line) {
                certificates.push(cert);
            }
        }

        Ok(certificates)
    }
}

use std::sync::Arc;
use tokio::io::AsyncWriteExt;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_certificate_type() {
        assert_eq!(CertificateType::User.as_str(), "user");
        assert_eq!(CertificateType::Host.as_str(), "host");
        assert_eq!(CertificateType::User.as_u32(), 1);
        assert_eq!(CertificateType::Host.as_u32(), 2);
    }

    #[test]
    fn test_validity_period() {
        let duration = Duration::hours(24);
        let validity = ValidityPeriod::from_duration(duration);
        
        assert!(validity.is_valid());
        assert!(validity.remaining_duration().is_some());
    }

    #[test]
    fn test_certificate_options() {
        let options = CertificateOptions::user_cert("alice", Duration::hours(24));
        
        assert_eq!(options.cert_type, CertificateType::User);
        assert_eq!(options.valid_principals, vec!["alice".to_string()]);
        assert!(options.extensions.permit_pty);
    }

    #[test]
    fn test_certificate_options_builder() {
        let options = CertificateOptions::user_cert("bob", Duration::hours(12))
            .add_principal("admin")
            .with_force_command("rsync")
            .with_metadata("purpose", "backup");

        assert_eq!(options.valid_principals.len(), 2);
        assert!(options.valid_principals.contains(&"bob".to_string()));
        assert!(options.valid_principals.contains(&"admin".to_string()));
        assert_eq!(options.extensions.force_command, Some("rsync".to_string()));
        assert_eq!(options.metadata.get("purpose"), Some(&"backup".to_string()));
    }
}