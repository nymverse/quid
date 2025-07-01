//! X.509 certificate implementation with ML-DSA quantum-resistant signatures
//!
//! This module provides X.509 certificate generation and validation using QuID identities
//! with ML-DSA (Dilithium) quantum-resistant signatures.

use anyhow::Result;
use chrono::{DateTime, Utc, Duration};
use quid_core::{QuIDClient, QuIDIdentity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

use crate::{QuIDTLSError, QuIDTLSResult};

/// ML-DSA signature algorithm identifiers for X.509
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MLDSAAlgorithm {
    /// ML-DSA-44 (security level 2)
    MLDSA44,
    /// ML-DSA-65 (security level 3)
    MLDSA65,
    /// ML-DSA-87 (security level 5)
    MLDSA87,
}

impl MLDSAAlgorithm {
    /// Get the OID for this algorithm
    pub fn oid(&self) -> &'static str {
        match self {
            MLDSAAlgorithm::MLDSA44 => "1.3.6.1.4.1.2.267.12.4.4",
            MLDSAAlgorithm::MLDSA65 => "1.3.6.1.4.1.2.267.12.6.5",
            MLDSAAlgorithm::MLDSA87 => "1.3.6.1.4.1.2.267.12.8.7",
        }
    }

    /// Get algorithm name
    pub fn name(&self) -> &'static str {
        match self {
            MLDSAAlgorithm::MLDSA44 => "ML-DSA-44",
            MLDSAAlgorithm::MLDSA65 => "ML-DSA-65",
            MLDSAAlgorithm::MLDSA87 => "ML-DSA-87",
        }
    }

    /// Get from QuID security level
    pub fn from_security_level(level: &quid_core::SecurityLevel) -> Self {
        match level {
            quid_core::SecurityLevel::Level1 => MLDSAAlgorithm::MLDSA44,
            quid_core::SecurityLevel::Level2 => MLDSAAlgorithm::MLDSA65,
            quid_core::SecurityLevel::Level3 => MLDSAAlgorithm::MLDSA87,
        }
    }
}

/// ML-DSA signature structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLDSASignature {
    /// The signature algorithm used
    pub algorithm: MLDSAAlgorithm,
    /// The signature bytes
    pub signature: Vec<u8>,
    /// The public key used for verification
    pub public_key: Vec<u8>,
}

impl MLDSASignature {
    /// Create a new ML-DSA signature
    pub fn new(algorithm: MLDSAAlgorithm, signature: Vec<u8>, public_key: Vec<u8>) -> Self {
        Self {
            algorithm,
            signature,
            public_key,
        }
    }

    /// Verify the signature against given data
    pub async fn verify(&self, quid_client: &QuIDClient, data: &[u8], identity: &QuIDIdentity) -> QuIDTLSResult<bool> {
        // In a real implementation, this would verify the ML-DSA signature
        // For now, we'll use QuID's verification mechanism
        quid_client.verify_signature(identity, &self.signature, data)
            .await
            .map_err(|e| QuIDTLSError::CertificateValidationFailed(format!("Signature verification failed: {}", e)))
    }

    /// Encode signature for X.509 DER format
    pub fn to_der(&self) -> QuIDTLSResult<Vec<u8>> {
        // In a real implementation, this would encode the signature in proper DER format
        // For now, we'll create a simplified encoding
        let mut der_data = Vec::new();
        
        // Algorithm identifier
        der_data.extend_from_slice(self.algorithm.oid().as_bytes());
        der_data.push(0x00); // NULL parameters
        
        // Signature value
        der_data.extend_from_slice(&self.signature);
        
        Ok(der_data)
    }
}

/// X.509 certificate extension types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum X509Extension {
    /// Key Usage extension
    KeyUsage {
        digital_signature: bool,
        key_encipherment: bool,
        key_agreement: bool,
        key_cert_sign: bool,
        crl_sign: bool,
        critical: bool,
    },
    /// Extended Key Usage extension
    ExtendedKeyUsage {
        server_auth: bool,
        client_auth: bool,
        code_signing: bool,
        email_protection: bool,
        time_stamping: bool,
        critical: bool,
    },
    /// Subject Alternative Name extension
    SubjectAltName {
        dns_names: Vec<String>,
        ip_addresses: Vec<IpAddr>,
        email_addresses: Vec<String>,
        critical: bool,
    },
    /// Basic Constraints extension
    BasicConstraints {
        ca: bool,
        path_length: Option<u8>,
        critical: bool,
    },
    /// Authority Key Identifier extension
    AuthorityKeyIdentifier {
        key_identifier: Vec<u8>,
        critical: bool,
    },
    /// Subject Key Identifier extension
    SubjectKeyIdentifier {
        key_identifier: Vec<u8>,
        critical: bool,
    },
}

impl X509Extension {
    /// Get the OID for this extension
    pub fn oid(&self) -> &'static str {
        match self {
            X509Extension::KeyUsage { .. } => "2.5.29.15",
            X509Extension::ExtendedKeyUsage { .. } => "2.5.29.37",
            X509Extension::SubjectAltName { .. } => "2.5.29.17",
            X509Extension::BasicConstraints { .. } => "2.5.29.19",
            X509Extension::AuthorityKeyIdentifier { .. } => "2.5.29.35",
            X509Extension::SubjectKeyIdentifier { .. } => "2.5.29.14",
        }
    }

    /// Check if this extension is marked as critical
    pub fn is_critical(&self) -> bool {
        match self {
            X509Extension::KeyUsage { critical, .. } => *critical,
            X509Extension::ExtendedKeyUsage { critical, .. } => *critical,
            X509Extension::SubjectAltName { critical, .. } => *critical,
            X509Extension::BasicConstraints { critical, .. } => *critical,
            X509Extension::AuthorityKeyIdentifier { critical, .. } => *critical,
            X509Extension::SubjectKeyIdentifier { critical, .. } => *critical,
        }
    }

    /// Encode extension value to DER
    pub fn to_der_value(&self) -> QuIDTLSResult<Vec<u8>> {
        // In a real implementation, this would properly encode extensions in DER format
        // For now, we'll create simplified encodings
        match self {
            X509Extension::KeyUsage { 
                digital_signature, 
                key_encipherment, 
                key_agreement, 
                key_cert_sign, 
                crl_sign, 
                .. 
            } => {
                let mut bits = 0u8;
                if *digital_signature { bits |= 0x80; }
                if *key_encipherment { bits |= 0x20; }
                if *key_agreement { bits |= 0x08; }
                if *key_cert_sign { bits |= 0x04; }
                if *crl_sign { bits |= 0x02; }
                Ok(vec![0x03, 0x02, 0x00, bits])
            }
            X509Extension::ExtendedKeyUsage { 
                server_auth, 
                client_auth, 
                code_signing, 
                email_protection, 
                time_stamping, 
                .. 
            } => {
                // Simplified EKU encoding
                let mut eku = Vec::new();
                if *server_auth { eku.extend_from_slice(b"1.3.6.1.5.5.7.3.1"); }
                if *client_auth { eku.extend_from_slice(b"1.3.6.1.5.5.7.3.2"); }
                if *code_signing { eku.extend_from_slice(b"1.3.6.1.5.5.7.3.3"); }
                if *email_protection { eku.extend_from_slice(b"1.3.6.1.5.5.7.3.4"); }
                if *time_stamping { eku.extend_from_slice(b"1.3.6.1.5.5.7.3.8"); }
                Ok(eku)
            }
            X509Extension::SubjectAltName { dns_names, ip_addresses, email_addresses, .. } => {
                // Simplified SAN encoding
                let mut san = Vec::new();
                for dns in dns_names {
                    san.extend_from_slice(dns.as_bytes());
                }
                for ip in ip_addresses {
                    san.extend_from_slice(&ip.to_string().as_bytes());
                }
                for email in email_addresses {
                    san.extend_from_slice(email.as_bytes());
                }
                Ok(san)
            }
            X509Extension::BasicConstraints { ca, path_length, .. } => {
                let mut bc = vec![0x01, 0x01, if *ca { 0xFF } else { 0x00 }];
                if let Some(length) = path_length {
                    bc.extend_from_slice(&[0x02, 0x01, *length]);
                }
                Ok(bc)
            }
            X509Extension::AuthorityKeyIdentifier { key_identifier, .. } => {
                Ok(key_identifier.clone())
            }
            X509Extension::SubjectKeyIdentifier { key_identifier, .. } => {
                Ok(key_identifier.clone())
            }
        }
    }
}

/// X.509 certificate with ML-DSA signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X509Certificate {
    /// Certificate version (v3 = 2)
    pub version: u8,
    /// Serial number
    pub serial_number: Vec<u8>,
    /// Signature algorithm
    pub signature_algorithm: MLDSAAlgorithm,
    /// Issuer distinguished name
    pub issuer: String,
    /// Validity period
    pub validity: CertificateValidity,
    /// Subject distinguished name
    pub subject: String,
    /// Subject public key info
    pub public_key: Vec<u8>,
    /// Extensions
    pub extensions: Vec<X509Extension>,
    /// ML-DSA signature
    pub signature: MLDSASignature,
    /// QuID identity used for signing
    pub signer_identity: QuIDIdentity,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Certificate validity period
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateValidity {
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

impl CertificateValidity {
    /// Create validity period from duration
    pub fn from_duration(duration: Duration) -> Self {
        let now = Utc::now();
        Self {
            not_before: now,
            not_after: now + duration,
        }
    }

    /// Check if certificate is currently valid
    pub fn is_valid(&self) -> bool {
        let now = Utc::now();
        now >= self.not_before && now <= self.not_after
    }

    /// Get remaining validity duration
    pub fn remaining_duration(&self) -> Option<Duration> {
        let now = Utc::now();
        if now <= self.not_after {
            Some(self.not_after - now)
        } else {
            None
        }
    }
}

impl X509Certificate {
    /// Create a new X.509 certificate
    pub fn new(
        serial_number: Vec<u8>,
        signature_algorithm: MLDSAAlgorithm,
        issuer: String,
        validity: CertificateValidity,
        subject: String,
        public_key: Vec<u8>,
        extensions: Vec<X509Extension>,
        signature: MLDSASignature,
        signer_identity: QuIDIdentity,
    ) -> Self {
        Self {
            version: 2, // v3
            serial_number,
            signature_algorithm,
            issuer,
            validity,
            subject,
            public_key,
            extensions,
            signature,
            signer_identity,
            metadata: HashMap::new(),
        }
    }

    /// Verify the certificate signature
    pub async fn verify_signature(&self, quid_client: &QuIDClient, ca_identity: &QuIDIdentity) -> QuIDTLSResult<bool> {
        let tbs_certificate = self.encode_tbs_certificate()?;
        self.signature.verify(quid_client, &tbs_certificate, ca_identity).await
    }

    /// Check if certificate is valid for a given purpose
    pub fn is_valid_for_purpose(&self, purpose: CertificatePurpose) -> bool {
        if !self.validity.is_valid() {
            return false;
        }

        // Check extensions for appropriate usage
        for ext in &self.extensions {
            match (ext, purpose) {
                (X509Extension::ExtendedKeyUsage { server_auth: true, .. }, CertificatePurpose::ServerAuth) => return true,
                (X509Extension::ExtendedKeyUsage { client_auth: true, .. }, CertificatePurpose::ClientAuth) => return true,
                (X509Extension::ExtendedKeyUsage { code_signing: true, .. }, CertificatePurpose::CodeSigning) => return true,
                _ => continue,
            }
        }

        false
    }

    /// Get certificate fingerprint (SHA-256)
    pub fn fingerprint(&self) -> QuIDTLSResult<String> {
        use sha2::{Sha256, Digest};
        
        let der_data = self.to_der()?;
        let mut hasher = Sha256::new();
        hasher.update(&der_data);
        let hash = hasher.finalize();
        
        Ok(hex::encode(hash))
    }

    /// Convert certificate to DER format
    pub fn to_der(&self) -> QuIDTLSResult<Vec<u8>> {
        // In a real implementation, this would properly encode the certificate in DER format
        // For now, we'll create a simplified encoding
        let mut der_data = Vec::new();
        
        // Certificate version
        der_data.push(self.version);
        
        // Serial number
        der_data.extend_from_slice(&self.serial_number);
        
        // Signature algorithm
        der_data.extend_from_slice(self.signature_algorithm.oid().as_bytes());
        
        // Issuer
        der_data.extend_from_slice(self.issuer.as_bytes());
        
        // Validity
        der_data.extend_from_slice(&self.validity.not_before.timestamp().to_be_bytes());
        der_data.extend_from_slice(&self.validity.not_after.timestamp().to_be_bytes());
        
        // Subject
        der_data.extend_from_slice(self.subject.as_bytes());
        
        // Public key
        der_data.extend_from_slice(&self.public_key);
        
        // Extensions
        for ext in &self.extensions {
            der_data.extend_from_slice(ext.oid().as_bytes());
            der_data.push(if ext.is_critical() { 0xFF } else { 0x00 });
            der_data.extend_from_slice(&ext.to_der_value()?);
        }
        
        // Signature
        der_data.extend_from_slice(&self.signature.to_der()?);
        
        Ok(der_data)
    }

    /// Convert certificate to PEM format
    pub fn to_pem(&self) -> QuIDTLSResult<String> {
        let der_data = self.to_der()?;
        let base64_data = base64::encode(&der_data);
        
        let mut pem = String::new();
        pem.push_str("-----BEGIN CERTIFICATE-----\n");
        
        // Split base64 data into 64-character lines
        for chunk in base64_data.as_bytes().chunks(64) {
            pem.push_str(&String::from_utf8_lossy(chunk));
            pem.push('\n');
        }
        
        pem.push_str("-----END CERTIFICATE-----\n");
        Ok(pem)
    }

    /// Encode the ToBeSigned certificate data
    fn encode_tbs_certificate(&self) -> QuIDTLSResult<Vec<u8>> {
        // This would encode everything except the signature
        let mut tbs_data = Vec::new();
        
        tbs_data.push(self.version);
        tbs_data.extend_from_slice(&self.serial_number);
        tbs_data.extend_from_slice(self.signature_algorithm.oid().as_bytes());
        tbs_data.extend_from_slice(self.issuer.as_bytes());
        tbs_data.extend_from_slice(&self.validity.not_before.timestamp().to_be_bytes());
        tbs_data.extend_from_slice(&self.validity.not_after.timestamp().to_be_bytes());
        tbs_data.extend_from_slice(self.subject.as_bytes());
        tbs_data.extend_from_slice(&self.public_key);
        
        for ext in &self.extensions {
            tbs_data.extend_from_slice(ext.oid().as_bytes());
            tbs_data.push(if ext.is_critical() { 0xFF } else { 0x00 });
            tbs_data.extend_from_slice(&ext.to_der_value()?);
        }
        
        Ok(tbs_data)
    }

    /// Export certificate to file
    pub fn export_to_file(&self, path: &std::path::Path, format: CertificateFormat) -> QuIDTLSResult<()> {
        let data = match format {
            CertificateFormat::DER => self.to_der()?,
            CertificateFormat::PEM => self.to_pem()?.into_bytes(),
        };
        
        std::fs::write(path, data)?;
        
        // Set appropriate permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))?;
        }
        
        Ok(())
    }
}

/// Certificate purposes for validation
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CertificatePurpose {
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    TimeStamping,
}

/// Certificate file formats
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CertificateFormat {
    DER,
    PEM,
}

/// X.509 certificate builder with QuID integration
pub struct X509CertificateBuilder<'a> {
    quid_client: &'a QuIDClient,
    identity: &'a QuIDIdentity,
}

impl<'a> X509CertificateBuilder<'a> {
    /// Create a new certificate builder
    pub fn new(quid_client: &'a QuIDClient, identity: &'a QuIDIdentity) -> Self {
        Self {
            quid_client,
            identity,
        }
    }

    /// Build a new X.509 certificate
    pub async fn build_certificate(
        &self,
        subject: &str,
        options: crate::cert::CertificateOptions,
    ) -> QuIDTLSResult<X509Certificate> {
        // Generate serial number
        let serial_number = self.generate_serial_number();
        
        // Determine ML-DSA algorithm from identity security level
        let signature_algorithm = MLDSAAlgorithm::from_security_level(&self.identity.security_level);
        
        // Get public key from QuID identity
        let public_key = self.quid_client
            .get_public_key(self.identity)
            .await
            .map_err(|e| QuIDTLSError::CertificateGenerationFailed(format!("Failed to get public key: {}", e)))?;
        
        // Create validity period
        let validity = CertificateValidity::from_duration(options.validity_duration);
        
        // Build extensions
        let extensions = self.build_extensions(&options)?;
        
        // Create TBS certificate data for signing
        let mut tbs_data = Vec::new();
        tbs_data.push(2); // version v3
        tbs_data.extend_from_slice(&serial_number);
        tbs_data.extend_from_slice(signature_algorithm.oid().as_bytes());
        tbs_data.extend_from_slice(options.issuer.as_bytes());
        tbs_data.extend_from_slice(&validity.not_before.timestamp().to_be_bytes());
        tbs_data.extend_from_slice(&validity.not_after.timestamp().to_be_bytes());
        tbs_data.extend_from_slice(subject.as_bytes());
        tbs_data.extend_from_slice(&public_key);
        
        // Sign the TBS data with QuID
        let signature_bytes = self.quid_client
            .sign_data(self.identity, &tbs_data)
            .await
            .map_err(|e| QuIDTLSError::CertificateGenerationFailed(format!("Failed to sign certificate: {}", e)))?;
        
        let signature = MLDSASignature::new(signature_algorithm.clone(), signature_bytes, public_key.clone());
        
        let certificate = X509Certificate::new(
            serial_number,
            signature_algorithm,
            options.issuer,
            validity,
            subject.to_string(),
            public_key,
            extensions,
            signature,
            self.identity.clone(),
        );
        
        Ok(certificate)
    }

    /// Generate a unique serial number
    fn generate_serial_number(&self) -> Vec<u8> {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut serial = vec![0u8; 16];
        rng.fill_bytes(&mut serial);
        serial
    }

    /// Build certificate extensions
    fn build_extensions(&self, options: &crate::cert::CertificateOptions) -> QuIDTLSResult<Vec<X509Extension>> {
        let mut extensions = Vec::new();
        
        // Basic Constraints
        if options.is_ca {
            extensions.push(X509Extension::BasicConstraints {
                ca: true,
                path_length: options.path_length,
                critical: true,
            });
        }
        
        // Key Usage
        extensions.push(X509Extension::KeyUsage {
            digital_signature: options.key_usage.digital_signature,
            key_encipherment: options.key_usage.key_encipherment,
            key_agreement: options.key_usage.key_agreement,
            key_cert_sign: options.key_usage.key_cert_sign,
            crl_sign: options.key_usage.crl_sign,
            critical: true,
        });
        
        // Extended Key Usage
        if options.extended_key_usage.server_auth ||
           options.extended_key_usage.client_auth ||
           options.extended_key_usage.code_signing ||
           options.extended_key_usage.email_protection ||
           options.extended_key_usage.time_stamping {
            extensions.push(X509Extension::ExtendedKeyUsage {
                server_auth: options.extended_key_usage.server_auth,
                client_auth: options.extended_key_usage.client_auth,
                code_signing: options.extended_key_usage.code_signing,
                email_protection: options.extended_key_usage.email_protection,
                time_stamping: options.extended_key_usage.time_stamping,
                critical: false,
            });
        }
        
        // Subject Alternative Name
        if !options.subject_alt_names.dns_names.is_empty() ||
           !options.subject_alt_names.ip_addresses.is_empty() ||
           !options.subject_alt_names.email_addresses.is_empty() {
            extensions.push(X509Extension::SubjectAltName {
                dns_names: options.subject_alt_names.dns_names.clone(),
                ip_addresses: options.subject_alt_names.ip_addresses.clone(),
                email_addresses: options.subject_alt_names.email_addresses.clone(),
                critical: false,
            });
        }
        
        // Subject Key Identifier
        let ski = self.generate_key_identifier();
        extensions.push(X509Extension::SubjectKeyIdentifier {
            key_identifier: ski,
            critical: false,
        });
        
        Ok(extensions)
    }

    /// Generate a key identifier
    fn generate_key_identifier(&self) -> Vec<u8> {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&self.identity.id);
        hasher.finalize()[..20].to_vec() // Use first 20 bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_mldsa_algorithm() {
        assert_eq!(MLDSAAlgorithm::MLDSA44.name(), "ML-DSA-44");
        assert_eq!(MLDSAAlgorithm::MLDSA65.name(), "ML-DSA-65");
        assert_eq!(MLDSAAlgorithm::MLDSA87.name(), "ML-DSA-87");
        
        assert!(MLDSAAlgorithm::MLDSA44.oid().contains("4.4"));
        assert!(MLDSAAlgorithm::MLDSA65.oid().contains("6.5"));
        assert!(MLDSAAlgorithm::MLDSA87.oid().contains("8.7"));
    }

    #[test]
    fn test_certificate_validity() {
        let validity = CertificateValidity::from_duration(Duration::hours(24));
        assert!(validity.is_valid());
        assert!(validity.remaining_duration().is_some());
        
        let past_validity = CertificateValidity {
            not_before: Utc::now() - Duration::days(2),
            not_after: Utc::now() - Duration::days(1),
        };
        assert!(!past_validity.is_valid());
        assert!(past_validity.remaining_duration().is_none());
    }

    #[test]
    fn test_x509_extension() {
        let ext = X509Extension::KeyUsage {
            digital_signature: true,
            key_encipherment: false,
            key_agreement: false,
            key_cert_sign: false,
            crl_sign: false,
            critical: true,
        };
        
        assert_eq!(ext.oid(), "2.5.29.15");
        assert!(ext.is_critical());
        assert!(ext.to_der_value().is_ok());
    }
}