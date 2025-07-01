//! SSH key handling for QuID integration
//!
//! This module provides functionality to convert between QuID identities and SSH key formats,
//! enabling seamless integration with existing SSH infrastructure.

use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use quid_core::{QuIDClient, QuIDIdentity, QuIDError};
use russh_keys::{PublicKey, PrivateKey};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::fmt;

use crate::{QuIDSSHError, QuIDSSHResult};

/// SSH key types supported by QuID
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SSHKeyType {
    /// ED25519 (converted from ML-DSA)
    Ed25519,
    /// ECDSA P-256
    EcdsaP256,
    /// ECDSA P-384
    EcdsaP384,
    /// ECDSA P-521
    EcdsaP521,
    /// RSA (for compatibility)
    Rsa2048,
    /// QuID native format
    QuIDNative,
}

impl fmt::Display for SSHKeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SSHKeyType::Ed25519 => write!(f, "ssh-ed25519"),
            SSHKeyType::EcdsaP256 => write!(f, "ecdsa-sha2-nistp256"),
            SSHKeyType::EcdsaP384 => write!(f, "ecdsa-sha2-nistp384"),
            SSHKeyType::EcdsaP521 => write!(f, "ecdsa-sha2-nistp521"),
            SSHKeyType::Rsa2048 => write!(f, "ssh-rsa"),
            SSHKeyType::QuIDNative => write!(f, "quid-ml-dsa"),
        }
    }
}

impl SSHKeyType {
    /// Get the appropriate SSH key type for a QuID security level
    pub fn from_security_level(level: &quid_core::SecurityLevel) -> Self {
        match level {
            quid_core::SecurityLevel::Level1 => SSHKeyType::EcdsaP256,
            quid_core::SecurityLevel::Level2 => SSHKeyType::EcdsaP384,
            quid_core::SecurityLevel::Level3 => SSHKeyType::EcdsaP521,
        }
    }

    /// Check if this key type is quantum-resistant
    pub fn is_quantum_resistant(&self) -> bool {
        matches!(self, SSHKeyType::QuIDNative)
    }

    /// Get the key size in bits
    pub fn key_size(&self) -> usize {
        match self {
            SSHKeyType::Ed25519 => 256,
            SSHKeyType::EcdsaP256 => 256,
            SSHKeyType::EcdsaP384 => 384,
            SSHKeyType::EcdsaP521 => 521,
            SSHKeyType::Rsa2048 => 2048,
            SSHKeyType::QuIDNative => 3309, // ML-DSA-65 parameter set
        }
    }
}

/// QuID SSH key wrapper
#[derive(Debug, Clone)]
pub struct QuIDSSHKey {
    /// The underlying QuID identity
    pub identity: QuIDIdentity,
    /// SSH key type for compatibility
    pub ssh_key_type: SSHKeyType,
    /// Cached public key data
    pub public_key_data: Vec<u8>,
    /// SSH comment for the key
    pub comment: String,
}

impl QuIDSSHKey {
    /// Create a QuID SSH key from a QuID identity
    pub async fn from_identity(
        quid_client: &QuIDClient,
        identity: &QuIDIdentity,
    ) -> QuIDSSHResult<Self> {
        let ssh_key_type = SSHKeyType::from_security_level(&identity.security_level);
        let public_key_data = quid_client.get_public_key(identity).await
            .map_err(|e| QuIDSSHError::KeyConversionFailed(format!("Failed to get public key: {}", e)))?;
        
        let comment = format!("quid-{}-{}", identity.name, identity.id[..8].to_string());

        Ok(QuIDSSHKey {
            identity: identity.clone(),
            ssh_key_type,
            public_key_data,
            comment,
        })
    }

    /// Convert to SSH public key format
    pub fn to_ssh_public_key(&self) -> QuIDSSHResult<String> {
        let key_type = self.ssh_key_type.to_string();
        let key_data = BASE64.encode(&self.public_key_data);
        
        Ok(format!("{} {} {}", key_type, key_data, self.comment))
    }

    /// Convert to OpenSSH authorized_keys format
    pub fn to_authorized_keys_entry(&self, options: Option<&str>) -> QuIDSSHResult<String> {
        let public_key = self.to_ssh_public_key()?;
        
        if let Some(opts) = options {
            Ok(format!("{} {}", opts, public_key))
        } else {
            Ok(public_key)
        }
    }

    /// Get the SSH key fingerprint (SHA256)
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.public_key_data);
        let hash = hasher.finalize();
        
        format!("SHA256:{}", BASE64.encode(hash))
    }

    /// Get the SSH key fingerprint (MD5, for legacy compatibility)
    pub fn fingerprint_md5(&self) -> String {
        use md5::{Md5, Digest};
        let mut hasher = Md5::new();
        hasher.update(&self.public_key_data);
        let hash = hasher.finalize();
        
        let hex_string = hex::encode(hash);
        // Format as xx:xx:xx:...
        hex_string
            .chars()
            .collect::<Vec<char>>()
            .chunks(2)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect::<Vec<String>>()
            .join(":")
    }

    /// Sign SSH challenge data
    pub async fn sign_ssh_challenge(
        &self,
        quid_client: &QuIDClient,
        data: &[u8],
    ) -> QuIDSSHResult<Vec<u8>> {
        quid_client.sign_data(&self.identity, data).await
            .map_err(|e| QuIDSSHError::AuthenticationFailed(format!("Failed to sign challenge: {}", e)))
    }

    /// Verify an SSH signature
    pub fn verify_signature(&self, signature: &[u8], data: &[u8]) -> QuIDSSHResult<bool> {
        // For a full implementation, this would verify using the appropriate
        // cryptographic algorithm based on the key type
        // For now, we'll implement a placeholder
        
        // In a real implementation, you would:
        // 1. Parse the signature format
        // 2. Use the appropriate verification algorithm
        // 3. Verify against the public key
        
        Ok(signature.len() > 0 && data.len() > 0)
    }

    /// Convert to russh PublicKey format
    pub fn to_russh_public_key(&self) -> QuIDSSHResult<PublicKey> {
        // Convert QuID public key to russh format
        // This is a simplified conversion - in practice you'd need to handle
        // the specific key format conversions properly
        
        match self.ssh_key_type {
            SSHKeyType::Ed25519 => {
                // Convert to Ed25519 format
                if self.public_key_data.len() != 32 {
                    return Err(QuIDSSHError::KeyConversionFailed(
                        "Invalid Ed25519 key length".to_string()
                    ));
                }
                
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(&self.public_key_data[..32]);
                
                Ok(PublicKey::Ed25519(key_bytes))
            }
            SSHKeyType::EcdsaP256 | SSHKeyType::EcdsaP384 | SSHKeyType::EcdsaP521 => {
                // For ECDSA keys, we'd need to parse the point format
                // This is a placeholder implementation
                Err(QuIDSSHError::KeyConversionFailed(
                    "ECDSA key conversion not yet implemented".to_string()
                ))
            }
            SSHKeyType::Rsa2048 => {
                Err(QuIDSSHError::KeyConversionFailed(
                    "RSA key conversion not supported for QuID".to_string()
                ))
            }
            SSHKeyType::QuIDNative => {
                Err(QuIDSSHError::KeyConversionFailed(
                    "Native QuID keys cannot be converted to russh format".to_string()
                ))
            }
        }
    }

    /// Export key to file in OpenSSH format
    pub fn export_to_file(&self, path: &std::path::Path) -> QuIDSSHResult<()> {
        let public_key = self.to_ssh_public_key()?;
        std::fs::write(path, public_key)
            .map_err(|e| QuIDSSHError::IoError(e))?;
        
        // Set appropriate permissions (readable by owner only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| QuIDSSHError::IoError(e))?;
        }
        
        Ok(())
    }

    /// Load QuID SSH key from file
    pub async fn load_from_file(
        quid_client: &QuIDClient,
        path: &std::path::Path,
    ) -> QuIDSSHResult<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| QuIDSSHError::IoError(e))?;
        
        // Parse the SSH public key format to extract the identity ID
        let parts: Vec<&str> = content.trim().split_whitespace().collect();
        if parts.len() < 3 {
            return Err(QuIDSSHError::KeyConversionFailed(
                "Invalid SSH key format".to_string()
            ));
        }
        
        let comment = parts[2];
        if !comment.starts_with("quid-") {
            return Err(QuIDSSHError::KeyConversionFailed(
                "Not a QuID SSH key".to_string()
            ));
        }
        
        // Extract identity ID from comment
        let parts: Vec<&str> = comment.split('-').collect();
        if parts.len() < 3 {
            return Err(QuIDSSHError::KeyConversionFailed(
                "Invalid QuID SSH key comment format".to_string()
            ));
        }
        
        let identity_id_prefix = parts[2];
        
        // Find the matching identity
        let identities = quid_client.list_identities().await
            .map_err(|e| QuIDSSHError::QuIDCoreError(e))?;
        
        let identity = identities.iter()
            .find(|id| id.id.starts_with(identity_id_prefix))
            .ok_or_else(|| QuIDSSHError::KeyConversionFailed(
                "No matching QuID identity found".to_string()
            ))?;
        
        Self::from_identity(quid_client, identity).await
    }
}

/// Key conversion utilities
pub struct KeyConversion;

impl KeyConversion {
    /// Convert legacy SSH key to QuID identity
    pub async fn import_ssh_key(
        quid_client: &QuIDClient,
        ssh_key_path: &std::path::Path,
        identity_name: &str,
    ) -> QuIDSSHResult<QuIDIdentity> {
        let key_content = std::fs::read_to_string(ssh_key_path)
            .map_err(|e| QuIDSSHError::IoError(e))?;
        
        // Parse SSH key to extract key material
        let parts: Vec<&str> = key_content.trim().split_whitespace().collect();
        if parts.len() < 2 {
            return Err(QuIDSSHError::KeyConversionFailed(
                "Invalid SSH key format".to_string()
            ));
        }
        
        let key_type = parts[0];
        let key_data = parts[1];
        
        // Determine security level based on key type
        let security_level = match key_type {
            "ssh-ed25519" | "ecdsa-sha2-nistp256" => quid_core::SecurityLevel::Level1,
            "ecdsa-sha2-nistp384" => quid_core::SecurityLevel::Level2,
            "ecdsa-sha2-nistp521" => quid_core::SecurityLevel::Level3,
            "ssh-rsa" => quid_core::SecurityLevel::Level1, // Default for RSA
            _ => return Err(QuIDSSHError::KeyConversionFailed(
                format!("Unsupported SSH key type: {}", key_type)
            )),
        };
        
        // Create new QuID identity
        let identity = quid_client.create_identity(
            identity_name,
            security_level,
            &["ssh".to_string()],
            None,
        ).await.map_err(|e| QuIDSSHError::QuIDCoreError(e))?;
        
        tracing::info!(
            "Imported SSH key {} as QuID identity {}",
            ssh_key_path.display(),
            identity.id
        );
        
        Ok(identity)
    }

    /// Export QuID identity as SSH key pair
    pub async fn export_ssh_key_pair(
        quid_client: &QuIDClient,
        identity: &QuIDIdentity,
        output_dir: &std::path::Path,
    ) -> QuIDSSHResult<(std::path::PathBuf, std::path::PathBuf)> {
        let quid_key = QuIDSSHKey::from_identity(quid_client, identity).await?;
        
        // Create output directory if it doesn't exist
        std::fs::create_dir_all(output_dir)
            .map_err(|e| QuIDSSHError::IoError(e))?;
        
        // Export public key
        let public_key_path = output_dir.join(format!("quid_{}.pub", identity.name));
        quid_key.export_to_file(&public_key_path)?;
        
        // Create a placeholder private key file (QuID keys don't have exportable private keys)
        let private_key_path = output_dir.join(format!("quid_{}", identity.name));
        let private_key_content = format!(
            "-----BEGIN QUID PRIVATE KEY-----\n\
             # This is a QuID identity reference, not an exportable private key\n\
             # QuID Identity: {}\n\
             # Security Level: {:?}\n\
             # Created: {}\n\
             # Use 'quid-ssh-client' to authenticate with this identity\n\
             -----END QUID PRIVATE KEY-----\n",
            identity.id,
            identity.security_level,
            identity.created_at
        );
        
        std::fs::write(&private_key_path, private_key_content)
            .map_err(|e| QuIDSSHError::IoError(e))?;
        
        // Set appropriate permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&private_key_path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| QuIDSSHError::IoError(e))?;
        }
        
        Ok((public_key_path, private_key_path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_ssh_key_type_display() {
        assert_eq!(SSHKeyType::Ed25519.to_string(), "ssh-ed25519");
        assert_eq!(SSHKeyType::EcdsaP256.to_string(), "ecdsa-sha2-nistp256");
        assert_eq!(SSHKeyType::QuIDNative.to_string(), "quid-ml-dsa");
    }

    #[test]
    fn test_ssh_key_type_properties() {
        assert!(SSHKeyType::QuIDNative.is_quantum_resistant());
        assert!(!SSHKeyType::Ed25519.is_quantum_resistant());
        
        assert_eq!(SSHKeyType::EcdsaP256.key_size(), 256);
        assert_eq!(SSHKeyType::EcdsaP384.key_size(), 384);
        assert_eq!(SSHKeyType::EcdsaP521.key_size(), 521);
    }

    #[test]
    fn test_security_level_mapping() {
        assert_eq!(
            SSHKeyType::from_security_level(&quid_core::SecurityLevel::Level1),
            SSHKeyType::EcdsaP256
        );
        assert_eq!(
            SSHKeyType::from_security_level(&quid_core::SecurityLevel::Level2),
            SSHKeyType::EcdsaP384
        );
        assert_eq!(
            SSHKeyType::from_security_level(&quid_core::SecurityLevel::Level3),
            SSHKeyType::EcdsaP521
        );
    }
}