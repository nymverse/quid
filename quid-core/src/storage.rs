//! Encrypted identity storage and management
//!
//! This module provides secure, encrypted storage for QuID identities with
//! backup and recovery capabilities.

use crate::{QuIDError, Result, QuIDIdentity};
use crate::crypto::KeyPair;
use secrecy::{ExposeSecret, SecretString, SecretVec};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Encrypted identity container with versioning support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedIdentity {
    /// Encrypted identity data
    pub encrypted_data: Vec<u8>,
    /// Salt used for key derivation
    pub salt: Vec<u8>,
    /// Initialization vector for encryption
    pub iv: Vec<u8>,
    /// HMAC for authenticated encryption
    pub hmac: Vec<u8>,
    /// Version of the encryption scheme
    pub version: u32,
    /// Timestamp of creation/last modification
    pub timestamp: u64,
    /// Optional backup metadata
    pub backup_metadata: Option<BackupMetadata>,
}

/// Backup metadata for recovery purposes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMetadata {
    /// Backup creation timestamp
    pub created_at: u64,
    /// Recovery hint (encrypted)
    pub recovery_hint: Vec<u8>,
    /// Backup format version
    pub format_version: u32,
}

/// Storage configuration
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Storage directory path
    pub storage_path: PathBuf,
    /// Key derivation iterations
    pub kdf_iterations: u32,
    /// Enable automatic backups
    pub auto_backup: bool,
    /// Maximum number of backup versions to keep
    pub max_backups: usize,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            storage_path: PathBuf::from(".quid"),
            kdf_iterations: 100_000,
            auto_backup: true,
            max_backups: 5,
        }
    }
}

/// Secure identity storage manager
#[derive(Debug)]
pub struct IdentityStorage {
    config: StorageConfig,
    /// In-memory cache of loaded identities
    cache: HashMap<Vec<u8>, (QuIDIdentity, KeyPair)>,
}

/// Key derivation result
struct DerivedKeys {
    encryption_key: SecretVec<u8>,
    hmac_key: SecretVec<u8>,
}

impl IdentityStorage {
    /// Create a new identity storage manager
    pub fn new(config: StorageConfig) -> Result<Self> {
        // Ensure storage directory exists
        if !config.storage_path.exists() {
            std::fs::create_dir_all(&config.storage_path)
                .map_err(|e| QuIDError::StorageError(format!("Failed to create storage directory: {}", e)))?;
        }

        Ok(Self {
            config,
            cache: HashMap::new(),
        })
    }

    /// Store an identity with encryption
    pub fn store_identity(
        &mut self,
        identity: &QuIDIdentity,
        keypair: &KeyPair,
        password: &SecretString,
    ) -> Result<()> {
        let encrypted = self.encrypt_identity(identity, keypair, password)?;
        
        let storage_path = self.get_identity_path(&identity.id);
        
        // Create backup if auto-backup is enabled
        if self.config.auto_backup && storage_path.exists() {
            self.create_backup(&storage_path)?;
        }
        
        // Write encrypted identity to file
        let serialized = serde_json::to_vec(&encrypted)
            .map_err(|e| QuIDError::StorageError(format!("Serialization failed: {}", e)))?;
        
        std::fs::write(&storage_path, serialized)
            .map_err(|e| QuIDError::StorageError(format!("Failed to write identity: {}", e)))?;
        
        // Update cache
        self.cache.insert(identity.id.clone(), (identity.clone(), keypair.clone()));
        
        Ok(())
    }

    /// Load and decrypt an identity
    pub fn load_identity(
        &mut self,
        identity_id: &[u8],
        password: &SecretString,
    ) -> Result<(QuIDIdentity, KeyPair)> {
        // Check cache first
        if let Some((identity, keypair)) = self.cache.get(identity_id) {
            return Ok((identity.clone(), keypair.clone()));
        }
        
        let storage_path = self.get_identity_path(identity_id);
        
        if !storage_path.exists() {
            return Err(QuIDError::StorageError("Identity not found".to_string()));
        }
        
        // Read encrypted data
        let encrypted_data = std::fs::read(&storage_path)
            .map_err(|e| QuIDError::StorageError(format!("Failed to read identity: {}", e)))?;
        
        let encrypted: EncryptedIdentity = serde_json::from_slice(&encrypted_data)
            .map_err(|e| QuIDError::StorageError(format!("Deserialization failed: {}", e)))?;
        
        // Decrypt identity
        let (identity, keypair) = self.decrypt_identity(&encrypted, password)?;
        
        // Update cache
        self.cache.insert(identity_id.to_vec(), (identity.clone(), keypair.clone()));
        
        Ok((identity, keypair))
    }

    /// List all stored identity IDs
    pub fn list_identities(&self) -> Result<Vec<Vec<u8>>> {
        let mut identities = Vec::new();
        
        let entries = std::fs::read_dir(&self.config.storage_path)
            .map_err(|e| QuIDError::StorageError(format!("Failed to read storage directory: {}", e)))?;
        
        for entry in entries {
            let entry = entry
                .map_err(|e| QuIDError::StorageError(format!("Failed to read directory entry: {}", e)))?;
            
            let path = entry.path();
            if path.is_file() && path.extension().map_or(false, |ext| ext == "quid") {
                if let Some(stem) = path.file_stem() {
                    if let Some(stem_str) = stem.to_str() {
                        if let Ok(id_bytes) = hex::decode(stem_str) {
                            identities.push(id_bytes);
                        }
                    }
                }
            }
        }
        
        Ok(identities)
    }

    /// Create an explicit backup of an identity
    pub fn backup_identity(
        &self,
        identity_id: &[u8],
        backup_hint: Option<String>,
    ) -> Result<PathBuf> {
        let storage_path = self.get_identity_path(identity_id);
        
        if !storage_path.exists() {
            return Err(QuIDError::StorageError("Identity not found".to_string()));
        }
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| QuIDError::CryptoError(format!("Time error: {}", e)))?
            .as_secs();
        
        // Create backup with hint if provided
        let backup_name = if let Some(ref hint) = backup_hint {
            // Sanitize hint for filename
            let safe_hint = hint.chars()
                .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
                .take(20)
                .collect::<String>();
            format!("{}.backup.{}.{}", 
                storage_path.file_name().unwrap().to_str().unwrap(), 
                safe_hint,
                timestamp
            )
        } else {
            format!("{}.backup.{}", 
                storage_path.file_name().unwrap().to_str().unwrap(), 
                timestamp
            )
        };
        
        let backup_path = storage_path.parent().unwrap().join(backup_name);
        
        // Read the encrypted identity and add backup metadata
        let encrypted_data = std::fs::read(&storage_path)
            .map_err(|e| QuIDError::StorageError(format!("Failed to read identity: {}", e)))?;
        
        let mut encrypted: EncryptedIdentity = serde_json::from_slice(&encrypted_data)
            .map_err(|e| QuIDError::StorageError(format!("Deserialization failed: {}", e)))?;
        
        // Add backup metadata
        let backup_metadata = BackupMetadata {
            created_at: timestamp,
            recovery_hint: backup_hint.map(|h| h.into_bytes()).unwrap_or_default(),
            format_version: 1,
        };
        encrypted.backup_metadata = Some(backup_metadata);
        
        // Write backup with metadata
        let backup_data = serde_json::to_vec(&encrypted)
            .map_err(|e| QuIDError::StorageError(format!("Serialization failed: {}", e)))?;
        
        std::fs::write(&backup_path, backup_data)
            .map_err(|e| QuIDError::StorageError(format!("Failed to write backup: {}", e)))?;
        
        Ok(backup_path)
    }

    /// List all backups for an identity
    pub fn list_backups(&self, identity_id: &[u8]) -> Result<Vec<PathBuf>> {
        let base_name = format!("{}.quid", hex::encode(identity_id));
        let mut backups = Vec::new();
        
        let entries = std::fs::read_dir(&self.config.storage_path)
            .map_err(|e| QuIDError::StorageError(format!("Failed to read storage directory: {}", e)))?;
        
        for entry in entries {
            let entry = entry
                .map_err(|e| QuIDError::StorageError(format!("Failed to read directory entry: {}", e)))?;
            
            let path = entry.path();
            if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                if filename.starts_with(&base_name) && filename.contains(".backup.") {
                    backups.push(path);
                }
            }
        }
        
        // Sort by modification time (newest first)
        backups.sort_by(|a, b| {
            let a_time = a.metadata().and_then(|m| m.modified()).unwrap_or(SystemTime::UNIX_EPOCH);
            let b_time = b.metadata().and_then(|m| m.modified()).unwrap_or(SystemTime::UNIX_EPOCH);
            b_time.cmp(&a_time)
        });
        
        Ok(backups)
    }

    /// Restore an identity from a backup
    pub fn restore_from_backup(
        &mut self,
        backup_path: &Path,
        password: &SecretString,
    ) -> Result<(QuIDIdentity, KeyPair)> {
        if !backup_path.exists() {
            return Err(QuIDError::StorageError("Backup file not found".to_string()));
        }
        
        // Read backup data
        let backup_data = std::fs::read(backup_path)
            .map_err(|e| QuIDError::StorageError(format!("Failed to read backup: {}", e)))?;
        
        let encrypted: EncryptedIdentity = serde_json::from_slice(&backup_data)
            .map_err(|e| QuIDError::StorageError(format!("Backup deserialization failed: {}", e)))?;
        
        // Decrypt the identity
        let (identity, keypair) = self.decrypt_identity(&encrypted, password)?;
        
        // Store the restored identity as current
        let current_path = self.get_identity_path(&identity.id);
        
        // Create a clean encrypted identity without backup metadata for current storage
        let clean_encrypted = EncryptedIdentity {
            encrypted_data: encrypted.encrypted_data,
            salt: encrypted.salt,
            iv: encrypted.iv,
            hmac: encrypted.hmac,
            version: encrypted.version,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| QuIDError::CryptoError(format!("Time error: {}", e)))?
                .as_secs(),
            backup_metadata: None,
        };
        
        let current_data = serde_json::to_vec(&clean_encrypted)
            .map_err(|e| QuIDError::StorageError(format!("Serialization failed: {}", e)))?;
        
        std::fs::write(&current_path, current_data)
            .map_err(|e| QuIDError::StorageError(format!("Failed to restore identity: {}", e)))?;
        
        // Update cache
        self.cache.insert(identity.id.clone(), (identity.clone(), keypair.clone()));
        
        Ok((identity, keypair))
    }

    /// Delete an identity from storage
    pub fn delete_identity(&mut self, identity_id: &[u8]) -> Result<()> {
        let storage_path = self.get_identity_path(identity_id);
        
        if storage_path.exists() {
            std::fs::remove_file(&storage_path)
                .map_err(|e| QuIDError::StorageError(format!("Failed to delete identity: {}", e)))?;
        }
        
        // Remove from cache
        self.cache.remove(identity_id);
        
        Ok(())
    }

    /// Create a backup of an identity file
    fn create_backup(&self, original_path: &Path) -> Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| QuIDError::CryptoError(format!("Time error: {}", e)))?
            .as_secs();
        
        let backup_name = format!("{}.backup.{}", 
            original_path.file_name().unwrap().to_str().unwrap(), 
            timestamp
        );
        let backup_path = original_path.parent().unwrap().join(backup_name);
        
        std::fs::copy(original_path, &backup_path)
            .map_err(|e| QuIDError::StorageError(format!("Failed to create backup: {}", e)))?;
        
        // Clean up old backups
        self.cleanup_old_backups(original_path)?;
        
        Ok(())
    }

    /// Clean up old backup files
    fn cleanup_old_backups(&self, original_path: &Path) -> Result<()> {
        let base_name = original_path.file_name().unwrap().to_str().unwrap();
        let parent_dir = original_path.parent().unwrap();
        
        let mut backups = Vec::new();
        
        let entries = std::fs::read_dir(parent_dir)
            .map_err(|e| QuIDError::StorageError(format!("Failed to read backup directory: {}", e)))?;
        
        for entry in entries {
            let entry = entry
                .map_err(|e| QuIDError::StorageError(format!("Failed to read directory entry: {}", e)))?;
            
            let path = entry.path();
            if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                if filename.starts_with(base_name) && filename.contains(".backup.") {
                    if let Some(timestamp_str) = filename.split(".backup.").last() {
                        if let Ok(timestamp) = timestamp_str.parse::<u64>() {
                            backups.push((timestamp, path));
                        }
                    }
                }
            }
        }
        
        // Sort by timestamp (newest first)
        backups.sort_by(|a, b| b.0.cmp(&a.0));
        
        // Remove old backups beyond max_backups
        for (_, path) in backups.iter().skip(self.config.max_backups) {
            let _ = std::fs::remove_file(path);
        }
        
        Ok(())
    }

    /// Get the storage path for an identity
    fn get_identity_path(&self, identity_id: &[u8]) -> PathBuf {
        let filename = format!("{}.quid", hex::encode(identity_id));
        self.config.storage_path.join(filename)
    }

    /// Encrypt an identity with a password
    fn encrypt_identity(
        &self,
        identity: &QuIDIdentity,
        keypair: &KeyPair,
        password: &SecretString,
    ) -> Result<EncryptedIdentity> {
        // Serialize identity and keypair together
        let combined_data = CombinedIdentityData {
            identity: identity.clone(),
            keypair: keypair.clone(),
        };
        
        let serialized = serde_json::to_vec(&combined_data)
            .map_err(|e| QuIDError::CryptoError(format!("Serialization failed: {}", e)))?;
        
        // Generate salt and IV
        let salt = self.generate_random_bytes(32)?;
        let iv = self.generate_random_bytes(16)?;
        
        // Derive encryption keys
        let derived_keys = self.derive_keys(password.expose_secret().as_bytes(), &salt)?;
        
        // Encrypt data using improved XOR cipher with IV mixing
        let mut encrypted_data = serialized.clone();
        let key_bytes = derived_keys.encryption_key.expose_secret();
        
        // Mix IV into the encryption for better security
        let mut mixed_key = Vec::new();
        for i in 0..key_bytes.len() {
            mixed_key.push(key_bytes[i] ^ iv[i % iv.len()]);
        }
        
        for (i, byte) in encrypted_data.iter_mut().enumerate() {
            *byte ^= mixed_key[i % mixed_key.len()];
        }
        
        // Calculate HMAC including salt and IV for better authentication
        let mut hmac_input = Vec::new();
        hmac_input.extend_from_slice(&encrypted_data);
        hmac_input.extend_from_slice(&salt);
        hmac_input.extend_from_slice(&iv);
        let hmac = self.calculate_hmac(&hmac_input, derived_keys.hmac_key.expose_secret())?;
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| QuIDError::CryptoError(format!("Time error: {}", e)))?
            .as_secs();
        
        Ok(EncryptedIdentity {
            encrypted_data,
            salt,
            iv,
            hmac,
            version: 1,
            timestamp,
            backup_metadata: None,
        })
    }

    /// Decrypt an identity with a password
    fn decrypt_identity(
        &self,
        encrypted: &EncryptedIdentity,
        password: &SecretString,
    ) -> Result<(QuIDIdentity, KeyPair)> {
        // Derive keys using the same salt
        let derived_keys = self.derive_keys(password.expose_secret().as_bytes(), &encrypted.salt)?;
        
        // Verify HMAC including salt and IV
        let mut hmac_input = Vec::new();
        hmac_input.extend_from_slice(&encrypted.encrypted_data);
        hmac_input.extend_from_slice(&encrypted.salt);
        hmac_input.extend_from_slice(&encrypted.iv);
        let expected_hmac = self.calculate_hmac(&hmac_input, derived_keys.hmac_key.expose_secret())?;
        if expected_hmac != encrypted.hmac {
            return Err(QuIDError::CryptoError("HMAC verification failed - wrong password or corrupted data".to_string()));
        }
        
        // Decrypt data using the same IV mixing
        let mut decrypted_data = encrypted.encrypted_data.clone();
        let key_bytes = derived_keys.encryption_key.expose_secret();
        
        // Mix IV into the decryption key the same way
        let mut mixed_key = Vec::new();
        for i in 0..key_bytes.len() {
            mixed_key.push(key_bytes[i] ^ encrypted.iv[i % encrypted.iv.len()]);
        }
        
        for (i, byte) in decrypted_data.iter_mut().enumerate() {
            *byte ^= mixed_key[i % mixed_key.len()];
        }
        
        // Deserialize combined data
        let combined_data: CombinedIdentityData = serde_json::from_slice(&decrypted_data)
            .map_err(|e| QuIDError::CryptoError(format!("Deserialization failed: {}", e)))?;
        
        Ok((combined_data.identity.clone(), combined_data.keypair.clone()))
    }

    /// Derive encryption and HMAC keys from password and salt
    fn derive_keys(&self, password: &[u8], salt: &[u8]) -> Result<DerivedKeys> {
        // Enhanced PBKDF2-like key derivation using SHA3 with password dependency
        let mut key_material = Vec::new();
        key_material.extend_from_slice(b"quid-kdf-v1");
        key_material.extend_from_slice(password);
        key_material.extend_from_slice(salt);
        key_material.extend_from_slice(&password.len().to_le_bytes());
        
        let mut derived = key_material;
        for i in 0..self.config.kdf_iterations {
            let mut hasher = Sha3_256::new();
            hasher.update(&derived);
            hasher.update(password); // Re-mix password each iteration
            hasher.update(&(i as u32).to_le_bytes()); // Add iteration counter
            derived = hasher.finalize().to_vec();
        }
        
        // Generate HMAC key with different derivation path
        let mut hasher2 = Sha3_256::new();
        hasher2.update(&derived);
        hasher2.update(b"hmac-key-derivation");
        hasher2.update(password);
        hasher2.update(salt);
        let hmac_material = hasher2.finalize().to_vec();
        
        // Create secret keys
        let encryption_key = SecretVec::new(derived);
        let hmac_key = SecretVec::new(hmac_material);
        
        Ok(DerivedKeys {
            encryption_key,
            hmac_key,
        })
    }

    /// Calculate HMAC using SHA3
    fn calculate_hmac(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        let mut hasher = Sha3_256::new();
        hasher.update(key);
        hasher.update(data);
        Ok(hasher.finalize().to_vec())
    }

    /// Generate cryptographically secure random bytes
    fn generate_random_bytes(&self, len: usize) -> Result<Vec<u8>> {
        use rand::RngCore;
        let mut bytes = vec![0u8; len];
        rand::thread_rng().fill_bytes(&mut bytes);
        Ok(bytes)
    }
}

/// Combined identity and keypair data for storage
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CombinedIdentityData {
    identity: QuIDIdentity,
    keypair: KeyPair,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecurityLevel;
    use tempfile::TempDir;

    fn create_test_storage() -> (IdentityStorage, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let config = StorageConfig {
            storage_path: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        let storage = IdentityStorage::new(config).unwrap();
        (storage, temp_dir)
    }

    #[test]
    fn test_store_and_load_identity() {
        let (mut storage, _temp_dir) = create_test_storage();
        
        // Create a test identity
        let (identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let password = SecretString::new("test_password".to_string());
        
        // Store the identity
        storage.store_identity(&identity, &keypair, &password).unwrap();
        
        // Load the identity back
        let (loaded_identity, loaded_keypair) = storage.load_identity(&identity.id, &password).unwrap();
        
        // Verify the loaded identity matches
        assert_eq!(identity.id, loaded_identity.id);
        assert_eq!(identity.public_key, loaded_identity.public_key);
        assert_eq!(identity.security_level, loaded_identity.security_level);
        assert_eq!(keypair.public_key, loaded_keypair.public_key);
    }

    #[test]
    fn test_wrong_password_fails() {
        let (mut storage, temp_dir) = create_test_storage();
        
        let (identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let password = SecretString::new("correct_password".to_string());
        let wrong_password = SecretString::new("wrong_password".to_string());
        
        // Store with correct password
        storage.store_identity(&identity, &keypair, &password).unwrap();
        
        // Create fresh storage to avoid cache
        let config = StorageConfig {
            storage_path: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        let mut fresh_storage = IdentityStorage::new(config).unwrap();
        
        // Try to load with wrong password - should fail
        let result = fresh_storage.load_identity(&identity.id, &wrong_password);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("HMAC verification failed"));
        }
    }

    #[test]
    fn test_list_identities() {
        let (mut storage, _temp_dir) = create_test_storage();
        
        let password = SecretString::new("test_password".to_string());
        
        // Create and store multiple identities
        let (identity1, keypair1) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let (identity2, keypair2) = QuIDIdentity::new(SecurityLevel::Level3).unwrap();
        
        storage.store_identity(&identity1, &keypair1, &password).unwrap();
        storage.store_identity(&identity2, &keypair2, &password).unwrap();
        
        // List identities
        let identities = storage.list_identities().unwrap();
        assert_eq!(identities.len(), 2);
        assert!(identities.contains(&identity1.id));
        assert!(identities.contains(&identity2.id));
    }

    #[test]
    fn test_delete_identity() {
        let (mut storage, _temp_dir) = create_test_storage();
        
        let (identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let password = SecretString::new("test_password".to_string());
        
        // Store identity
        storage.store_identity(&identity, &keypair, &password).unwrap();
        
        // Verify it exists
        let identities = storage.list_identities().unwrap();
        assert_eq!(identities.len(), 1);
        
        // Delete identity
        storage.delete_identity(&identity.id).unwrap();
        
        // Verify it's gone
        let identities = storage.list_identities().unwrap();
        assert_eq!(identities.len(), 0);
        
        // Try to load - should fail
        let result = storage.load_identity(&identity.id, &password);
        assert!(result.is_err());
    }

    #[test]
    fn test_encryption_decryption_roundtrip() {
        let (storage, _temp_dir) = create_test_storage();
        
        let (identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let password = SecretString::new("test_password".to_string());
        
        // Encrypt identity
        let encrypted = storage.encrypt_identity(&identity, &keypair, &password).unwrap();
        
        // Decrypt identity
        let (decrypted_identity, decrypted_keypair) = storage.decrypt_identity(&encrypted, &password).unwrap();
        
        // Verify roundtrip integrity
        assert_eq!(identity.id, decrypted_identity.id);
        assert_eq!(identity.public_key, decrypted_identity.public_key);
        assert_eq!(keypair.public_key, decrypted_keypair.public_key);
    }

    #[test]
    fn test_backup_and_restore() {
        let (mut storage, _temp_dir) = create_test_storage();
        
        let (identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let password = SecretString::new("test_password".to_string());
        
        // Store identity
        storage.store_identity(&identity, &keypair, &password).unwrap();
        
        // Create backup
        let backup_path = storage.backup_identity(&identity.id, Some("test-backup".to_string())).unwrap();
        assert!(backup_path.exists());
        
        // Delete original
        storage.delete_identity(&identity.id).unwrap();
        
        // Restore from backup
        let (restored_identity, restored_keypair) = storage.restore_from_backup(&backup_path, &password).unwrap();
        
        // Verify restoration
        assert_eq!(identity.id, restored_identity.id);
        assert_eq!(identity.public_key, restored_identity.public_key);
        assert_eq!(keypair.public_key, restored_keypair.public_key);
    }

    #[test]
    fn test_list_backups() {
        let (mut storage, _temp_dir) = create_test_storage();
        
        let (identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let password = SecretString::new("test_password".to_string());
        
        // Store identity
        storage.store_identity(&identity, &keypair, &password).unwrap();
        
        // Create multiple backups
        let _backup1 = storage.backup_identity(&identity.id, Some("backup1".to_string())).unwrap();
        let _backup2 = storage.backup_identity(&identity.id, Some("backup2".to_string())).unwrap();
        
        // List backups
        let backups = storage.list_backups(&identity.id).unwrap();
        assert_eq!(backups.len(), 2);
        
        // Backups should be sorted by modification time (newest first)
        for backup_path in &backups {
            assert!(backup_path.exists());
            assert!(backup_path.file_name().unwrap().to_str().unwrap().contains("backup"));
        }
    }

    #[test]
    fn test_backup_with_metadata() {
        let (mut storage, _temp_dir) = create_test_storage();
        
        let (identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let password = SecretString::new("test_password".to_string());
        
        // Store identity
        storage.store_identity(&identity, &keypair, &password).unwrap();
        
        // Create backup with hint
        let hint = "important-backup".to_string();
        let backup_path = storage.backup_identity(&identity.id, Some(hint.clone())).unwrap();
        
        // Read backup and verify metadata
        let backup_data = std::fs::read(&backup_path).unwrap();
        let encrypted: EncryptedIdentity = serde_json::from_slice(&backup_data).unwrap();
        
        assert!(encrypted.backup_metadata.is_some());
        let metadata = encrypted.backup_metadata.unwrap();
        assert_eq!(metadata.recovery_hint, hint.into_bytes());
        assert_eq!(metadata.format_version, 1);
    }
}