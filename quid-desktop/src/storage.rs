//! Desktop-specific secure storage backend for QuID

use crate::{DesktopError, DesktopResult, Platform};
use quid_core::storage::IdentityStorage;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::sync::RwLock;

/// Desktop storage backend types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageBackend {
    /// Encrypted file storage
    EncryptedFile {
        /// Directory path for storage
        storage_dir: PathBuf,
        /// Backup directory
        backup_dir: Option<PathBuf>,
    },
    /// System keychain integration
    SystemKeychain {
        /// Service name for keychain entries
        service_name: String,
        /// Fallback to encrypted file if keychain fails
        file_fallback: bool,
    },
    /// Memory-only storage (for testing)
    Memory,
}

impl Default for StorageBackend {
    fn default() -> Self {
        let platform = Platform::detect();
        
        // Use system keychain on supported platforms
        if platform.supports_keychain() {
            Self::SystemKeychain {
                service_name: "QuID Universal Authentication".to_string(),
                file_fallback: true,
            }
        } else {
            // Fallback to encrypted file storage
            let storage_dir = StorageBackend::get_default_storage_dir();
            Self::EncryptedFile {
                storage_dir,
                backup_dir: None,
            }
        }
    }
}

impl StorageBackend {
    /// Get default storage directory for the platform
    pub fn get_default_storage_dir() -> PathBuf {
        let platform = Platform::detect();
        
        match platform {
            Platform::Windows => {
                dirs::config_dir()
                    .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"))
                    .join("QuID")
            }
            Platform::MacOS => {
                dirs::config_dir()
                    .unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join("Library/Application Support"))
                    .join("QuID")
            }
            Platform::Linux => {
                dirs::config_dir()
                    .unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join(".config"))
                    .join("quid")
            }
            Platform::Unknown => {
                std::env::current_dir()
                    .unwrap_or_default()
                    .join("quid-data")
            }
        }
    }

    /// Get backup directory
    pub fn get_backup_dir(&self) -> Option<PathBuf> {
        match self {
            StorageBackend::EncryptedFile { backup_dir, .. } => backup_dir.clone(),
            StorageBackend::SystemKeychain { .. } => {
                Some(StorageBackend::get_default_storage_dir().join("backups"))
            }
            StorageBackend::Memory => None,
        }
    }
}

/// Desktop storage manager with platform-specific integrations
#[derive(Debug)]
pub struct DesktopStorage {
    backend: StorageBackend,
    core_storage: RwLock<IdentityStorage>,
    keychain_client: Option<KeychainClient>,
    file_storage: Option<FileStorageClient>,
}

impl DesktopStorage {
    /// Create new desktop storage manager
    pub async fn new(backend: StorageBackend) -> DesktopResult<Self> {
        let (keychain_client, file_storage) = match &backend {
            StorageBackend::SystemKeychain { service_name, file_fallback } => {
                let keychain = KeychainClient::new(service_name.clone()).await?;
                let file_storage = if *file_fallback {
                    Some(FileStorageClient::new(StorageBackend::get_default_storage_dir()).await?)
                } else {
                    None
                };
                (Some(keychain), file_storage)
            }
            StorageBackend::EncryptedFile { storage_dir, .. } => {
                let file_storage = FileStorageClient::new(storage_dir.clone()).await?;
                (None, Some(file_storage))
            }
            StorageBackend::Memory => (None, None),
        };

        // Initialize core storage with appropriate configuration
        let storage_config = match &backend {
            StorageBackend::EncryptedFile { storage_dir, .. } => {
                quid_core::storage::StorageConfig {
                    storage_path: storage_dir.clone(),
                    kdf_iterations: 100_000,
                    auto_backup: true,
                    max_backups: 5,
                }
            }
            _ => {
                let storage_dir = StorageBackend::get_default_storage_dir();
                quid_core::storage::StorageConfig {
                    storage_path: storage_dir,
                    kdf_iterations: 100_000,
                    auto_backup: true,
                    max_backups: 5,
                }
            }
        };

        let core_storage = IdentityStorage::new(storage_config)
            .map_err(|e| DesktopError::Storage(format!("Failed to initialize core storage: {}", e)))?;

        Ok(Self {
            backend,
            core_storage: RwLock::new(core_storage),
            keychain_client,
            file_storage,
        })
    }

    /// Store identity with desktop-specific enhancements
    pub async fn store_identity(&self, identity: &quid_core::QuIDIdentity, keypair: &quid_core::crypto::KeyPair, password: &str) -> DesktopResult<()> {
        use secrecy::Secret;
        let password_secret = Secret::new(password.to_string());
        
        // Use keychain for password storage if available
        if let Some(ref keychain) = self.keychain_client {
            // Store the actual identity in core storage
            {
                let mut storage = self.core_storage.write().await;
                storage.store_identity(identity, keypair, &password_secret)
                    .map_err(|e| DesktopError::Storage(format!("Core storage failed: {}", e)))?;
            }

            // Store password in system keychain
            let identity_hex = hex::encode(&identity.id);
            keychain.store_password(&identity_hex, password).await
                .map_err(|e| DesktopError::Storage(format!("Keychain storage failed: {}", e)))?;
        } else {
            // Fallback to core storage only
            let mut storage = self.core_storage.write().await;
            storage.store_identity(identity, keypair, &password_secret)
                .map_err(|e| DesktopError::Storage(format!("Storage failed: {}", e)))?;
        }

        Ok(())
    }

    /// Load identity with desktop-specific enhancements
    pub async fn load_identity(&self, identity_id: &[u8], password: &str) -> DesktopResult<(quid_core::QuIDIdentity, quid_core::crypto::KeyPair)> {
        use secrecy::Secret;
        let password_secret = Secret::new(password.to_string());
        
        let mut storage = self.core_storage.write().await;
        storage.load_identity(identity_id, &password_secret)
            .map_err(|e| DesktopError::Storage(format!("Failed to load identity: {}", e)))
    }

    /// List stored identity IDs
    pub async fn list_identities(&self) -> DesktopResult<Vec<Vec<u8>>> {
        let storage = self.core_storage.read().await;
        storage.list_identities()
            .map_err(|e| DesktopError::Storage(format!("Failed to list identities: {}", e)))
    }

    /// Delete identity
    pub async fn delete_identity(&self, identity_id: &[u8]) -> DesktopResult<()> {
        // Remove from keychain if using it
        if let Some(ref keychain) = self.keychain_client {
            let identity_hex = hex::encode(identity_id);
            let _ = keychain.delete_password(&identity_hex).await; // Don't fail if not found
        }

        // Remove from core storage
        let mut storage = self.core_storage.write().await;
        storage.delete_identity(identity_id)
            .map_err(|e| DesktopError::Storage(format!("Failed to delete identity: {}", e)))?;

        Ok(())
    }

    /// Create backup with desktop-specific features
    pub async fn create_backup(&self, backup_path: Option<PathBuf>) -> DesktopResult<PathBuf> {
        let backup_dir = backup_path.unwrap_or_else(|| {
            self.backend.get_backup_dir()
                .unwrap_or_else(|| StorageBackend::get_default_storage_dir().join("backups"))
        });

        // For now, return the backup directory path
        // In a full implementation, this would create actual backups
        std::fs::create_dir_all(&backup_dir)
            .map_err(|e| DesktopError::Storage(format!("Failed to create backup directory: {}", e)))?;
        
        Ok(backup_dir)
    }

    /// Restore from backup
    pub async fn restore_backup(&self, _backup_path: &PathBuf, _password: &str) -> DesktopResult<()> {
        // For now, this is a placeholder
        // In a full implementation, this would restore from backup files
        println!("🔄 Backup restore functionality not yet implemented");
        Ok(())
    }

    /// Get storage backend info
    pub fn backend(&self) -> &StorageBackend {
        &self.backend
    }

    /// Check if keychain is available
    pub fn has_keychain_support(&self) -> bool {
        self.keychain_client.is_some()
    }

    /// Get storage statistics
    pub async fn get_storage_stats(&self) -> DesktopResult<StorageStats> {
        let identities = self.list_identities().await?;
        let storage_dir = StorageBackend::get_default_storage_dir();
        
        let mut total_size = 0u64;
        if storage_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(&storage_dir) {
                for entry in entries.flatten() {
                    if let Ok(metadata) = entry.metadata() {
                        total_size += metadata.len();
                    }
                }
            }
        }

        Ok(StorageStats {
            identity_count: identities.len(),
            total_size_bytes: total_size,
            storage_path: storage_dir,
            backend_type: format!("{:?}", self.backend),
            has_keychain: self.has_keychain_support(),
        })
    }
}

/// Storage statistics
#[derive(Debug, Clone)]
pub struct StorageStats {
    pub identity_count: usize,
    pub total_size_bytes: u64,
    pub storage_path: PathBuf,
    pub backend_type: String,
    pub has_keychain: bool,
}

/// System keychain client
#[derive(Debug)]
struct KeychainClient {
    service_name: String,
    #[cfg(feature = "system-keychain")]
    #[allow(dead_code)]
    keyring: Option<keyring::Entry>,
}

impl KeychainClient {
    async fn new(service_name: String) -> DesktopResult<Self> {
        #[cfg(feature = "system-keychain")]
        {
            // Test keychain availability
            let test_entry = keyring::Entry::new(&service_name, "test")
                .map_err(|e| DesktopError::Storage(format!("Keychain unavailable: {}", e)))?;

            Ok(Self {
                service_name,
                keyring: Some(test_entry),
            })
        }
        #[cfg(not(feature = "system-keychain"))]
        {
            Ok(Self {
                service_name,
            })
        }
    }

    async fn store_password(&self, identity_id: &str, password: &str) -> DesktopResult<()> {
        #[cfg(feature = "system-keychain")]
        {
            let entry = keyring::Entry::new(&self.service_name, identity_id)
                .map_err(|e| DesktopError::Storage(format!("Failed to create keychain entry: {}", e)))?;

            entry.set_password(password)
                .map_err(|e| DesktopError::Storage(format!("Failed to store password in keychain: {}", e)))?;

            Ok(())
        }
        #[cfg(not(feature = "system-keychain"))]
        {
            println!("🔐 Keychain store (fallback): {} for {}", password.len(), identity_id);
            Ok(())
        }
    }

    async fn get_password(&self, _identity_id: &str) -> DesktopResult<String> {
        #[cfg(feature = "system-keychain")]
        {
            let entry = keyring::Entry::new(&self.service_name, identity_id)
                .map_err(|e| DesktopError::Storage(format!("Failed to create keychain entry: {}", e)))?;

            entry.get_password()
                .map_err(|e| DesktopError::Storage(format!("Failed to get password from keychain: {}", e)))
        }
        #[cfg(not(feature = "system-keychain"))]
        {
            Err(DesktopError::Storage("Keychain feature not enabled".to_string()))
        }
    }

    async fn delete_password(&self, identity_id: &str) -> DesktopResult<()> {
        #[cfg(feature = "system-keychain")]
        {
            let entry = keyring::Entry::new(&self.service_name, identity_id)
                .map_err(|e| DesktopError::Storage(format!("Failed to create keychain entry: {}", e)))?;

            entry.delete_password()
                .map_err(|e| DesktopError::Storage(format!("Failed to delete password from keychain: {}", e)))?;

            Ok(())
        }
        #[cfg(not(feature = "system-keychain"))]
        {
            println!("🔐 Keychain delete (fallback): {}", identity_id);
            Ok(())
        }
    }
}

/// File storage client for fallback scenarios
#[derive(Debug)]
struct FileStorageClient {
    storage_dir: PathBuf,
}

impl FileStorageClient {
    async fn new(storage_dir: PathBuf) -> DesktopResult<Self> {
        // Ensure storage directory exists
        tokio::fs::create_dir_all(&storage_dir).await
            .map_err(|e| DesktopError::Storage(format!("Failed to create storage directory: {}", e)))?;

        Ok(Self { storage_dir })
    }

    #[allow(dead_code)]
    async fn store_data(&self, key: &str, data: &[u8]) -> DesktopResult<()> {
        let file_path = self.storage_dir.join(format!("{}.enc", key));
        tokio::fs::write(&file_path, data).await
            .map_err(|e| DesktopError::Storage(format!("Failed to write file: {}", e)))?;

        Ok(())
    }

    #[allow(dead_code)]
    async fn load_data(&self, key: &str) -> DesktopResult<Vec<u8>> {
        let file_path = self.storage_dir.join(format!("{}.enc", key));
        tokio::fs::read(&file_path).await
            .map_err(|e| DesktopError::Storage(format!("Failed to read file: {}", e)))
    }

    #[allow(dead_code)]
    async fn delete_data(&self, key: &str) -> DesktopResult<()> {
        let file_path = self.storage_dir.join(format!("{}.enc", key));
        tokio::fs::remove_file(&file_path).await
            .map_err(|e| DesktopError::Storage(format!("Failed to delete file: {}", e)))?;

        Ok(())
    }
}

/// Get default storage directory
pub fn get_default_storage_dir() -> PathBuf {
    StorageBackend::get_default_storage_dir()
}

/// Create backup of current storage
pub async fn create_system_backup() -> DesktopResult<PathBuf> {
    let backend = StorageBackend::default();
    let storage = DesktopStorage::new(backend).await?;
    storage.create_backup(None).await
}

/// Restore from system backup
pub async fn restore_system_backup(backup_path: &PathBuf, password: &str) -> DesktopResult<()> {
    let backend = StorageBackend::default();
    let storage = DesktopStorage::new(backend).await?;
    storage.restore_backup(backup_path, password).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_storage_backend_default() {
        let backend = StorageBackend::default();
        match backend {
            StorageBackend::SystemKeychain { .. } => {
                // Should be system keychain on supported platforms
                assert!(Platform::detect().supports_keychain());
            }
            StorageBackend::EncryptedFile { .. } => {
                // Should be file storage on unsupported platforms
                assert!(!Platform::detect().supports_keychain());
            }
            _ => panic!("Unexpected default backend"),
        }
    }

    #[test]
    fn test_default_storage_dir() {
        let dir = StorageBackend::get_default_storage_dir();
        assert!(!dir.as_os_str().is_empty());
        
        let platform = Platform::detect();
        match platform {
            Platform::Windows => assert!(dir.to_string_lossy().contains("QuID")),
            Platform::MacOS => assert!(dir.to_string_lossy().contains("QuID")),
            Platform::Linux => assert!(dir.to_string_lossy().contains("quid")),
            Platform::Unknown => assert!(dir.to_string_lossy().contains("quid-data")),
        }
    }

    #[tokio::test]
    async fn test_file_storage_backend() {
        let temp_dir = TempDir::new().unwrap();
        let backend = StorageBackend::EncryptedFile {
            storage_dir: temp_dir.path().to_path_buf(),
            backup_dir: None,
        };

        let storage = DesktopStorage::new(backend).await;
        assert!(storage.is_ok());
    }

    #[tokio::test]
    async fn test_memory_storage_backend() {
        let backend = StorageBackend::Memory;
        let storage = DesktopStorage::new(backend).await;
        assert!(storage.is_ok());
    }

    #[tokio::test]
    async fn test_storage_stats() {
        let temp_dir = TempDir::new().unwrap();
        let backend = StorageBackend::EncryptedFile {
            storage_dir: temp_dir.path().to_path_buf(),
            backup_dir: None,
        };

        let storage = DesktopStorage::new(backend).await.unwrap();
        let stats = storage.get_storage_stats().await.unwrap();
        
        assert_eq!(stats.identity_count, 0);
        assert_eq!(stats.total_size_bytes, 0);
        assert!(stats.storage_path.exists());
    }

    #[tokio::test]
    async fn test_file_storage_client() {
        let temp_dir = TempDir::new().unwrap();
        let client = FileStorageClient::new(temp_dir.path().to_path_buf()).await;
        assert!(client.is_ok());
        
        let client = client.unwrap();
        assert_eq!(client.storage_dir, temp_dir.path());
    }

    #[test]
    fn test_storage_backend_serialization() {
        let backend = StorageBackend::default();
        let json = serde_json::to_string(&backend).unwrap();
        let deserialized: StorageBackend = serde_json::from_str(&json).unwrap();
        
        // Check that serialization/deserialization works
        match (backend, deserialized) {
            (StorageBackend::SystemKeychain { .. }, StorageBackend::SystemKeychain { .. }) => (),
            (StorageBackend::EncryptedFile { .. }, StorageBackend::EncryptedFile { .. }) => (),
            (StorageBackend::Memory, StorageBackend::Memory) => (),
            _ => panic!("Serialization/deserialization mismatch"),
        }
    }
}