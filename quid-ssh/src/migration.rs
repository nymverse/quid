//! SSH key migration tools for QuID
//!
//! This module provides tools to migrate from traditional SSH keys to QuID identities
//! while maintaining compatibility with existing SSH infrastructure.

use anyhow::Result;
use quid_core::{QuIDClient, QuIDIdentity, SecurityLevel};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

use crate::keys::{KeyConversion, QuIDSSHKey, SSHKeyType};
use crate::{QuIDSSHError, QuIDSSHResult};

/// Migration options and configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationOptions {
    /// Source SSH key directory (e.g., ~/.ssh)
    pub source_directory: PathBuf,
    /// Target QuID key directory
    pub target_directory: PathBuf,
    /// Whether to backup original keys
    pub backup_original_keys: bool,
    /// Backup directory for original keys
    pub backup_directory: Option<PathBuf>,
    /// Whether to preserve key comments
    pub preserve_comments: bool,
    /// Default security level for migrated identities
    pub default_security_level: SecurityLevel,
    /// Whether to migrate private keys (create QuID equivalents)
    pub migrate_private_keys: bool,
    /// Whether to migrate authorized_keys files
    pub migrate_authorized_keys: bool,
    /// Whether to migrate known_hosts files
    pub migrate_known_hosts: bool,
    /// Key type preferences for migration
    pub key_type_mapping: HashMap<String, SecurityLevel>,
    /// Skip keys that already have QuID equivalents
    pub skip_existing: bool,
    /// Dry run mode (don't actually perform migration)
    pub dry_run: bool,
}

impl Default for MigrationOptions {
    fn default() -> Self {
        let mut key_type_mapping = HashMap::new();
        key_type_mapping.insert("ssh-ed25519".to_string(), SecurityLevel::Level1);
        key_type_mapping.insert("ecdsa-sha2-nistp256".to_string(), SecurityLevel::Level1);
        key_type_mapping.insert("ecdsa-sha2-nistp384".to_string(), SecurityLevel::Level2);
        key_type_mapping.insert("ecdsa-sha2-nistp521".to_string(), SecurityLevel::Level3);
        key_type_mapping.insert("ssh-rsa".to_string(), SecurityLevel::Level1);

        Self {
            source_directory: dirs::home_dir().unwrap_or_default().join(".ssh"),
            target_directory: dirs::home_dir().unwrap_or_default().join(".ssh").join("quid"),
            backup_original_keys: true,
            backup_directory: None,
            preserve_comments: true,
            default_security_level: SecurityLevel::Level1,
            migrate_private_keys: true,
            migrate_authorized_keys: true,
            migrate_known_hosts: true,
            key_type_mapping,
            skip_existing: true,
            dry_run: false,
        }
    }
}

/// Migration result information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationResult {
    /// Number of keys successfully migrated
    pub migrated_keys: usize,
    /// Number of keys skipped
    pub skipped_keys: usize,
    /// Number of keys that failed to migrate
    pub failed_keys: usize,
    /// Details of migrated keys
    pub migrated_identities: Vec<MigratedIdentity>,
    /// Migration errors
    pub errors: Vec<MigrationError>,
    /// Warnings during migration
    pub warnings: Vec<String>,
    /// Total migration time
    pub migration_time: std::time::Duration,
}

/// Information about a migrated identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigratedIdentity {
    /// Original SSH key path
    pub original_key_path: PathBuf,
    /// Original SSH key type
    pub original_key_type: String,
    /// QuID identity ID
    pub quid_identity_id: String,
    /// QuID identity name
    pub quid_identity_name: String,
    /// Security level used
    pub security_level: SecurityLevel,
    /// Generated QuID SSH key path
    pub quid_key_path: PathBuf,
}

/// Migration error information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationError {
    /// Key path that failed
    pub key_path: PathBuf,
    /// Error message
    pub error: String,
    /// Error category
    pub category: ErrorCategory,
}

/// Error categories for migration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ErrorCategory {
    /// File I/O error
    IoError,
    /// Key parsing error
    KeyParsingError,
    /// QuID operation error
    QuIDError,
    /// Unsupported key type
    UnsupportedKeyType,
    /// Permission error
    PermissionError,
}

/// SSH key migration engine
pub struct SSHKeyMigrator {
    quid_client: Arc<QuIDClient>,
    options: MigrationOptions,
}

impl SSHKeyMigrator {
    /// Create a new SSH key migrator
    pub fn new(quid_client: Arc<QuIDClient>, options: MigrationOptions) -> Self {
        Self {
            quid_client,
            options,
        }
    }

    /// Perform the migration
    pub async fn migrate(&self) -> QuIDSSHResult<MigrationResult> {
        let start_time = std::time::Instant::now();
        
        info!("Starting SSH key migration from {} to {}", 
            self.options.source_directory.display(),
            self.options.target_directory.display()
        );

        if self.options.dry_run {
            info!("Running in DRY RUN mode - no changes will be made");
        }

        let mut result = MigrationResult {
            migrated_keys: 0,
            skipped_keys: 0,
            failed_keys: 0,
            migrated_identities: Vec::new(),
            errors: Vec::new(),
            warnings: Vec::new(),
            migration_time: std::time::Duration::default(),
        };

        // Create target directory
        if !self.options.dry_run {
            if let Err(e) = std::fs::create_dir_all(&self.options.target_directory) {
                return Err(QuIDSSHError::MigrationFailed(
                    format!("Failed to create target directory: {}", e)
                ));
            }
        }

        // Find SSH keys to migrate
        let ssh_keys = self.discover_ssh_keys()?;
        info!("Found {} SSH keys to process", ssh_keys.len());

        // Migrate each key
        for key_info in ssh_keys {
            match self.migrate_single_key(&key_info).await {
                Ok(Some(migrated)) => {
                    result.migrated_keys += 1;
                    result.migrated_identities.push(migrated);
                }
                Ok(None) => {
                    result.skipped_keys += 1;
                }
                Err(e) => {
                    result.failed_keys += 1;
                    result.errors.push(MigrationError {
                        key_path: key_info.path.clone(),
                        error: e.to_string(),
                        category: self.categorize_error(&e),
                    });
                    warn!("Failed to migrate key {}: {}", key_info.path.display(), e);
                }
            }
        }

        // Migrate authorized_keys if requested
        if self.options.migrate_authorized_keys {
            if let Err(e) = self.migrate_authorized_keys().await {
                result.warnings.push(format!("Failed to migrate authorized_keys: {}", e));
            }
        }

        // Migrate known_hosts if requested
        if self.options.migrate_known_hosts {
            if let Err(e) = self.migrate_known_hosts().await {
                result.warnings.push(format!("Failed to migrate known_hosts: {}", e));
            }
        }

        result.migration_time = start_time.elapsed();

        info!(
            "Migration completed: {} migrated, {} skipped, {} failed in {:?}",
            result.migrated_keys,
            result.skipped_keys,
            result.failed_keys,
            result.migration_time
        );

        Ok(result)
    }

    /// Discover SSH keys in the source directory
    fn discover_ssh_keys(&self) -> QuIDSSHResult<Vec<SSHKeyInfo>> {
        let mut keys = Vec::new();

        if !self.options.source_directory.exists() {
            return Ok(keys);
        }

        let entries = std::fs::read_dir(&self.options.source_directory)
            .map_err(|e| QuIDSSHError::IoError(e))?;

        for entry in entries {
            let entry = entry.map_err(|e| QuIDSSHError::IoError(e))?;
            let path = entry.path();

            // Skip directories and dot files
            if path.is_dir() || path.file_name().unwrap().to_string_lossy().starts_with('.') {
                continue;
            }

            // Check if this looks like an SSH public key
            if let Some(extension) = path.extension() {
                if extension == "pub" {
                    if let Ok(key_info) = self.analyze_ssh_key(&path) {
                        keys.push(key_info);
                    }
                }
            }
        }

        Ok(keys)
    }

    /// Analyze an SSH key file
    fn analyze_ssh_key(&self, path: &Path) -> QuIDSSHResult<SSHKeyInfo> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| QuIDSSHError::IoError(e))?;

        let parts: Vec<&str> = content.trim().split_whitespace().collect();
        if parts.len() < 2 {
            return Err(QuIDSSHError::KeyConversionFailed(
                "Invalid SSH key format".to_string()
            ));
        }

        let key_type = parts[0].to_string();
        let key_data = parts[1].to_string();
        let comment = if parts.len() > 2 {
            parts[2..].join(" ")
        } else {
            String::new()
        };

        // Try to find corresponding private key
        let private_key_path = if path.extension() == Some(std::ffi::OsStr::new("pub")) {
            let private_path = path.with_extension("");
            if private_path.exists() {
                Some(private_path)
            } else {
                None
            }
        } else {
            None
        };

        Ok(SSHKeyInfo {
            path: path.to_path_buf(),
            private_key_path,
            key_type,
            key_data,
            comment,
        })
    }

    /// Migrate a single SSH key
    async fn migrate_single_key(&self, key_info: &SSHKeyInfo) -> QuIDSSHResult<Option<MigratedIdentity>> {
        debug!("Migrating SSH key: {}", key_info.path.display());

        // Check if we should skip this key
        if self.options.skip_existing {
            let identity_name = self.generate_identity_name(key_info);
            let existing_identities = self.quid_client.list_identities().await
                .map_err(|e| QuIDSSHError::QuIDCoreError(e))?;
            
            if existing_identities.iter().any(|id| id.name == identity_name) {
                debug!("Skipping key {} - QuID identity already exists", key_info.path.display());
                return Ok(None);
            }
        }

        // Determine security level
        let security_level = self.options.key_type_mapping
            .get(&key_info.key_type)
            .cloned()
            .unwrap_or(self.options.default_security_level);

        // Generate identity name
        let identity_name = self.generate_identity_name(key_info);

        // Create QuID identity (if not dry run)
        if !self.options.dry_run {
            let identity = KeyConversion::import_ssh_key(
                &self.quid_client,
                &key_info.path,
                &identity_name,
            ).await?;

            // Generate QuID SSH key
            let quid_key = QuIDSSHKey::from_identity(&self.quid_client, &identity).await?;

            // Export QuID SSH key pair
            let (public_key_path, private_key_path) = KeyConversion::export_ssh_key_pair(
                &self.quid_client,
                &identity,
                &self.options.target_directory,
            ).await?;

            // Backup original keys if requested
            if self.options.backup_original_keys {
                self.backup_original_key(key_info).await?;
            }

            let migrated = MigratedIdentity {
                original_key_path: key_info.path.clone(),
                original_key_type: key_info.key_type.clone(),
                quid_identity_id: identity.id.clone(),
                quid_identity_name: identity.name.clone(),
                security_level,
                quid_key_path: public_key_path,
            };

            info!("Successfully migrated {} to QuID identity {}", 
                key_info.path.display(), identity.name);

            Ok(Some(migrated))
        } else {
            // Dry run - just log what would happen
            info!("DRY RUN: Would migrate {} to QuID identity {} with security level {:?}",
                key_info.path.display(), identity_name, security_level);
            
            Ok(Some(MigratedIdentity {
                original_key_path: key_info.path.clone(),
                original_key_type: key_info.key_type.clone(),
                quid_identity_id: "dry-run-id".to_string(),
                quid_identity_name: identity_name,
                security_level,
                quid_key_path: self.options.target_directory.join("dry-run-key.pub"),
            }))
        }
    }

    /// Generate a unique identity name from SSH key info
    fn generate_identity_name(&self, key_info: &SSHKeyInfo) -> String {
        let base_name = if self.options.preserve_comments && !key_info.comment.is_empty() {
            // Use comment as base name
            key_info.comment.clone()
        } else {
            // Use filename as base name
            key_info.path.file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string()
        };

        // Sanitize the name
        let sanitized = base_name
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect::<String>();

        format!("ssh-migrated-{}", sanitized)
    }

    /// Backup original SSH key
    async fn backup_original_key(&self, key_info: &SSHKeyInfo) -> QuIDSSHResult<()> {
        let backup_dir = self.options.backup_directory
            .as_ref()
            .cloned()
            .unwrap_or_else(|| self.options.source_directory.join("backup"));

        if !backup_dir.exists() {
            std::fs::create_dir_all(&backup_dir)
                .map_err(|e| QuIDSSHError::IoError(e))?;
        }

        // Backup public key
        let backup_pub_path = backup_dir.join(key_info.path.file_name().unwrap());
        std::fs::copy(&key_info.path, &backup_pub_path)
            .map_err(|e| QuIDSSHError::IoError(e))?;

        // Backup private key if it exists
        if let Some(private_path) = &key_info.private_key_path {
            let backup_priv_path = backup_dir.join(private_path.file_name().unwrap());
            std::fs::copy(private_path, &backup_priv_path)
                .map_err(|e| QuIDSSHError::IoError(e))?;
        }

        debug!("Backed up SSH key to {}", backup_pub_path.display());
        Ok(())
    }

    /// Migrate authorized_keys file
    async fn migrate_authorized_keys(&self) -> QuIDSSHResult<()> {
        let auth_keys_path = self.options.source_directory.join("authorized_keys");
        if !auth_keys_path.exists() {
            return Ok(());
        }

        info!("Migrating authorized_keys file");

        let content = std::fs::read_to_string(&auth_keys_path)
            .map_err(|e| QuIDSSHError::IoError(e))?;

        let mut quid_entries = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                quid_entries.push(line.to_string());
                continue;
            }

            // Parse SSH key entry
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let key_type = parts[0];
                let key_data = parts[1];
                let comment = if parts.len() > 2 { parts[2] } else { "migrated" };

                // Add QuID equivalent
                let quid_comment = format!("quid-equivalent-{}", comment);
                quid_entries.push(format!("# Original: {}", line));
                quid_entries.push(format!("quid-ml-dsa {} {}", key_data, quid_comment));
            }
        }

        // Write updated authorized_keys
        let quid_auth_keys_path = self.options.target_directory.join("authorized_keys");
        if !self.options.dry_run {
            std::fs::write(&quid_auth_keys_path, quid_entries.join("\n"))
                .map_err(|e| QuIDSSHError::IoError(e))?;

            // Set appropriate permissions
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&quid_auth_keys_path, std::fs::Permissions::from_mode(0o600))
                    .map_err(|e| QuIDSSHError::IoError(e))?;
            }
        }

        info!("Migrated authorized_keys to {}", quid_auth_keys_path.display());
        Ok(())
    }

    /// Migrate known_hosts file
    async fn migrate_known_hosts(&self) -> QuIDSSHResult<()> {
        let known_hosts_path = self.options.source_directory.join("known_hosts");
        if !known_hosts_path.exists() {
            return Ok(());
        }

        info!("Migrating known_hosts file");

        let content = std::fs::read_to_string(&known_hosts_path)
            .map_err(|e| QuIDSSHError::IoError(e))?;

        let mut quid_entries = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                quid_entries.push(line.to_string());
                continue;
            }

            // Add original entry as comment
            quid_entries.push(format!("# Original: {}", line));

            // Parse and convert to QuID format
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let host = parts[0];
                let key_type = parts[1];
                let key_data = parts[2];

                // Add QuID equivalent entry
                quid_entries.push(format!("{} quid-ml-dsa {}", host, key_data));
            }
        }

        // Write updated known_hosts
        let quid_known_hosts_path = self.options.target_directory.join("known_hosts");
        if !self.options.dry_run {
            std::fs::write(&quid_known_hosts_path, quid_entries.join("\n"))
                .map_err(|e| QuIDSSHError::IoError(e))?;

            // Set appropriate permissions
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&quid_known_hosts_path, std::fs::Permissions::from_mode(0o644))
                    .map_err(|e| QuIDSSHError::IoError(e))?;
            }
        }

        info!("Migrated known_hosts to {}", quid_known_hosts_path.display());
        Ok(())
    }

    /// Categorize migration errors
    fn categorize_error(&self, error: &QuIDSSHError) -> ErrorCategory {
        match error {
            QuIDSSHError::IoError(_) => ErrorCategory::IoError,
            QuIDSSHError::KeyConversionFailed(_) => ErrorCategory::KeyParsingError,
            QuIDSSHError::QuIDCoreError(_) => ErrorCategory::QuIDError,
            QuIDSSHError::ConfigurationError(_) => ErrorCategory::PermissionError,
            _ => ErrorCategory::IoError,
        }
    }
}

/// SSH key information
#[derive(Debug, Clone)]
struct SSHKeyInfo {
    path: PathBuf,
    private_key_path: Option<PathBuf>,
    key_type: String,
    key_data: String,
    comment: String,
}

use std::sync::Arc;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_migration_options_default() {
        let options = MigrationOptions::default();
        assert!(options.backup_original_keys);
        assert!(options.preserve_comments);
        assert_eq!(options.default_security_level, SecurityLevel::Level1);
        assert!(!options.dry_run);
    }

    #[test]
    fn test_error_categorization() {
        let quid_client = Arc::new(QuIDClient::new(Default::default()).unwrap());
        let migrator = SSHKeyMigrator::new(quid_client, MigrationOptions::default());

        let io_error = QuIDSSHError::IoError(std::io::Error::new(std::io::ErrorKind::NotFound, "file not found"));
        assert_eq!(migrator.categorize_error(&io_error), ErrorCategory::IoError);

        let key_error = QuIDSSHError::KeyConversionFailed("invalid key".to_string());
        assert_eq!(migrator.categorize_error(&key_error), ErrorCategory::KeyParsingError);
    }

    #[test]
    fn test_migration_result() {
        let result = MigrationResult {
            migrated_keys: 5,
            skipped_keys: 2,
            failed_keys: 1,
            migrated_identities: Vec::new(),
            errors: Vec::new(),
            warnings: Vec::new(),
            migration_time: std::time::Duration::from_secs(10),
        };

        assert_eq!(result.migrated_keys, 5);
        assert_eq!(result.skipped_keys, 2);
        assert_eq!(result.failed_keys, 1);
    }
}