//! Configuration for QuID multi-signature recovery

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Multi-signature configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigConfig {
    /// Secret sharing configuration
    pub secret_sharing: SecretSharingConfig,
    /// Threshold signature configuration
    pub threshold: ThresholdConfig,
    /// Social recovery configuration
    pub social: SocialConfig,
    /// Recovery configuration
    pub recovery: RecoveryConfig,
    /// Time-lock configuration
    pub timelock: TimeLockConfig,
    /// Storage configuration
    pub storage: StorageConfig,
}

/// Secret sharing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretSharingConfig {
    /// Default threshold
    pub default_threshold: u32,
    /// Default total shares
    pub default_total_shares: u32,
    /// Share encryption enabled
    pub encryption_enabled: bool,
    /// Share verification enabled
    pub verification_enabled: bool,
}

/// Threshold configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    /// Default threshold
    pub default_threshold: u32,
    /// Signature scheme
    pub signature_scheme: String,
    /// Curve parameters
    pub curve: String,
}

/// Social configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialConfig {
    /// Default social threshold
    pub default_threshold: u32,
    /// Maximum trusted contacts
    pub max_trusted_contacts: u32,
    /// Verification required
    pub verification_required: bool,
}

/// Recovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryConfig {
    /// Default session timeout in seconds
    pub default_timeout: u64,
    /// Maximum active sessions
    pub max_active_sessions: u32,
    /// Cleanup interval in seconds
    pub cleanup_interval: u64,
}

/// Time-lock configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeLockConfig {
    /// Default lock duration in seconds
    pub default_duration: u64,
    /// Grace period in seconds
    pub grace_period: u64,
    /// Notification enabled
    pub notifications_enabled: bool,
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Base directory
    pub base_directory: PathBuf,
    /// Encryption enabled
    pub encryption_enabled: bool,
    /// Backup enabled
    pub backup_enabled: bool,
}

impl Default for MultisigConfig {
    fn default() -> Self {
        Self {
            secret_sharing: SecretSharingConfig::default(),
            threshold: ThresholdConfig::default(),
            social: SocialConfig::default(),
            recovery: RecoveryConfig::default(),
            timelock: TimeLockConfig::default(),
            storage: StorageConfig::default(),
        }
    }
}

impl Default for SecretSharingConfig {
    fn default() -> Self {
        Self {
            default_threshold: 2,
            default_total_shares: 3,
            encryption_enabled: true,
            verification_enabled: true,
        }
    }
}

impl Default for ThresholdConfig {
    fn default() -> Self {
        Self {
            default_threshold: 2,
            signature_scheme: "BLS12-381".to_string(),
            curve: "BLS12-381".to_string(),
        }
    }
}

impl Default for SocialConfig {
    fn default() -> Self {
        Self {
            default_threshold: 2,
            max_trusted_contacts: 10,
            verification_required: true,
        }
    }
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            default_timeout: 3600, // 1 hour
            max_active_sessions: 10,
            cleanup_interval: 300, // 5 minutes
        }
    }
}

impl Default for TimeLockConfig {
    fn default() -> Self {
        Self {
            default_duration: 7 * 24 * 3600, // 7 days
            grace_period: 24 * 3600, // 1 day
            notifications_enabled: true,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            base_directory: dirs::home_dir().unwrap_or_default().join(".quid").join("multisig"),
            encryption_enabled: true,
            backup_enabled: true,
        }
    }
}