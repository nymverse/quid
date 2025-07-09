//! Type definitions for QuID multi-signature recovery

use quid_core::QuIDIdentity;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use uuid::Uuid;

/// Recovery type enumeration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RecoveryType {
    SecretSharing,
    ThresholdSignature,
    SocialRecovery,
    TimeLock,
}

/// Recovery method enumeration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RecoveryMethod {
    ShamirSecretSharing,
    ThresholdBLS,
    SocialConsensus,
    TimeLockRelease,
    EmergencyRecovery,
}

/// Recovery status enumeration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RecoveryStatus {
    Pending,
    InProgress,
    Ready,
    Completed,
    Failed,
    Cancelled,
    Expired,
}

/// Signature type enumeration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SignatureType {
    Regular,
    Threshold,
    Social,
    Emergency,
}

/// Recovery setup configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverySetup {
    /// Recovery type
    pub recovery_type: RecoveryType,
    /// Master secret for recovery
    pub master_secret: Vec<u8>,
    /// Threshold for recovery
    pub threshold: u32,
    /// Total number of shares
    pub total_shares: u32,
    /// Recovery participants
    pub participants: Vec<QuIDIdentity>,
    /// Trusted contacts for social recovery
    pub trusted_contacts: Vec<TrustedContact>,
    /// Social recovery threshold
    pub social_threshold: u32,
    /// Time-lock duration in seconds
    pub timelock_duration: u64,
    /// Emergency contacts
    pub emergency_contacts: Vec<EmergencyContact>,
}

/// Trusted contact for social recovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedContact {
    /// Contact identity
    pub identity: QuIDIdentity,
    /// Contact name
    pub name: String,
    /// Contact email
    pub email: Option<String>,
    /// Contact phone
    pub phone: Option<String>,
    /// Trust level (0-100)
    pub trust_level: u8,
    /// Contact role
    pub role: ContactRole,
    /// Added timestamp
    pub added_at: DateTime<Utc>,
    /// Last verified timestamp
    pub last_verified: Option<DateTime<Utc>>,
}

/// Emergency contact for time-lock recovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyContact {
    /// Contact identity
    pub identity: QuIDIdentity,
    /// Contact name
    pub name: String,
    /// Contact details
    pub contact_details: ContactDetails,
    /// Authorization level
    pub authorization_level: AuthorizationLevel,
    /// Added timestamp
    pub added_at: DateTime<Utc>,
}

/// Contact role enumeration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ContactRole {
    Family,
    Friend,
    Colleague,
    Professional,
    Guardian,
    Backup,
}

/// Authorization level enumeration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AuthorizationLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Contact details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactDetails {
    /// Email address
    pub email: Option<String>,
    /// Phone number
    pub phone: Option<String>,
    /// Backup communication method
    pub backup_method: Option<String>,
    /// Verification required
    pub verification_required: bool,
}

/// Recovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryConfiguration {
    /// Configuration ID
    pub id: String,
    /// Recovery type
    pub recovery_type: RecoveryType,
    /// Threshold for recovery
    pub threshold: u32,
    /// Total shares
    pub total_shares: u32,
    /// Secret shares
    pub secret_shares: Vec<EncryptedShare>,
    /// Threshold configuration
    pub threshold_config: ThresholdConfig,
    /// Social recovery configuration
    pub social_config: SocialConfig,
    /// Time-lock configuration
    pub timelock_config: TimeLockConfig,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Last updated timestamp
    pub last_updated: DateTime<Utc>,
}

/// Encrypted share for secret sharing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedShare {
    /// Share ID
    pub id: u32,
    /// Encrypted share data
    pub encrypted_data: Vec<u8>,
    /// Share holder identity
    pub holder: QuIDIdentity,
    /// Encryption nonce
    pub nonce: Vec<u8>,
    /// Verification hash
    pub verification_hash: Vec<u8>,
}

/// Threshold configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    /// Threshold value
    pub threshold: u32,
    /// Participant public keys
    pub participants: Vec<ParticipantKey>,
    /// Threshold scheme parameters
    pub scheme_params: ThresholdSchemeParams,
}

/// Participant key information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantKey {
    /// Participant identity
    pub identity: QuIDIdentity,
    /// Public key for threshold scheme
    pub public_key: Vec<u8>,
    /// Key index
    pub index: u32,
    /// Key weight
    pub weight: u32,
}

/// Threshold scheme parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdSchemeParams {
    /// Scheme type
    pub scheme_type: String,
    /// Curve parameters
    pub curve_params: HashMap<String, String>,
    /// Generator point
    pub generator: Vec<u8>,
    /// Group order
    pub group_order: Vec<u8>,
}

/// Social recovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialConfig {
    /// Social threshold
    pub threshold: u32,
    /// Trusted contacts
    pub trusted_contacts: Vec<TrustedContact>,
    /// Verification requirements
    pub verification_requirements: VerificationRequirements,
    /// Recovery window in seconds
    pub recovery_window: u64,
}

/// Verification requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationRequirements {
    /// Require identity verification
    pub identity_verification: bool,
    /// Require multi-factor authentication
    pub multi_factor_auth: bool,
    /// Require video verification
    pub video_verification: bool,
    /// Require document verification
    pub document_verification: bool,
    /// Minimum trust level
    pub minimum_trust_level: u8,
}

/// Time-lock configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeLockConfig {
    /// Lock duration in seconds
    pub duration: u64,
    /// Emergency contacts
    pub emergency_contacts: Vec<EmergencyContact>,
    /// Grace period in seconds
    pub grace_period: u64,
    /// Notification settings
    pub notifications: NotificationSettings,
}

/// Notification settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationSettings {
    /// Enable notifications
    pub enabled: bool,
    /// Notification channels
    pub channels: Vec<NotificationChannel>,
    /// Notification schedule
    pub schedule: NotificationSchedule,
}

/// Notification channel
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NotificationChannel {
    Email,
    SMS,
    Push,
    InApp,
    WebHook,
}

/// Notification schedule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationSchedule {
    /// Immediate notification
    pub immediate: bool,
    /// Reminder intervals in seconds
    pub reminder_intervals: Vec<u64>,
    /// Final warning time in seconds
    pub final_warning: u64,
}

/// Recovery request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryRequest {
    /// Recovery type
    pub recovery_type: RecoveryType,
    /// Request initiator
    pub initiator: QuIDIdentity,
    /// Required signatures
    pub required_signatures: u32,
    /// Timeout in seconds
    pub timeout_seconds: u64,
    /// Recovery data
    pub recovery_data: crate::RecoveryData,
}

/// Recovery proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryProof {
    /// Proof type
    pub proof_type: ProofType,
    /// Proof data
    pub proof_data: Vec<u8>,
    /// Verification data
    pub verification_data: Vec<u8>,
    /// Proof timestamp
    pub timestamp: DateTime<Utc>,
}

/// Proof type enumeration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ProofType {
    SecretSharing,
    ThresholdSignature,
    SocialConsensus,
    TimeLockRelease,
    ZeroKnowledgeProof,
}

/// Recovery audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryAuditEntry {
    /// Entry ID
    pub id: String,
    /// Session ID
    pub session_id: String,
    /// Event type
    pub event_type: AuditEventType,
    /// Actor identity
    pub actor: QuIDIdentity,
    /// Event details
    pub details: HashMap<String, String>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Audit event type enumeration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AuditEventType {
    RecoveryInitiated,
    SignatureAdded,
    RecoveryCompleted,
    RecoveryFailed,
    RecoveryCancelled,
    ThresholdMet,
    TimeLockActivated,
    EmergencyRecoveryTriggered,
}

/// Recovery metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryMetrics {
    /// Total recovery attempts
    pub total_attempts: u64,
    /// Successful recoveries
    pub successful_recoveries: u64,
    /// Failed recoveries
    pub failed_recoveries: u64,
    /// Average recovery time in seconds
    pub avg_recovery_time: f64,
    /// Recovery success rate
    pub success_rate: f64,
    /// Last recovery attempt
    pub last_attempt: Option<DateTime<Utc>>,
}

impl Default for RecoverySetup {
    fn default() -> Self {
        Self {
            recovery_type: RecoveryType::SecretSharing,
            master_secret: Vec::new(),
            threshold: 2,
            total_shares: 3,
            participants: Vec::new(),
            trusted_contacts: Vec::new(),
            social_threshold: 2,
            timelock_duration: 7 * 24 * 3600, // 7 days
            emergency_contacts: Vec::new(),
        }
    }
}

impl Default for RecoveryRequest {
    fn default() -> Self {
        Self {
            recovery_type: RecoveryType::SecretSharing,
            initiator: QuIDIdentity::generate(quid_core::SecurityLevel::High).unwrap(),
            required_signatures: 2,
            timeout_seconds: 3600, // 1 hour
            recovery_data: crate::RecoveryData {
                target_identity: QuIDIdentity::generate(quid_core::SecurityLevel::High).unwrap(),
                method: RecoveryMethod::ShamirSecretSharing,
                encrypted_payload: Vec::new(),
                metadata: HashMap::new(),
            },
        }
    }
}

impl Default for VerificationRequirements {
    fn default() -> Self {
        Self {
            identity_verification: true,
            multi_factor_auth: true,
            video_verification: false,
            document_verification: false,
            minimum_trust_level: 50,
        }
    }
}

impl Default for NotificationSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            channels: vec![NotificationChannel::Email, NotificationChannel::SMS],
            schedule: NotificationSchedule {
                immediate: true,
                reminder_intervals: vec![3600, 7200, 14400], // 1h, 2h, 4h
                final_warning: 300, // 5 minutes
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quid_core::SecurityLevel;
    
    #[test]
    fn test_recovery_setup_default() {
        let setup = RecoverySetup::default();
        assert_eq!(setup.recovery_type, RecoveryType::SecretSharing);
        assert_eq!(setup.threshold, 2);
        assert_eq!(setup.total_shares, 3);
        assert_eq!(setup.timelock_duration, 7 * 24 * 3600);
    }
    
    #[test]
    fn test_recovery_request_default() {
        let request = RecoveryRequest::default();
        assert_eq!(request.recovery_type, RecoveryType::SecretSharing);
        assert_eq!(request.required_signatures, 2);
        assert_eq!(request.timeout_seconds, 3600);
    }
    
    #[test]
    fn test_trusted_contact_creation() {
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        let contact = TrustedContact {
            identity,
            name: "John Doe".to_string(),
            email: Some("john@example.com".to_string()),
            phone: Some("+1234567890".to_string()),
            trust_level: 85,
            role: ContactRole::Family,
            added_at: Utc::now(),
            last_verified: Some(Utc::now()),
        };
        
        assert_eq!(contact.name, "John Doe");
        assert_eq!(contact.trust_level, 85);
        assert_eq!(contact.role, ContactRole::Family);
    }
    
    #[test]
    fn test_verification_requirements_default() {
        let requirements = VerificationRequirements::default();
        assert!(requirements.identity_verification);
        assert!(requirements.multi_factor_auth);
        assert!(!requirements.video_verification);
        assert!(!requirements.document_verification);
        assert_eq!(requirements.minimum_trust_level, 50);
    }
    
    #[test]
    fn test_notification_settings_default() {
        let settings = NotificationSettings::default();
        assert!(settings.enabled);
        assert!(settings.channels.contains(&NotificationChannel::Email));
        assert!(settings.channels.contains(&NotificationChannel::SMS));
        assert!(settings.schedule.immediate);
        assert_eq!(settings.schedule.reminder_intervals.len(), 3);
        assert_eq!(settings.schedule.final_warning, 300);
    }
    
    #[test]
    fn test_recovery_status_serialization() {
        let status = RecoveryStatus::Pending;
        let serialized = serde_json::to_string(&status).unwrap();
        let deserialized: RecoveryStatus = serde_json::from_str(&serialized).unwrap();
        assert_eq!(status, deserialized);
    }
    
    #[test]
    fn test_recovery_type_serialization() {
        let recovery_type = RecoveryType::ThresholdSignature;
        let serialized = serde_json::to_string(&recovery_type).unwrap();
        let deserialized: RecoveryType = serde_json::from_str(&serialized).unwrap();
        assert_eq!(recovery_type, deserialized);
    }
}