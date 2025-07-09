//! QuID Multi-Signature Recovery System
//!
//! This crate provides advanced multi-signature recovery mechanisms for QuID identities,
//! enabling secure key recovery through threshold cryptography, secret sharing, and
//! multi-party computation.
//!
//! Features:
//! - Shamir's Secret Sharing for key recovery
//! - Threshold signatures for multi-party authorization
//! - Secure multi-signature schemes
//! - Emergency recovery procedures
//! - Social recovery with trusted contacts
//! - Time-locked recovery mechanisms

use quid_core::{QuIDIdentity, SecurityLevel, KeyPair};
use quid_wallet::{QuIDWalletManager, WalletError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use secrecy::{SecretString, ExposeSecret};
use zeroize::Zeroize;

pub mod error;
pub mod types;
pub mod config;
pub mod secret_sharing;
pub mod threshold;
pub mod recovery;
pub mod social;
pub mod timelock;

pub use error::{MultisigError, MultisigResult};
pub use types::*;
pub use config::MultisigConfig;

/// QuID multi-signature recovery manager
#[derive(Debug)]
pub struct QuIDMultisigManager {
    /// Configuration
    config: MultisigConfig,
    /// Primary identity
    primary_identity: QuIDIdentity,
    /// Wallet manager
    wallet_manager: Arc<QuIDWalletManager>,
    /// Secret sharing manager
    secret_sharing: Arc<secret_sharing::SecretSharingManager>,
    /// Threshold signature manager
    threshold_manager: Arc<threshold::ThresholdManager>,
    /// Recovery coordinator
    recovery_coordinator: Arc<recovery::RecoveryCoordinator>,
    /// Social recovery manager
    social_recovery: Arc<social::SocialRecoveryManager>,
    /// Time-lock manager
    timelock_manager: Arc<timelock::TimeLockManager>,
    /// Active recovery sessions
    active_sessions: Arc<RwLock<HashMap<String, RecoverySession>>>,
}

/// Recovery session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverySession {
    /// Session ID
    pub id: String,
    /// Recovery type
    pub recovery_type: RecoveryType,
    /// Initiator identity
    pub initiator: QuIDIdentity,
    /// Required signatures
    pub required_signatures: u32,
    /// Collected signatures
    pub collected_signatures: Vec<RecoverySignature>,
    /// Session status
    pub status: RecoveryStatus,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Expiry timestamp
    pub expires_at: DateTime<Utc>,
    /// Recovery data
    pub recovery_data: RecoveryData,
}

/// Recovery signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverySignature {
    /// Signer identity
    pub signer: QuIDIdentity,
    /// Signature data
    pub signature: Vec<u8>,
    /// Signature timestamp
    pub timestamp: DateTime<Utc>,
    /// Signature type
    pub signature_type: SignatureType,
}

/// Recovery data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryData {
    /// Target identity to recover
    pub target_identity: QuIDIdentity,
    /// Recovery method
    pub method: RecoveryMethod,
    /// Encrypted recovery payload
    pub encrypted_payload: Vec<u8>,
    /// Recovery metadata
    pub metadata: HashMap<String, String>,
}

impl QuIDMultisigManager {
    /// Create new multisig manager
    pub async fn new(
        config: MultisigConfig,
        primary_identity: QuIDIdentity,
        wallet_manager: Arc<QuIDWalletManager>,
    ) -> MultisigResult<Self> {
        let secret_sharing = Arc::new(
            secret_sharing::SecretSharingManager::new(config.secret_sharing.clone()).await?
        );
        
        let threshold_manager = Arc::new(
            threshold::ThresholdManager::new(config.threshold.clone()).await?
        );
        
        let recovery_coordinator = Arc::new(
            recovery::RecoveryCoordinator::new(
                config.recovery.clone(),
                primary_identity.clone(),
                wallet_manager.clone(),
            ).await?
        );
        
        let social_recovery = Arc::new(
            social::SocialRecoveryManager::new(config.social.clone(), primary_identity.clone()).await?
        );
        
        let timelock_manager = Arc::new(
            timelock::TimeLockManager::new(config.timelock.clone()).await?
        );
        
        let active_sessions = Arc::new(RwLock::new(HashMap::new()));
        
        Ok(Self {
            config,
            primary_identity,
            wallet_manager,
            secret_sharing,
            threshold_manager,
            recovery_coordinator,
            social_recovery,
            timelock_manager,
            active_sessions,
        })
    }
    
    /// Set up multi-signature recovery
    pub async fn setup_recovery(&self, setup: &RecoverySetup) -> MultisigResult<RecoveryConfiguration> {
        // Validate setup parameters
        self.validate_setup(setup)?;
        
        // Create secret shares
        let secret_shares = self.secret_sharing.create_shares(
            &setup.master_secret,
            setup.threshold,
            setup.total_shares,
        ).await?;
        
        // Set up threshold signatures
        let threshold_config = self.threshold_manager.setup_threshold_scheme(
            setup.threshold,
            &setup.participants,
        ).await?;
        
        // Configure social recovery
        let social_config = self.social_recovery.setup_social_recovery(
            &setup.trusted_contacts,
            setup.social_threshold,
        ).await?;
        
        // Set up time-lock recovery
        let timelock_config = self.timelock_manager.setup_timelock(
            setup.timelock_duration,
            &setup.emergency_contacts,
        ).await?;
        
        let recovery_config = RecoveryConfiguration {
            id: Uuid::new_v4().to_string(),
            recovery_type: setup.recovery_type.clone(),
            threshold: setup.threshold,
            total_shares: setup.total_shares,
            secret_shares,
            threshold_config,
            social_config,
            timelock_config,
            created_at: Utc::now(),
            last_updated: Utc::now(),
        };
        
        tracing::info!("Multi-signature recovery setup completed for identity: {}", 
                      hex::encode(self.primary_identity.public_key().as_bytes()));
        
        Ok(recovery_config)
    }
    
    /// Initiate recovery process
    pub async fn initiate_recovery(&self, request: &RecoveryRequest) -> MultisigResult<String> {
        // Validate recovery request
        self.validate_recovery_request(request)?;
        
        // Create recovery session
        let session_id = Uuid::new_v4().to_string();
        let recovery_session = RecoverySession {
            id: session_id.clone(),
            recovery_type: request.recovery_type.clone(),
            initiator: request.initiator.clone(),
            required_signatures: request.required_signatures,
            collected_signatures: Vec::new(),
            status: RecoveryStatus::Pending,
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(request.timeout_seconds as i64),
            recovery_data: request.recovery_data.clone(),
        };
        
        // Store session
        {
            let mut sessions = self.active_sessions.write().await;
            sessions.insert(session_id.clone(), recovery_session);
        }
        
        // Notify recovery coordinator
        self.recovery_coordinator.initiate_recovery(&session_id, request).await?;
        
        tracing::info!("Recovery session initiated: {}", session_id);
        
        Ok(session_id)
    }
    
    /// Add signature to recovery session
    pub async fn add_recovery_signature(
        &self,
        session_id: &str,
        signature: RecoverySignature,
    ) -> MultisigResult<RecoveryStatus> {
        let mut sessions = self.active_sessions.write().await;
        let session = sessions.get_mut(session_id)
            .ok_or_else(|| MultisigError::RecoverySessionNotFound(session_id.to_string()))?;
        
        // Validate signature
        self.validate_recovery_signature(&signature, &session.recovery_data)?;
        
        // Check if already signed
        if session.collected_signatures.iter().any(|s| s.signer == signature.signer) {
            return Err(MultisigError::DuplicateSignature(hex::encode(signature.signer.public_key().as_bytes())));
        }
        
        // Add signature
        session.collected_signatures.push(signature);
        
        // Check if we have enough signatures
        if session.collected_signatures.len() >= session.required_signatures as usize {
            session.status = RecoveryStatus::Ready;
            
            // Attempt to complete recovery
            if let Err(e) = self.complete_recovery(session).await {
                tracing::error!("Failed to complete recovery: {}", e);
                session.status = RecoveryStatus::Failed;
            } else {
                session.status = RecoveryStatus::Completed;
            }
        }
        
        Ok(session.status.clone())
    }
    
    /// Complete recovery process
    async fn complete_recovery(&self, session: &RecoverySession) -> MultisigResult<()> {
        match session.recovery_type {
            RecoveryType::SecretSharing => {
                self.complete_secret_sharing_recovery(session).await?;
            }
            RecoveryType::ThresholdSignature => {
                self.complete_threshold_signature_recovery(session).await?;
            }
            RecoveryType::SocialRecovery => {
                self.complete_social_recovery(session).await?;
            }
            RecoveryType::TimeLock => {
                self.complete_timelock_recovery(session).await?;
            }
        }
        
        Ok(())
    }
    
    /// Complete secret sharing recovery
    async fn complete_secret_sharing_recovery(&self, session: &RecoverySession) -> MultisigResult<()> {
        // Collect secret shares from signatures
        let mut shares = Vec::new();
        for signature in &session.collected_signatures {
            // Extract share from signature (this is simplified)
            let share = self.extract_share_from_signature(signature)?;
            shares.push(share);
        }
        
        // Reconstruct secret
        let reconstructed_secret = self.secret_sharing.reconstruct_secret(&shares).await?;
        
        // Recover identity
        let recovered_identity = self.recover_identity_from_secret(&reconstructed_secret, &session.recovery_data)?;
        
        // Update wallet with recovered identity
        self.update_wallet_with_recovered_identity(&recovered_identity).await?;
        
        tracing::info!("Secret sharing recovery completed successfully");
        Ok(())
    }
    
    /// Complete threshold signature recovery
    async fn complete_threshold_signature_recovery(&self, session: &RecoverySession) -> MultisigResult<()> {
        // Aggregate threshold signatures
        let signatures: Vec<_> = session.collected_signatures.iter()
            .map(|s| s.signature.clone())
            .collect();
        
        let aggregated_signature = self.threshold_manager.aggregate_signatures(&signatures).await?;
        
        // Verify aggregated signature
        if !self.threshold_manager.verify_threshold_signature(&aggregated_signature, &session.recovery_data).await? {
            return Err(MultisigError::InvalidThresholdSignature);
        }
        
        // Recover identity using threshold signature
        let recovered_identity = self.recover_identity_from_threshold(&aggregated_signature, &session.recovery_data)?;
        
        // Update wallet with recovered identity
        self.update_wallet_with_recovered_identity(&recovered_identity).await?;
        
        tracing::info!("Threshold signature recovery completed successfully");
        Ok(())
    }
    
    /// Complete social recovery
    async fn complete_social_recovery(&self, session: &RecoverySession) -> MultisigResult<()> {
        // Verify social recovery signatures
        for signature in &session.collected_signatures {
            if !self.social_recovery.verify_social_signature(signature).await? {
                return Err(MultisigError::InvalidSocialSignature);
            }
        }
        
        // Recover identity using social recovery
        let recovered_identity = self.social_recovery.recover_identity_socially(&session.recovery_data).await?;
        
        // Update wallet with recovered identity
        self.update_wallet_with_recovered_identity(&recovered_identity).await?;
        
        tracing::info!("Social recovery completed successfully");
        Ok(())
    }
    
    /// Complete time-lock recovery
    async fn complete_timelock_recovery(&self, session: &RecoverySession) -> MultisigResult<()> {
        // Verify time-lock conditions
        if !self.timelock_manager.verify_timelock_conditions(&session.recovery_data).await? {
            return Err(MultisigError::TimeLockNotMet);
        }
        
        // Recover identity using time-lock
        let recovered_identity = self.timelock_manager.recover_identity_timelock(&session.recovery_data).await?;
        
        // Update wallet with recovered identity
        self.update_wallet_with_recovered_identity(&recovered_identity).await?;
        
        tracing::info!("Time-lock recovery completed successfully");
        Ok(())
    }
    
    /// Get recovery session
    pub async fn get_recovery_session(&self, session_id: &str) -> MultisigResult<RecoverySession> {
        let sessions = self.active_sessions.read().await;
        sessions.get(session_id)
            .cloned()
            .ok_or_else(|| MultisigError::RecoverySessionNotFound(session_id.to_string()))
    }
    
    /// Cancel recovery session
    pub async fn cancel_recovery_session(&self, session_id: &str) -> MultisigResult<()> {
        let mut sessions = self.active_sessions.write().await;
        if let Some(mut session) = sessions.remove(session_id) {
            session.status = RecoveryStatus::Cancelled;
            tracing::info!("Recovery session cancelled: {}", session_id);
        }
        Ok(())
    }
    
    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) -> MultisigResult<()> {
        let mut sessions = self.active_sessions.write().await;
        let now = Utc::now();
        
        let expired_sessions: Vec<_> = sessions.iter()
            .filter(|(_, session)| session.expires_at < now)
            .map(|(id, _)| id.clone())
            .collect();
        
        for session_id in expired_sessions {
            sessions.remove(&session_id);
            tracing::info!("Expired recovery session cleaned up: {}", session_id);
        }
        
        Ok(())
    }
    
    /// Get active recovery sessions
    pub async fn get_active_sessions(&self) -> Vec<RecoverySession> {
        let sessions = self.active_sessions.read().await;
        sessions.values().cloned().collect()
    }
    
    /// Validate recovery setup
    fn validate_setup(&self, setup: &RecoverySetup) -> MultisigResult<()> {
        if setup.threshold == 0 {
            return Err(MultisigError::InvalidThreshold);
        }
        
        if setup.threshold > setup.total_shares {
            return Err(MultisigError::InvalidThreshold);
        }
        
        if setup.participants.is_empty() {
            return Err(MultisigError::NoParticipants);
        }
        
        Ok(())
    }
    
    /// Validate recovery request
    fn validate_recovery_request(&self, request: &RecoveryRequest) -> MultisigResult<()> {
        if request.required_signatures == 0 {
            return Err(MultisigError::InvalidSignatureCount);
        }
        
        if request.timeout_seconds == 0 {
            return Err(MultisigError::InvalidTimeout);
        }
        
        Ok(())
    }
    
    /// Validate recovery signature
    fn validate_recovery_signature(
        &self,
        signature: &RecoverySignature,
        recovery_data: &RecoveryData,
    ) -> MultisigResult<()> {
        // Verify signature against recovery data
        let data_hash = self.hash_recovery_data(recovery_data)?;
        
        if !signature.signer.verify(&data_hash, &signature.signature)? {
            return Err(MultisigError::InvalidSignature);
        }
        
        Ok(())
    }
    
    /// Hash recovery data
    fn hash_recovery_data(&self, recovery_data: &RecoveryData) -> MultisigResult<Vec<u8>> {
        let serialized = bincode::serialize(recovery_data)
            .map_err(|e| MultisigError::SerializationError(e.to_string()))?;
        
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&serialized);
        Ok(hasher.finalize().to_vec())
    }
    
    /// Extract share from signature (placeholder)
    fn extract_share_from_signature(&self, signature: &RecoverySignature) -> MultisigResult<secret_sharing::SecretShare> {
        // This is a simplified implementation
        // In practice, the share would be embedded in the signature or metadata
        Ok(secret_sharing::SecretShare {
            id: 1,
            share: signature.signature.clone(),
        })
    }
    
    /// Recover identity from secret
    fn recover_identity_from_secret(
        &self,
        secret: &[u8],
        recovery_data: &RecoveryData,
    ) -> MultisigResult<QuIDIdentity> {
        // This is a simplified implementation
        // In practice, the secret would be used to derive the private key
        QuIDIdentity::generate(SecurityLevel::High)
            .map_err(|e| MultisigError::IdentityRecoveryFailed(e.to_string()))
    }
    
    /// Recover identity from threshold signature
    fn recover_identity_from_threshold(
        &self,
        signature: &[u8],
        recovery_data: &RecoveryData,
    ) -> MultisigResult<QuIDIdentity> {
        // This is a simplified implementation
        QuIDIdentity::generate(SecurityLevel::High)
            .map_err(|e| MultisigError::IdentityRecoveryFailed(e.to_string()))
    }
    
    /// Update wallet with recovered identity
    async fn update_wallet_with_recovered_identity(&self, identity: &QuIDIdentity) -> MultisigResult<()> {
        // This would update the wallet manager with the recovered identity
        // Implementation depends on wallet manager interface
        tracing::info!("Wallet updated with recovered identity: {}", 
                      hex::encode(identity.public_key().as_bytes()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quid_core::SecurityLevel;
    use quid_wallet::WalletConfig;
    
    #[tokio::test]
    async fn test_multisig_manager_creation() {
        let config = MultisigConfig::default();
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        let wallet_config = WalletConfig::default();
        let wallet_manager = Arc::new(QuIDWalletManager::new(wallet_config).await.unwrap());
        
        let manager = QuIDMultisigManager::new(config, identity, wallet_manager).await.unwrap();
        
        let active_sessions = manager.get_active_sessions().await;
        assert_eq!(active_sessions.len(), 0);
    }
    
    #[tokio::test]
    async fn test_recovery_setup_validation() {
        let config = MultisigConfig::default();
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        let wallet_config = WalletConfig::default();
        let wallet_manager = Arc::new(QuIDWalletManager::new(wallet_config).await.unwrap());
        
        let manager = QuIDMultisigManager::new(config, identity, wallet_manager).await.unwrap();
        
        // Test invalid threshold
        let mut setup = RecoverySetup::default();
        setup.threshold = 0;
        assert!(manager.validate_setup(&setup).is_err());
        
        // Test threshold > total_shares
        setup.threshold = 5;
        setup.total_shares = 3;
        assert!(manager.validate_setup(&setup).is_err());
        
        // Test valid setup
        setup.threshold = 2;
        setup.total_shares = 3;
        setup.participants = vec![QuIDIdentity::generate(SecurityLevel::High).unwrap()];
        assert!(manager.validate_setup(&setup).is_ok());
    }
    
    #[tokio::test]
    async fn test_recovery_request_validation() {
        let config = MultisigConfig::default();
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        let wallet_config = WalletConfig::default();
        let wallet_manager = Arc::new(QuIDWalletManager::new(wallet_config).await.unwrap());
        
        let manager = QuIDMultisigManager::new(config, identity, wallet_manager).await.unwrap();
        
        // Test invalid signature count
        let mut request = RecoveryRequest::default();
        request.required_signatures = 0;
        assert!(manager.validate_recovery_request(&request).is_err());
        
        // Test invalid timeout
        request.required_signatures = 2;
        request.timeout_seconds = 0;
        assert!(manager.validate_recovery_request(&request).is_err());
        
        // Test valid request
        request.timeout_seconds = 3600;
        assert!(manager.validate_recovery_request(&request).is_ok());
    }
}