//! Nostr Implementation Possibilities (NIPs) support

use crate::{NostrResult, NostrError, NostrEvent, EventKind};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// NIP-01: Basic protocol flow description
pub mod nip01 {
    use super::*;
    
    /// Validate basic event structure according to NIP-01
    pub fn validate_event(event: &NostrEvent) -> NostrResult<()> {
        event.validate()
    }
}

/// NIP-04: Encrypted Direct Messages
pub mod nip04 {
    use super::*;
    
    /// Encrypt message content for NIP-04
    pub fn encrypt_message(content: &str, shared_secret: &[u8]) -> NostrResult<String> {
        // Simplified encryption for demo
        let mut encrypted = Vec::new();
        for (i, &byte) in content.as_bytes().iter().enumerate() {
            encrypted.push(byte ^ shared_secret[i % shared_secret.len()]);
        }
        Ok(base64::encode(encrypted))
    }
    
    /// Decrypt message content for NIP-04
    pub fn decrypt_message(encrypted_content: &str, shared_secret: &[u8]) -> NostrResult<String> {
        let encrypted = base64::decode(encrypted_content)
            .map_err(|e| NostrError::DecryptionError(e.to_string()))?;
        
        let mut decrypted = Vec::new();
        for (i, &byte) in encrypted.iter().enumerate() {
            decrypted.push(byte ^ shared_secret[i % shared_secret.len()]);
        }
        
        String::from_utf8(decrypted)
            .map_err(|e| NostrError::DecryptionError(e.to_string()))
    }
}

/// NIP-05: Mapping Nostr keys to DNS-based internet identifiers
pub mod nip05 {
    use super::*;
    
    /// Verify NIP-05 identifier
    pub async fn verify_identifier(identifier: &str, pubkey: &str) -> NostrResult<bool> {
        // In production, this would make HTTP request to verify
        // For now, just validate format
        if identifier.contains('@') && identifier.contains('.') {
            Ok(true)
        } else {
            Err(NostrError::NipNotSupported("Invalid NIP-05 identifier format".to_string()))
        }
    }
}

/// NIP-09: Event Deletion
pub mod nip09 {
    use super::*;
    
    /// Create deletion event
    pub fn create_deletion_event(
        pubkey: String,
        event_ids_to_delete: Vec<String>,
        reason: Option<String>,
    ) -> NostrEvent {
        let mut tags = Vec::new();
        
        // Add 'e' tags for each event to delete
        for event_id in event_ids_to_delete {
            tags.push(vec!["e".to_string(), event_id]);
        }
        
        let content = reason.unwrap_or_default();
        
        NostrEvent::new(pubkey, EventKind::DELETE, content, tags)
    }
    
    /// Check if event is a deletion request
    pub fn is_deletion_event(event: &NostrEvent) -> bool {
        event.kind == EventKind::DELETE
    }
    
    /// Get deleted event IDs from deletion event
    pub fn get_deleted_event_ids(event: &NostrEvent) -> Vec<String> {
        if !is_deletion_event(event) {
            return vec![];
        }
        
        event.get_tags("e")
            .iter()
            .filter_map(|tag| tag.get(1).cloned())
            .collect()
    }
}

/// NIP-11: Relay Information Document
pub mod nip11 {
    use super::*;
    
    /// Relay information document
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RelayInformation {
        pub name: String,
        pub description: String,
        pub pubkey: String,
        pub contact: String,
        pub supported_nips: Vec<u16>,
        pub software: String,
        pub version: String,
        pub limitation: Option<RelayLimitations>,
        pub payment_required: bool,
        pub fees: Option<RelayFees>,
    }
    
    /// Relay limitations
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RelayLimitations {
        pub max_message_length: Option<u32>,
        pub max_subscriptions: Option<u32>,
        pub max_filters: Option<u32>,
        pub max_limit: Option<u32>,
        pub max_subid_length: Option<u32>,
        pub min_prefix: Option<u32>,
        pub max_event_tags: Option<u32>,
        pub max_content_length: Option<u32>,
        pub min_pow_difficulty: Option<u32>,
        pub auth_required: bool,
        pub payment_required: bool,
    }
    
    /// Relay fees
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RelayFees {
        pub admission: Option<Vec<FeeSchedule>>,
        pub subscription: Option<Vec<FeeSchedule>>,
        pub publication: Option<Vec<FeeSchedule>>,
    }
    
    /// Fee schedule
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct FeeSchedule {
        pub amount: u64,
        pub unit: String,
        pub period: Option<u32>,
    }
    
    impl Default for RelayInformation {
        fn default() -> Self {
            Self {
                name: "QuID Nostr Relay".to_string(),
                description: "Quantum-resistant Nostr relay powered by QuID".to_string(),
                pubkey: "".to_string(),
                contact: "admin@quid-nostr.example".to_string(),
                supported_nips: vec![1, 2, 4, 9, 11, 12, 15, 16, 20, 28, 33, 40, 42, 50, 51, 57],
                software: "quid-nostr".to_string(),
                version: "1.0.0".to_string(),
                limitation: Some(RelayLimitations::default()),
                payment_required: false,
                fees: None,
            }
        }
    }
    
    impl Default for RelayLimitations {
        fn default() -> Self {
            Self {
                max_message_length: Some(16384),
                max_subscriptions: Some(20),
                max_filters: Some(100),
                max_limit: Some(5000),
                max_subid_length: Some(100),
                min_prefix: Some(4),
                max_event_tags: Some(100),
                max_content_length: Some(8196),
                min_pow_difficulty: Some(0),
                auth_required: false,
                payment_required: false,
            }
        }
    }
}

/// NIP-15: End of Stored Events Notice
pub mod nip15 {
    use super::*;
    
    /// Create EOSE (End of Stored Events) message
    pub fn create_eose_message(subscription_id: &str) -> String {
        format!("[\"EOSE\",\"{}\"]", subscription_id)
    }
}

/// NIP-16: Event Treatment
pub mod nip16 {
    use super::*;
    
    /// Check if event is replaceable
    pub fn is_replaceable_event(kind: &EventKind) -> bool {
        kind.is_replaceable()
    }
    
    /// Check if event is ephemeral
    pub fn is_ephemeral_event(kind: &EventKind) -> bool {
        kind.is_ephemeral()
    }
    
    /// Check if event is regular
    pub fn is_regular_event(kind: &EventKind) -> bool {
        kind.is_regular()
    }
}

/// NIP-57: Lightning Zaps
pub mod nip57 {
    use super::*;
    
    /// Zap request event
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ZapRequest {
        pub amount: u64,
        pub recipient: String,
        pub comment: Option<String>,
        pub relays: Vec<String>,
    }
    
    /// Create zap request event
    pub fn create_zap_request(
        pubkey: String,
        recipient: &str,
        amount: u64,
        comment: Option<String>,
        relays: Vec<String>,
    ) -> NostrEvent {
        let mut tags = vec![
            vec!["p".to_string(), recipient.to_string()],
            vec!["amount".to_string(), amount.to_string()],
        ];
        
        for relay in relays {
            tags.push(vec!["relays".to_string(), relay]);
        }
        
        let content = comment.unwrap_or_default();
        
        NostrEvent::new(pubkey, EventKind::ZAP_REQUEST, content, tags)
    }
    
    /// Create zap receipt event
    pub fn create_zap_receipt(
        pubkey: String,
        zap_request: &NostrEvent,
        bolt11: String,
        preimage: String,
    ) -> NostrEvent {
        let mut tags = vec![
            vec!["bolt11".to_string(), bolt11],
            vec!["preimage".to_string(), preimage],
            vec!["e".to_string(), zap_request.id.clone()],
            vec!["p".to_string(), zap_request.pubkey.clone()],
        ];
        
        // Copy relevant tags from zap request
        for tag in &zap_request.tags {
            if tag.len() >= 2 && (tag[0] == "amount" || tag[0] == "relays") {
                tags.push(tag.clone());
            }
        }
        
        NostrEvent::new(pubkey, EventKind::ZAP_RECEIPT, String::new(), tags)
    }
}

/// QuID-specific NIP extensions
pub mod quid_extensions {
    use super::*;
    use quid_core::QuIDIdentity;
    
    /// NIP-31000: QuID Identity Proof
    pub fn create_identity_proof(identity: &QuIDIdentity) -> NostrResult<NostrEvent> {
        let proof_data = serde_json::json!({
            "quid_version": "1.0",
            "identity_id": identity.identity_id(),
            "public_key": hex::encode(identity.public_key().as_bytes()),
            "security_level": format!("{:?}", identity.security_level()),
            "quantum_resistant": true,
            "timestamp": chrono::Utc::now().timestamp()
        });
        
        let content = proof_data.to_string();
        let tags = vec![
            vec!["quid".to_string(), "identity_proof".to_string()],
            vec!["version".to_string(), "1.0".to_string()],
        ];
        
        // Derive Nostr pubkey from QuID identity
        let nostr_pubkey = derive_nostr_pubkey(identity)?;
        
        Ok(NostrEvent::new(
            nostr_pubkey,
            EventKind::QUID_IDENTITY_PROOF,
            content,
            tags,
        ))
    }
    
    /// NIP-31001: QuID Authentication Event
    pub fn create_authentication_event(
        identity: &QuIDIdentity,
        challenge: &str,
        service: &str,
    ) -> NostrResult<NostrEvent> {
        let auth_data = serde_json::json!({
            "challenge": challenge,
            "service": service,
            "timestamp": chrono::Utc::now().timestamp(),
            "quantum_resistant": true
        });
        
        let content = auth_data.to_string();
        let tags = vec![
            vec!["quid".to_string(), "authentication".to_string()],
            vec!["service".to_string(), service.to_string()],
            vec!["challenge".to_string(), challenge.to_string()],
        ];
        
        let nostr_pubkey = derive_nostr_pubkey(identity)?;
        
        Ok(NostrEvent::new(
            nostr_pubkey,
            EventKind::QUID_AUTHENTICATION,
            content,
            tags,
        ))
    }
    
    /// NIP-31002: QuID Capability Announcement
    pub fn create_capability_announcement(
        identity: &QuIDIdentity,
        capabilities: Vec<String>,
    ) -> NostrResult<NostrEvent> {
        let capability_data = serde_json::json!({
            "capabilities": capabilities,
            "quantum_resistant": true,
            "timestamp": chrono::Utc::now().timestamp()
        });
        
        let content = capability_data.to_string();
        let mut tags = vec![
            vec!["quid".to_string(), "capabilities".to_string()],
        ];
        
        for capability in capabilities {
            tags.push(vec!["capability".to_string(), capability]);
        }
        
        let nostr_pubkey = derive_nostr_pubkey(identity)?;
        
        Ok(NostrEvent::new(
            nostr_pubkey,
            EventKind::QUID_CAPABILITY_ANNOUNCEMENT,
            content,
            tags,
        ))
    }
    
    /// Derive Nostr pubkey from QuID identity
    fn derive_nostr_pubkey(identity: &QuIDIdentity) -> NostrResult<String> {
        use sha3::{Sha3_256, Digest};
        
        let mut hasher = Sha3_256::new();
        hasher.update(b"quid-nostr-pubkey");
        hasher.update(identity.public_key().as_bytes());
        let hash = hasher.finalize();
        
        Ok(hex::encode(&hash[..32]))
    }
}

/// NIP registry and support checker
pub struct NipRegistry {
    supported_nips: HashMap<u16, String>,
}

impl NipRegistry {
    /// Create new NIP registry
    pub fn new() -> Self {
        let mut supported_nips = HashMap::new();
        
        // Standard NIPs
        supported_nips.insert(1, "Basic protocol flow description".to_string());
        supported_nips.insert(2, "Contact List and Petnames".to_string());
        supported_nips.insert(4, "Encrypted Direct Messages".to_string());
        supported_nips.insert(5, "Mapping Nostr keys to DNS-based internet identifiers".to_string());
        supported_nips.insert(9, "Event Deletion".to_string());
        supported_nips.insert(11, "Relay Information Document".to_string());
        supported_nips.insert(12, "Generic Tag Queries".to_string());
        supported_nips.insert(15, "End of Stored Events Notice".to_string());
        supported_nips.insert(16, "Event Treatment".to_string());
        supported_nips.insert(20, "Command Results".to_string());
        supported_nips.insert(28, "Public Chat".to_string());
        supported_nips.insert(33, "Parameterized Replaceable Events".to_string());
        supported_nips.insert(40, "Expiration Timestamp".to_string());
        supported_nips.insert(42, "Authentication of clients to relays".to_string());
        supported_nips.insert(50, "Keywords filter".to_string());
        supported_nips.insert(51, "Lists".to_string());
        supported_nips.insert(57, "Lightning Zaps".to_string());
        
        // QuID extensions
        supported_nips.insert(31000, "QuID Identity Proof".to_string());
        supported_nips.insert(31001, "QuID Authentication".to_string());
        supported_nips.insert(31002, "QuID Capability Announcement".to_string());
        
        Self { supported_nips }
    }
    
    /// Check if NIP is supported
    pub fn is_supported(&self, nip: u16) -> bool {
        self.supported_nips.contains_key(&nip)
    }
    
    /// Get NIP description
    pub fn get_description(&self, nip: u16) -> Option<&String> {
        self.supported_nips.get(&nip)
    }
    
    /// Get all supported NIPs
    pub fn get_supported_nips(&self) -> Vec<u16> {
        self.supported_nips.keys().cloned().collect()
    }
}

impl Default for NipRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quid_core::SecurityLevel;
    
    #[test]
    fn test_nip04_encryption() {
        let content = "Hello, secret world!";
        let shared_secret = b"shared_secret_key_32_bytes_long!";
        
        let encrypted = nip04::encrypt_message(content, shared_secret).unwrap();
        let decrypted = nip04::decrypt_message(&encrypted, shared_secret).unwrap();
        
        assert_eq!(content, decrypted);
    }
    
    #[test]
    fn test_nip09_deletion() {
        let event_ids = vec!["event1".to_string(), "event2".to_string()];
        let deletion_event = nip09::create_deletion_event(
            "pubkey".to_string(),
            event_ids.clone(),
            Some("Spam content".to_string()),
        );
        
        assert!(nip09::is_deletion_event(&deletion_event));
        
        let deleted_ids = nip09::get_deleted_event_ids(&deletion_event);
        assert_eq!(deleted_ids, event_ids);
    }
    
    #[test]
    fn test_nip16_event_classification() {
        assert!(nip16::is_regular_event(&EventKind::TEXT_NOTE));
        assert!(nip16::is_replaceable_event(&EventKind::METADATA));
        
        let ephemeral_kind = EventKind(25000);
        assert!(nip16::is_ephemeral_event(&ephemeral_kind));
    }
    
    #[test]
    fn test_nip57_zap_request() {
        let zap_request = nip57::create_zap_request(
            "sender_pubkey".to_string(),
            "recipient_pubkey",
            1000,
            Some("Great content!".to_string()),
            vec!["wss://relay.example.com".to_string()],
        );
        
        assert_eq!(zap_request.kind, EventKind::ZAP_REQUEST);
        assert_eq!(zap_request.content, "Great content!");
    }
    
    #[test]
    fn test_quid_identity_proof() {
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        let proof_event = quid_extensions::create_identity_proof(&identity).unwrap();
        
        assert_eq!(proof_event.kind, EventKind::QUID_IDENTITY_PROOF);
        assert!(proof_event.content.contains("quid_version"));
        assert!(proof_event.content.contains("quantum_resistant"));
    }
    
    #[test]
    fn test_nip_registry() {
        let registry = NipRegistry::new();
        
        assert!(registry.is_supported(1));
        assert!(registry.is_supported(4));
        assert!(registry.is_supported(31000)); // QuID extension
        assert!(!registry.is_supported(999));
        
        assert!(registry.get_description(1).is_some());
        assert!(registry.get_description(999).is_none());
        
        let supported = registry.get_supported_nips();
        assert!(supported.contains(&1));
        assert!(supported.contains(&31000));
    }
}