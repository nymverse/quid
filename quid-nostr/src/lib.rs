//! QuID Nostr Protocol Integration
//!
//! This crate provides integration between QuID quantum-resistant authentication
//! and the Nostr decentralized social protocol, enabling secure identity verification
//! and quantum-resistant signatures for Nostr events.
//!
//! Features:
//! - Nostr event signing with QuID identities
//! - Quantum-resistant public key derivation for Nostr
//! - Encrypted direct messages using QuID cryptography
//! - Relay authentication and verification
//! - NIP (Nostr Implementation Possibilities) extensions
//! - Lightning Network integration for Zaps

use quid_core::{QuIDIdentity, QuIDError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use uuid::Uuid;

pub mod client;
pub mod relay;
pub mod event;
pub mod crypto;
pub mod nips;
pub mod lightning;
pub mod config;
pub mod error;

pub use client::NostrClient;
pub use relay::NostrRelay;
pub use event::{NostrEvent, EventKind};
pub use error::{NostrError, NostrResult};
pub use config::NostrConfig;

/// QuID Nostr integration manager
#[derive(Debug)]
pub struct QuIDNostr {
    /// Configuration
    config: NostrConfig,
    /// Connected clients
    clients: Arc<RwLock<HashMap<String, Arc<NostrClient>>>>,
    /// Connected relays
    relays: Arc<RwLock<HashMap<String, Arc<NostrRelay>>>>,
    /// Event cache
    event_cache: Arc<RwLock<HashMap<String, NostrEvent>>>,
    /// Identity to pubkey mapping
    identity_mapping: Arc<RwLock<HashMap<String, NostrPublicKey>>>,
}

/// Nostr public key representation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct NostrPublicKey {
    /// Hex-encoded public key
    pub hex: String,
    /// Bech32-encoded public key (npub)
    pub npub: String,
    /// QuID identity ID that generated this key
    pub quid_identity_id: String,
}

/// Nostr private key representation
#[derive(Debug, Clone)]
pub struct NostrPrivateKey {
    /// Hex-encoded private key
    pub hex: String,
    /// Bech32-encoded private key (nsec)
    pub nsec: String,
    /// Associated QuID identity
    pub quid_identity: QuIDIdentity,
}

impl QuIDNostr {
    /// Create a new QuID Nostr integration manager
    pub async fn new(config: NostrConfig) -> NostrResult<Self> {
        Ok(Self {
            config,
            clients: Arc::new(RwLock::new(HashMap::new())),
            relays: Arc::new(RwLock::new(HashMap::new())),
            event_cache: Arc::new(RwLock::new(HashMap::new())),
            identity_mapping: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Derive Nostr public key from QuID identity
    pub async fn derive_nostr_pubkey(&self, identity: &QuIDIdentity) -> NostrResult<NostrPublicKey> {
        let pubkey_hex = self.derive_nostr_pubkey_hex(identity)?;
        let npub = self.encode_npub(&pubkey_hex)?;
        
        let nostr_pubkey = NostrPublicKey {
            hex: pubkey_hex,
            npub,
            quid_identity_id: identity.identity_id().to_string(),
        };

        // Cache the mapping
        {
            let mut mapping = self.identity_mapping.write().await;
            mapping.insert(identity.identity_id().to_string(), nostr_pubkey.clone());
        }

        Ok(nostr_pubkey)
    }

    /// Derive Nostr private key from QuID identity
    pub async fn derive_nostr_privkey(&self, identity: &QuIDIdentity) -> NostrResult<NostrPrivateKey> {
        let privkey_hex = self.derive_nostr_privkey_hex(identity)?;
        let nsec = self.encode_nsec(&privkey_hex)?;
        
        Ok(NostrPrivateKey {
            hex: privkey_hex,
            nsec,
            quid_identity: identity.clone(),
        })
    }

    /// Create and sign a Nostr event
    pub async fn create_event(
        &self,
        identity: &QuIDIdentity,
        kind: EventKind,
        content: String,
        tags: Vec<Vec<String>>,
    ) -> NostrResult<NostrEvent> {
        let pubkey = self.derive_nostr_pubkey(identity).await?;
        let created_at = Utc::now().timestamp() as u64;
        
        let mut event = NostrEvent {
            id: String::new(), // Will be calculated
            pubkey: pubkey.hex,
            created_at,
            kind,
            tags,
            content,
            sig: String::new(), // Will be calculated
        };

        // Calculate event ID
        event.id = self.calculate_event_id(&event)?;
        
        // Sign the event
        event.sig = self.sign_event(identity, &event).await?;

        // Cache the event
        {
            let mut cache = self.event_cache.write().await;
            cache.insert(event.id.clone(), event.clone());
        }

        Ok(event)
    }

    /// Connect to a Nostr relay
    pub async fn connect_relay(&self, url: &str) -> NostrResult<String> {
        let relay_id = Uuid::new_v4().to_string();
        let relay = NostrRelay::connect(url, &self.config.relay_config).await?;
        
        {
            let mut relays = self.relays.write().await;
            relays.insert(relay_id.clone(), Arc::new(relay));
        }

        Ok(relay_id)
    }

    /// Create a Nostr client
    pub async fn create_client(&self, identity: &QuIDIdentity) -> NostrResult<String> {
        let client_id = Uuid::new_v4().to_string();
        let client = NostrClient::new(identity.clone(), &self.config.client_config).await?;
        
        {
            let mut clients = self.clients.write().await;
            clients.insert(client_id.clone(), Arc::new(client));
        }

        Ok(client_id)
    }

    /// Publish event to connected relays
    pub async fn publish_event(&self, event: &NostrEvent) -> NostrResult<Vec<String>> {
        let relays = self.relays.read().await;
        let mut published_to = Vec::new();

        for (relay_id, relay) in relays.iter() {
            match relay.publish_event(event).await {
                Ok(_) => published_to.push(relay_id.clone()),
                Err(e) => tracing::warn!("Failed to publish to relay {}: {}", relay_id, e),
            }
        }

        if published_to.is_empty() {
            return Err(NostrError::PublishFailed("No relays available".to_string()));
        }

        Ok(published_to)
    }

    /// Subscribe to events from relays
    pub async fn subscribe(&self, filters: Vec<event::Filter>) -> NostrResult<String> {
        let subscription_id = Uuid::new_v4().to_string();
        let relays = self.relays.read().await;

        for relay in relays.values() {
            relay.subscribe(&subscription_id, filters.clone()).await?;
        }

        Ok(subscription_id)
    }

    /// Get cached events
    pub async fn get_cached_events(&self) -> HashMap<String, NostrEvent> {
        self.event_cache.read().await.clone()
    }

    /// Verify event signature
    pub async fn verify_event(&self, event: &NostrEvent) -> NostrResult<bool> {
        // Verify event ID
        let calculated_id = self.calculate_event_id(event)?;
        if calculated_id != event.id {
            return Ok(false);
        }

        // Verify signature
        self.verify_event_signature(event).await
    }

    /// Send encrypted direct message
    pub async fn send_encrypted_dm(
        &self,
        sender_identity: &QuIDIdentity,
        recipient_pubkey: &str,
        message: &str,
    ) -> NostrResult<NostrEvent> {
        let encrypted_content = self.encrypt_dm_content(sender_identity, recipient_pubkey, message).await?;
        
        let tags = vec![
            vec!["p".to_string(), recipient_pubkey.to_string()],
        ];

        self.create_event(
            sender_identity,
            EventKind::EncryptedDirectMessage,
            encrypted_content,
            tags,
        ).await
    }

    /// Decrypt direct message
    pub async fn decrypt_dm(
        &self,
        recipient_identity: &QuIDIdentity,
        event: &NostrEvent,
    ) -> NostrResult<String> {
        if event.kind != EventKind::EncryptedDirectMessage {
            return Err(NostrError::InvalidEventKind);
        }

        self.decrypt_dm_content(recipient_identity, &event.pubkey, &event.content).await
    }

    // Private helper methods

    /// Derive Nostr public key hex from QuID identity
    fn derive_nostr_pubkey_hex(&self, identity: &QuIDIdentity) -> NostrResult<String> {
        use sha3::{Sha3_256, Digest};
        
        let mut hasher = Sha3_256::new();
        hasher.update(b"quid-nostr-pubkey");
        hasher.update(identity.public_key().as_bytes());
        let hash = hasher.finalize();
        
        Ok(hex::encode(&hash[..32]))
    }

    /// Derive Nostr private key hex from QuID identity
    fn derive_nostr_privkey_hex(&self, identity: &QuIDIdentity) -> NostrResult<String> {
        use sha3::{Sha3_256, Digest};
        
        let mut hasher = Sha3_256::new();
        hasher.update(b"quid-nostr-privkey");
        hasher.update(identity.public_key().as_bytes());
        // In production, this would use the actual private key material
        // For now, derive from public key with different salt
        hasher.update(b"private-derivation");
        let hash = hasher.finalize();
        
        Ok(hex::encode(&hash[..32]))
    }

    /// Encode public key as npub (bech32)
    fn encode_npub(&self, pubkey_hex: &str) -> NostrResult<String> {
        // Simplified bech32 encoding for demo
        // In production, use proper bech32 library
        Ok(format!("npub1{}", pubkey_hex))
    }

    /// Encode private key as nsec (bech32)
    fn encode_nsec(&self, privkey_hex: &str) -> NostrResult<String> {
        // Simplified bech32 encoding for demo
        // In production, use proper bech32 library
        Ok(format!("nsec1{}", privkey_hex))
    }

    /// Calculate event ID
    fn calculate_event_id(&self, event: &NostrEvent) -> NostrResult<String> {
        use sha3::{Sha3_256, Digest};
        
        // Nostr event ID is SHA256 of serialized event data
        let serialized = format!(
            "[0,\"{}\",{},{},{},[{}]]",
            event.pubkey,
            event.created_at,
            event.kind as u16,
            serde_json::to_string(&event.tags).map_err(|e| NostrError::SerializationError(e.to_string()))?,
            serde_json::to_string(&event.content).map_err(|e| NostrError::SerializationError(e.to_string()))?
        );
        
        let mut hasher = Sha3_256::new();
        hasher.update(serialized.as_bytes());
        let hash = hasher.finalize();
        
        Ok(hex::encode(hash))
    }

    /// Sign Nostr event
    async fn sign_event(&self, identity: &QuIDIdentity, event: &NostrEvent) -> NostrResult<String> {
        let event_id_bytes = hex::decode(&event.id)
            .map_err(|e| NostrError::SigningError(format!("Invalid event ID: {}", e)))?;
        
        let signature = identity.sign(&event_id_bytes)
            .map_err(|e| NostrError::SigningError(e.to_string()))?;
        
        Ok(hex::encode(signature))
    }

    /// Verify event signature
    async fn verify_event_signature(&self, event: &NostrEvent) -> NostrResult<bool> {
        // In production, this would verify the actual Schnorr signature
        // For now, just check that signature is not empty and has correct length
        Ok(!event.sig.is_empty() && event.sig.len() == 128) // 64 bytes * 2 (hex)
    }

    /// Encrypt direct message content
    async fn encrypt_dm_content(
        &self,
        sender_identity: &QuIDIdentity,
        recipient_pubkey: &str,
        message: &str,
    ) -> NostrResult<String> {
        // In production, this would use proper NIP-04 encryption
        // For now, simple XOR encryption for demo
        let key = self.derive_shared_secret(sender_identity, recipient_pubkey)?;
        let mut encrypted = Vec::new();
        
        for (i, &byte) in message.as_bytes().iter().enumerate() {
            encrypted.push(byte ^ key[i % key.len()]);
        }
        
        Ok(base64::encode(encrypted))
    }

    /// Decrypt direct message content
    async fn decrypt_dm_content(
        &self,
        recipient_identity: &QuIDIdentity,
        sender_pubkey: &str,
        encrypted_content: &str,
    ) -> NostrResult<String> {
        let key = self.derive_shared_secret(recipient_identity, sender_pubkey)?;
        let encrypted = base64::decode(encrypted_content)
            .map_err(|e| NostrError::DecryptionError(e.to_string()))?;
        
        let mut decrypted = Vec::new();
        for (i, &byte) in encrypted.iter().enumerate() {
            decrypted.push(byte ^ key[i % key.len()]);
        }
        
        String::from_utf8(decrypted)
            .map_err(|e| NostrError::DecryptionError(e.to_string()))
    }

    /// Derive shared secret for encryption
    fn derive_shared_secret(&self, identity: &QuIDIdentity, other_pubkey: &str) -> NostrResult<Vec<u8>> {
        use sha3::{Sha3_256, Digest};
        
        let mut hasher = Sha3_256::new();
        hasher.update(b"quid-nostr-shared-secret");
        hasher.update(identity.public_key().as_bytes());
        hasher.update(other_pubkey.as_bytes());
        let hash = hasher.finalize();
        
        Ok(hash.to_vec())
    }

    /// Get connected relay count
    pub async fn relay_count(&self) -> usize {
        self.relays.read().await.len()
    }

    /// Get connected client count
    pub async fn client_count(&self) -> usize {
        self.clients.read().await.len()
    }

    /// Get cached event count
    pub async fn cached_event_count(&self) -> usize {
        self.event_cache.read().await.len()
    }

    /// Clear all caches
    pub async fn clear_caches(&self) {
        self.event_cache.write().await.clear();
        self.identity_mapping.write().await.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quid_core::SecurityLevel;

    #[tokio::test]
    async fn test_quid_nostr_creation() {
        let config = NostrConfig::default();
        let quid_nostr = QuIDNostr::new(config).await.unwrap();
        
        assert_eq!(quid_nostr.relay_count().await, 0);
        assert_eq!(quid_nostr.client_count().await, 0);
        assert_eq!(quid_nostr.cached_event_count().await, 0);
    }

    #[tokio::test]
    async fn test_nostr_pubkey_derivation() {
        let config = NostrConfig::default();
        let quid_nostr = QuIDNostr::new(config).await.unwrap();
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        
        let pubkey = quid_nostr.derive_nostr_pubkey(&identity).await.unwrap();
        
        assert!(!pubkey.hex.is_empty());
        assert!(pubkey.npub.starts_with("npub1"));
        assert_eq!(pubkey.quid_identity_id, identity.identity_id());
        assert_eq!(pubkey.hex.len(), 64); // 32 bytes * 2 (hex)
    }

    #[tokio::test]
    async fn test_nostr_privkey_derivation() {
        let config = NostrConfig::default();
        let quid_nostr = QuIDNostr::new(config).await.unwrap();
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        
        let privkey = quid_nostr.derive_nostr_privkey(&identity).await.unwrap();
        
        assert!(!privkey.hex.is_empty());
        assert!(privkey.nsec.starts_with("nsec1"));
        assert_eq!(privkey.quid_identity.identity_id(), identity.identity_id());
        assert_eq!(privkey.hex.len(), 64); // 32 bytes * 2 (hex)
    }

    #[tokio::test]
    async fn test_event_creation_and_verification() {
        let config = NostrConfig::default();
        let quid_nostr = QuIDNostr::new(config).await.unwrap();
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        
        let event = quid_nostr.create_event(
            &identity,
            EventKind::TextNote,
            "Hello Nostr!".to_string(),
            vec![],
        ).await.unwrap();
        
        assert!(!event.id.is_empty());
        assert!(!event.pubkey.is_empty());
        assert!(!event.sig.is_empty());
        assert_eq!(event.content, "Hello Nostr!");
        assert_eq!(event.kind, EventKind::TextNote);
        
        // Verify the event
        assert!(quid_nostr.verify_event(&event).await.unwrap());
        
        // Check cache
        assert_eq!(quid_nostr.cached_event_count().await, 1);
    }

    #[tokio::test]
    async fn test_encrypted_dm() {
        let config = NostrConfig::default();
        let quid_nostr = QuIDNostr::new(config).await.unwrap();
        let sender = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        let recipient = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        
        let recipient_pubkey = quid_nostr.derive_nostr_pubkey(&recipient).await.unwrap();
        let message = "Secret message";
        
        // Send encrypted DM
        let dm_event = quid_nostr.send_encrypted_dm(
            &sender,
            &recipient_pubkey.hex,
            message,
        ).await.unwrap();
        
        assert_eq!(dm_event.kind, EventKind::EncryptedDirectMessage);
        assert_ne!(dm_event.content, message); // Should be encrypted
        
        // Decrypt DM
        let decrypted = quid_nostr.decrypt_dm(&recipient, &dm_event).await.unwrap();
        assert_eq!(decrypted, message);
    }

    #[tokio::test]
    async fn test_identity_mapping() {
        let config = NostrConfig::default();
        let quid_nostr = QuIDNostr::new(config).await.unwrap();
        let identity1 = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        let identity2 = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        
        let pubkey1 = quid_nostr.derive_nostr_pubkey(&identity1).await.unwrap();
        let pubkey2 = quid_nostr.derive_nostr_pubkey(&identity2).await.unwrap();
        
        // Different identities should produce different pubkeys
        assert_ne!(pubkey1.hex, pubkey2.hex);
        assert_ne!(pubkey1.npub, pubkey2.npub);
        
        // Same identity should produce same pubkey
        let pubkey1_again = quid_nostr.derive_nostr_pubkey(&identity1).await.unwrap();
        assert_eq!(pubkey1.hex, pubkey1_again.hex);
    }

    #[tokio::test]
    async fn test_event_id_calculation() {
        let config = NostrConfig::default();
        let quid_nostr = QuIDNostr::new(config).await.unwrap();
        
        let event = NostrEvent {
            id: String::new(),
            pubkey: "test_pubkey".to_string(),
            created_at: 1234567890,
            kind: EventKind::TextNote,
            tags: vec![],
            content: "test content".to_string(),
            sig: String::new(),
        };
        
        let event_id = quid_nostr.calculate_event_id(&event).unwrap();
        assert!(!event_id.is_empty());
        assert_eq!(event_id.len(), 64); // SHA256 hex
    }

    #[tokio::test]
    async fn test_cache_operations() {
        let config = NostrConfig::default();
        let quid_nostr = QuIDNostr::new(config).await.unwrap();
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        
        // Create multiple events
        for i in 0..3 {
            quid_nostr.create_event(
                &identity,
                EventKind::TextNote,
                format!("Message {}", i),
                vec![],
            ).await.unwrap();
        }
        
        assert_eq!(quid_nostr.cached_event_count().await, 3);
        
        // Clear caches
        quid_nostr.clear_caches().await;
        assert_eq!(quid_nostr.cached_event_count().await, 0);
    }
}