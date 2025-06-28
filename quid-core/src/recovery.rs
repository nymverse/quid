//! Recovery system for QuID identities using threshold secret sharing
//! 
//! This module implements a quantum-resistant social recovery system where
//! users can split their private key into shares distributed to trusted guardians.

use crate::{crypto::KeyPair, QuIDError, Result};
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use sha3::Shake256;
use sha3::digest::{Update, ExtendableOutput, XofReader};

/// A recovery share containing part of a secret key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryShare {
    /// Share identifier (1 to n)
    pub share_id: u8,
    /// Threshold required to recover (t)
    pub threshold: u8,
    /// Total number of shares (n)
    pub total_shares: u8,
    /// The encrypted share data
    pub share_data: Vec<u8>,
    /// Identity ID this share belongs to
    pub identity_id: Vec<u8>,
    /// Guardian information
    pub guardian_info: GuardianInfo,
    /// Signature from the identity owner
    pub signature: Vec<u8>,
    /// Creation timestamp
    pub created_at: u64,
    /// QuID version
    pub version: String,
}

/// Information about the guardian holding this share
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianInfo {
    pub name: String,
    pub contact: String,        // Email, phone, etc.
    pub public_key: Vec<u8>,    // Guardian's own QuID public key (optional)
}

/// Recovery coordinator that handles the sharing and reconstruction process
pub struct RecoveryCoordinator;

impl RecoveryCoordinator {
    /// Generate recovery shares for a private key using threshold secret sharing
    pub fn generate_shares(
        keypair: &KeyPair,
        identity_id: &[u8],
        guardians: Vec<GuardianInfo>,
        threshold: u8,
    ) -> Result<Vec<RecoveryShare>> {
        if guardians.is_empty() {
            return Err(QuIDError::ExtensionError("No guardians provided".to_string()));
        }
        
        let total_shares = guardians.len() as u8;
        if threshold > total_shares {
            return Err(QuIDError::ExtensionError(
                "Threshold cannot exceed total shares".to_string()
            ));
        }
        
        if threshold == 0 {
            return Err(QuIDError::ExtensionError(
                "Threshold must be at least 1".to_string()
            ));
        }

        // Use simplified secret sharing for now - in production you'd use proper Shamir's
        let private_key = keypair.private_key.expose_secret();
        let shares = Self::split_secret(private_key, threshold, total_shares)?;
        
        let mut recovery_shares = Vec::new();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| QuIDError::CryptoError(format!("Time error: {}", e)))?
            .as_secs();

        for (i, (share_data, guardian)) in shares.iter().zip(guardians.iter()).enumerate() {
            let share_id = (i + 1) as u8;
            
            // Create the share
            let mut share = RecoveryShare {
                share_id,
                threshold,
                total_shares,
                share_data: share_data.clone(),
                identity_id: identity_id.to_vec(),
                guardian_info: guardian.clone(),
                signature: Vec::new(), // Will be filled below
                created_at: timestamp,
                version: crate::QUID_VERSION.to_string(),
            };
            
            // Sign the share with the identity's private key
            let share_bytes = Self::serialize_share_for_signing(&share)?;
            share.signature = keypair.sign(&share_bytes)?;
            
            recovery_shares.push(share);
        }
        
        Ok(recovery_shares)
    }
    
    /// Recover a private key from threshold shares
    pub fn recover_private_key(
        shares: Vec<RecoveryShare>,
        original_keypair: &KeyPair, // For signature verification
    ) -> Result<Secret<Vec<u8>>> {
        if shares.is_empty() {
            return Err(QuIDError::ExtensionError("No shares provided".to_string()));
        }
        
        // Verify all shares have the same parameters
        let first_share = &shares[0];
        let required_threshold = first_share.threshold;
        let identity_id = &first_share.identity_id;
        
        if shares.len() < required_threshold as usize {
            return Err(QuIDError::ExtensionError(format!(
                "Need {} shares, got {}",
                required_threshold,
                shares.len()
            )));
        }
        
        // Verify all shares are for the same identity and parameters
        for share in &shares {
            if share.threshold != required_threshold {
                return Err(QuIDError::ExtensionError(
                    "Shares have different thresholds".to_string()
                ));
            }
            if share.identity_id != *identity_id {
                return Err(QuIDError::ExtensionError(
                    "Shares are for different identities".to_string()
                ));
            }
            
            // Verify share signature
            let share_bytes = Self::serialize_share_for_signing(share)?;
            if !original_keypair.verify(&share_bytes, &share.signature)? {
                return Err(QuIDError::ExtensionError(format!(
                    "Invalid signature on share {}",
                    share.share_id
                )));
            }
        }
        
        // Take only the required threshold number of shares
        let mut verified_shares = shares;
        verified_shares.truncate(required_threshold as usize);
        
        // Reconstruct the secret
        let share_data: Vec<Vec<u8>> = verified_shares
            .iter()
            .map(|s| s.share_data.clone())
            .collect();
        
        Self::reconstruct_secret(&share_data, required_threshold)
    }
    
    /// Split a secret into shares (PLACEHOLDER - use proper Shamir's in production)
    fn split_secret(
        secret: &[u8],
        threshold: u8,
        total_shares: u8,
    ) -> Result<Vec<Vec<u8>>> {
        // This is a PLACEHOLDER implementation for demonstration
        // In production, use a proper Shamir Secret Sharing library
        
        let mut shares = Vec::new();
        
        for share_id in 1..=total_shares {
            // Generate deterministic but unique share data
            let mut hasher = Shake256::default();
            hasher.update(b"quid-recovery-share");
            hasher.update(secret);
            hasher.update(&threshold.to_le_bytes());
            hasher.update(&total_shares.to_le_bytes());
            hasher.update(&share_id.to_le_bytes());
            
            let mut reader = hasher.finalize_xof();
            let mut share_data = vec![0u8; secret.len() + 16]; // Extra bytes for metadata
            reader.read(&mut share_data);
            
            // Embed the original secret XORed with share-specific key (INSECURE - just for demo)
            for (i, &byte) in secret.iter().enumerate() {
                share_data[i] ^= byte;
            }
            
            shares.push(share_data);
        }
        
        Ok(shares)
    }
    
    /// Reconstruct secret from shares (PLACEHOLDER)
    fn reconstruct_secret(
        shares: &[Vec<u8>],
        threshold: u8,
    ) -> Result<Secret<Vec<u8>>> {
        // This is a PLACEHOLDER - in production use proper Shamir reconstruction
        
        if shares.is_empty() {
            return Err(QuIDError::ExtensionError("No shares provided".to_string()));
        }
        
        // For this demo, we just XOR the first share with itself to recover the original
        // This obviously doesn't provide real threshold properties
        let first_share = &shares[0];
        let secret_len = first_share.len() - 16; // Remove metadata bytes
        
        let mut reconstructed = vec![0u8; secret_len];
        
        // Regenerate the share-specific key and XOR back
        let mut hasher = Shake256::default();
        hasher.update(b"quid-recovery-share");
        // We would need the original secret to regenerate this properly
        // This is why this is just a placeholder implementation
        
        let mut reader = hasher.finalize_xof();
        let mut key_data = vec![0u8; secret_len + 16];
        reader.read(&mut key_data);
        
        for i in 0..secret_len {
            reconstructed[i] = first_share[i] ^ key_data[i];
        }
        
        Ok(Secret::new(reconstructed))
    }
    
    /// Serialize share data for signing (excludes the signature field)
    pub fn serialize_share_for_signing(share: &RecoveryShare) -> Result<Vec<u8>> {
        let signable_share = SignableShare {
            share_id: share.share_id,
            threshold: share.threshold,
            total_shares: share.total_shares,
            share_data: &share.share_data,
            identity_id: &share.identity_id,
            guardian_info: &share.guardian_info,
            created_at: share.created_at,
            version: &share.version,
        };
        
        serde_json::to_vec(&signable_share)
            .map_err(QuIDError::SerializationError)
    }
}

/// Share data that gets signed (excludes signature field to avoid recursion)
#[derive(Serialize)]
struct SignableShare<'a> {
    share_id: u8,
    threshold: u8,
    total_shares: u8,
    share_data: &'a [u8],
    identity_id: &'a [u8],
    guardian_info: &'a GuardianInfo,
    created_at: u64,
    version: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecurityLevel;

    #[test]
    fn test_recovery_share_generation() {
        let keypair = KeyPair::generate(SecurityLevel::Level1).unwrap();
        let identity_id = b"test-identity-id".to_vec();
        
        let guardians = vec![
            GuardianInfo {
                name: "Alice".to_string(),
                contact: "alice@example.com".to_string(),
                public_key: vec![1, 2, 3],
            },
            GuardianInfo {
                name: "Bob".to_string(),
                contact: "bob@example.com".to_string(),
                public_key: vec![4, 5, 6],
            },
            GuardianInfo {
                name: "Charlie".to_string(),
                contact: "charlie@example.com".to_string(),
                public_key: vec![7, 8, 9],
            },
        ];
        
        let shares = RecoveryCoordinator::generate_shares(
            &keypair,
            &identity_id,
            guardians,
            2, // 2-of-3 threshold
        ).unwrap();
        
        assert_eq!(shares.len(), 3);
        assert_eq!(shares[0].threshold, 2);
        assert_eq!(shares[0].total_shares, 3);
        assert_eq!(shares[0].identity_id, identity_id);
    }

    #[test]
    fn test_invalid_threshold() {
        let keypair = KeyPair::generate(SecurityLevel::Level1).unwrap();
        let identity_id = b"test-identity-id".to_vec();
        let guardians = vec![GuardianInfo {
            name: "Alice".to_string(),
            contact: "alice@example.com".to_string(),
            public_key: vec![1, 2, 3],
        }];
        
        // Threshold greater than shares should fail
        let result = RecoveryCoordinator::generate_shares(
            &keypair,
            &identity_id,
            guardians,
            2, // 2-of-1 - impossible
        );
        
        assert!(result.is_err());
    }

    #[test]
    fn test_share_signature_verification() {
        let keypair = KeyPair::generate(SecurityLevel::Level1).unwrap();
        let identity_id = b"test-identity-id".to_vec();
        
        let guardians = vec![
            GuardianInfo {
                name: "Alice".to_string(),
                contact: "alice@example.com".to_string(),
                public_key: vec![1, 2, 3],
            },
            GuardianInfo {
                name: "Bob".to_string(),
                contact: "bob@example.com".to_string(),
                public_key: vec![4, 5, 6],
            },
        ];
        
        let shares = RecoveryCoordinator::generate_shares(
            &keypair,
            &identity_id,
            guardians,
            2,
        ).unwrap();
        
        // Verify each share signature
        for share in &shares {
            let share_bytes = RecoveryCoordinator::serialize_share_for_signing(share).unwrap();
            assert!(keypair.verify(&share_bytes, &share.signature).unwrap());
        }
    }
}
