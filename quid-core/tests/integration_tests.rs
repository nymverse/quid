//! Integration tests for QuID core functionality

use quid_core::{QuIDIdentity, SecurityLevel, RecoveryCoordinator, GuardianInfo};
use proptest::prelude::*;

#[test]
fn test_identity_lifecycle() {
    // Create identity
    let (_identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
    
    // Sign a message
    let message = b"test message";
    let signature = keypair.sign(message).unwrap();
    
    // Verify signature
    assert!(keypair.verify(message, &signature).unwrap());
    
    // Verify different message fails
    let different_message = b"different message";
    assert!(!keypair.verify(different_message, &signature).unwrap());
}

#[test]
fn test_extension_system() {
    let (mut identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
    
    // Add extension
    let extension_data = b"extension data".to_vec();
    identity.add_extension(&keypair, "test_ext".to_string(), extension_data.clone()).unwrap();
    
    // Verify extension exists
    assert!(identity.extensions.contains_key("test_ext"));
    
    // Verify extensions
    assert!(identity.verify_extensions(&keypair).unwrap());
}

#[test]
fn test_recovery_system_integration() {
    let (identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
    
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
    
    // Generate recovery shares
    let shares = RecoveryCoordinator::generate_shares(
        &keypair,
        &identity.id,
        guardians,
        2, // 2-of-3 threshold
    ).unwrap();
    
    assert_eq!(shares.len(), 3);
    
    // Verify all shares are signed correctly
    for share in &shares {
        let share_bytes = RecoveryCoordinator::serialize_share_for_signing(share).unwrap();
        assert!(keypair.verify(&share_bytes, &share.signature).unwrap());
    }
}

// Property-based tests
proptest! {
    #[test]
    fn prop_identity_ids_are_unique(
        _seed1 in any::<u64>(),
        _seed2 in any::<u64>(),
    ) {
        // Create two identities with slight time difference
        let (id1, _) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1)); // Ensure different timestamp
        let (id2, _) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        
        prop_assert_ne!(id1.id, id2.id);
    }
    
    #[test]
    fn prop_signatures_are_deterministic(
        message in prop::collection::vec(any::<u8>(), 0..1000)
    ) {
        let (_, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        
        let sig1 = keypair.sign(&message).unwrap();
        let sig2 = keypair.sign(&message).unwrap();
        
        prop_assert_eq!(sig1, sig2);
    }
    
    #[test]
    fn prop_verification_consistency(
        message in prop::collection::vec(any::<u8>(), 0..1000),
        wrong_message in prop::collection::vec(any::<u8>(), 0..1000)
    ) {
        let (_, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        
        let signature = keypair.sign(&message).unwrap();
        
        // Correct message should verify
        prop_assert!(keypair.verify(&message, &signature).unwrap());
        
        // Wrong message should not verify (unless by extreme coincidence)
        if message != wrong_message {
            prop_assert!(!keypair.verify(&wrong_message, &signature).unwrap());
        }
    }
}