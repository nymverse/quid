//! Integration tests for QuID core functionality

use quid_core::{QuIDIdentity, SecurityLevel, RecoveryCoordinator, GuardianInfo, IdentityStorage, StorageConfig};
use proptest::prelude::*;
use secrecy::SecretString;
use tempfile::TempDir;

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

    #[test]
    fn prop_storage_encryption_integrity(
        password in "[a-zA-Z0-9]{8,20}",
        extension_data in prop::collection::vec(any::<u8>(), 0..500)
    ) {
        let temp_dir = TempDir::new().unwrap();
        let config = StorageConfig {
            storage_path: temp_dir.path().to_path_buf(),
            kdf_iterations: 1000, // Lower for faster tests
            auto_backup: false,
            max_backups: 3,
        };
        let mut storage = IdentityStorage::new(config).unwrap();
        
        // Create identity with extension
        let (mut identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        identity.add_extension(&keypair, "test_ext".to_string(), extension_data.clone()).unwrap();
        
        let secret_password = SecretString::new(password);
        
        // Store and load should be consistent
        storage.store_identity(&identity, &keypair, &secret_password).unwrap();
        let (loaded_identity, loaded_keypair) = storage.load_identity(&identity.id, &secret_password).unwrap();
        
        // Verify integrity
        prop_assert_eq!(&identity.id, &loaded_identity.id);
        prop_assert_eq!(&identity.public_key, &loaded_identity.public_key);
        prop_assert_eq!(identity.security_level, loaded_identity.security_level);
        prop_assert_eq!(&keypair.public_key, &loaded_keypair.public_key);
        
        // Verify extensions are preserved
        prop_assert!(loaded_identity.extensions.contains_key("test_ext"));
        prop_assert!(loaded_identity.verify_extensions(&loaded_keypair).unwrap());
    }

    #[test]
    fn prop_backup_restore_integrity(
        password in "[a-zA-Z0-9]{8,20}",
        backup_hint in "[a-zA-Z0-9-_]{1,10}"
    ) {
        let temp_dir = TempDir::new().unwrap();
        let config = StorageConfig {
            storage_path: temp_dir.path().to_path_buf(),
            kdf_iterations: 1000,
            auto_backup: false,
            max_backups: 5,
        };
        let mut storage = IdentityStorage::new(config).unwrap();
        
        let (identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let secret_password = SecretString::new(password);
        
        // Store identity
        storage.store_identity(&identity, &keypair, &secret_password).unwrap();
        
        // Create backup
        let backup_path = storage.backup_identity(&identity.id, Some(backup_hint)).unwrap();
        prop_assert!(backup_path.exists());
        
        // Delete original
        storage.delete_identity(&identity.id).unwrap();
        
        // Restore from backup
        let (restored_identity, restored_keypair) = storage.restore_from_backup(&backup_path, &secret_password).unwrap();
        
        // Verify restoration integrity
        prop_assert_eq!(&identity.id, &restored_identity.id);
        prop_assert_eq!(&identity.public_key, &restored_identity.public_key);
        prop_assert_eq!(&keypair.public_key, &restored_keypair.public_key);
    }

    #[test]
    fn prop_security_levels_consistency(
        level in prop_oneof![
            Just(SecurityLevel::Level1),
            Just(SecurityLevel::Level3),
            Just(SecurityLevel::Level5),
        ]
    ) {
        let (identity1, keypair1) = QuIDIdentity::new(level).unwrap();
        let (identity2, keypair2) = QuIDIdentity::new(level).unwrap();
        
        // Both identities should have the same security level
        prop_assert_eq!(identity1.security_level, level);
        prop_assert_eq!(identity2.security_level, level);
        prop_assert_eq!(keypair1.security_level, level);
        prop_assert_eq!(keypair2.security_level, level);
        
        // Key sizes should be consistent for the same security level
        let expected_size = match level {
            SecurityLevel::Level1 => 32,
            SecurityLevel::Level3 => 48,
            SecurityLevel::Level5 => 64,
        };
        
        prop_assert_eq!(keypair1.public_key.len(), expected_size);
        prop_assert_eq!(keypair2.public_key.len(), expected_size);
        
        // Cross-verification should fail (different keypairs)
        let message = b"test message";
        let sig1 = keypair1.sign(message).unwrap();
        prop_assert!(!keypair2.verify(message, &sig1).unwrap());
    }

    #[test]
    fn prop_recovery_shares_consistency(
        threshold in 2u8..5u8,
        num_guardians in 3u8..10u8
    ) {
        prop_assume!(threshold <= num_guardians);
        
        let (identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        
        // Generate guardian info
        let guardians: Vec<GuardianInfo> = (0..num_guardians).map(|i| {
            GuardianInfo {
                name: format!("Guardian{}", i),
                contact: format!("guardian{}@example.com", i),
                public_key: vec![i; 32],
            }
        }).collect();
        
        // Generate recovery shares
        let shares = RecoveryCoordinator::generate_shares(
            &keypair,
            &identity.id,
            guardians,
            threshold,
        ).unwrap();
        
        // Should have correct number of shares
        prop_assert_eq!(shares.len(), num_guardians as usize);
        
        // All shares should have the same identity_id
        for share in &shares {
            prop_assert_eq!(&share.identity_id, &identity.id);
            prop_assert_eq!(share.threshold, threshold);
            
            // Share should be signed correctly
            let share_bytes = RecoveryCoordinator::serialize_share_for_signing(share).unwrap();
            prop_assert!(keypair.verify(&share_bytes, &share.signature).unwrap());
        }
    }

    #[test]
    fn prop_wrong_password_fails(
        password1 in "[a-zA-Z0-9]{8,20}",
        password2 in "[a-zA-Z0-9]{8,20}"
    ) {
        prop_assume!(password1 != password2);
        
        let temp_dir = TempDir::new().unwrap();
        let config = StorageConfig {
            storage_path: temp_dir.path().to_path_buf(),
            kdf_iterations: 1000,
            auto_backup: false,
            max_backups: 3,
        };
        let mut storage = IdentityStorage::new(config.clone()).unwrap();
        
        let (identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        
        // Store with first password
        let secret1 = SecretString::new(password1);
        storage.store_identity(&identity, &keypair, &secret1).unwrap();
        
        // Create fresh storage to avoid cache
        let mut fresh_storage = IdentityStorage::new(config).unwrap();
        
        // Try to load with wrong password - should fail
        let secret2 = SecretString::new(password2);
        let result = fresh_storage.load_identity(&identity.id, &secret2);
        prop_assert!(result.is_err());
    }
}