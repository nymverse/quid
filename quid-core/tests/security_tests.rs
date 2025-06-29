//! Security-focused tests for QuID core functionality
//!
//! These tests focus on edge cases, attack vectors, and security properties

use quid_core::{QuIDIdentity, SecurityLevel, IdentityStorage, StorageConfig};
use proptest::prelude::*;
use secrecy::SecretString;
use tempfile::TempDir;

/// Test that malformed data doesn't cause panics or unexpected behavior
#[test]
fn test_malformed_storage_data() {
    let temp_dir = TempDir::new().unwrap();
    let config = StorageConfig {
        storage_path: temp_dir.path().to_path_buf(),
        kdf_iterations: 1000,
        auto_backup: false,
        max_backups: 3,
    };
    let mut storage = IdentityStorage::new(config).unwrap();
    
    // Create a malformed file that looks like an identity
    let malformed_data = b"invalid json data";
    let identity_id = vec![1, 2, 3, 4];
    let storage_path = temp_dir.path().join(format!("{}.quid", hex::encode(&identity_id)));
    std::fs::write(&storage_path, malformed_data).unwrap();
    
    // Try to load the malformed identity - should fail gracefully
    let password = SecretString::new("test_password".to_string());
    let result = storage.load_identity(&identity_id, &password);
    assert!(result.is_err());
    
    // Should not panic or cause memory corruption
}

/// Test that very long passwords don't cause issues
#[test]
fn test_very_long_passwords() {
    let temp_dir = TempDir::new().unwrap();
    let config = StorageConfig {
        storage_path: temp_dir.path().to_path_buf(),
        kdf_iterations: 100, // Lower for test performance
        auto_backup: false,
        max_backups: 3,
    };
    let mut storage = IdentityStorage::new(config).unwrap();
    
    let (identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
    
    // Very long password (10KB)
    let long_password = "a".repeat(10_000);
    let secret_password = SecretString::new(long_password);
    
    // Should handle without issues
    let store_result = storage.store_identity(&identity, &keypair, &secret_password);
    assert!(store_result.is_ok());
    
    let load_result = storage.load_identity(&identity.id, &secret_password);
    assert!(load_result.is_ok());
}

/// Test edge cases with empty and minimal data
#[test]
fn test_edge_case_data() {
    let temp_dir = TempDir::new().unwrap();
    let config = StorageConfig {
        storage_path: temp_dir.path().to_path_buf(),
        kdf_iterations: 100,
        auto_backup: false,
        max_backups: 3,
    };
    let mut storage = IdentityStorage::new(config).unwrap();
    
    let (mut identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
    
    // Add empty extension
    identity.add_extension(&keypair, "empty".to_string(), vec![]).unwrap();
    
    // Add extension with special characters in name
    identity.add_extension(&keypair, "special!@#$%^&*()".to_string(), vec![1, 2, 3]).unwrap();
    
    let password = SecretString::new("test".to_string());
    
    // Should handle gracefully
    let store_result = storage.store_identity(&identity, &keypair, &password);
    assert!(store_result.is_ok());
    
    let (loaded_identity, loaded_keypair) = storage.load_identity(&identity.id, &password).unwrap();
    assert!(loaded_identity.verify_extensions(&loaded_keypair).unwrap());
}

/// Test that concurrent access doesn't cause corruption
#[test]
fn test_concurrent_access() {
    use std::sync::Arc;
    use std::thread;
    
    let temp_dir = TempDir::new().unwrap();
    let config = StorageConfig {
        storage_path: temp_dir.path().to_path_buf(),
        kdf_iterations: 100,
        auto_backup: false,
        max_backups: 3,
    };
    
    // Create multiple identities
    let identities: Vec<_> = (0..5).map(|_| {
        QuIDIdentity::new(SecurityLevel::Level1).unwrap()
    }).collect();
    
    let config = Arc::new(config);
    let identities = Arc::new(identities);
    
    // Spawn multiple threads to store identities concurrently
    let handles: Vec<_> = (0..5).map(|i| {
        let config = Arc::clone(&config);
        let identities = Arc::clone(&identities);
        
        thread::spawn(move || {
            let mut storage = IdentityStorage::new((*config).clone()).unwrap();
            let (identity, keypair) = &identities[i];
            let password = SecretString::new(format!("password{}", i));
            
            // Store and immediately load
            storage.store_identity(identity, keypair, &password).unwrap();
            let (loaded_identity, _) = storage.load_identity(&identity.id, &password).unwrap();
            
            // Verify integrity
            assert_eq!(identity.id, loaded_identity.id);
        })
    }).collect();
    
    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }
}

// Property-based security tests using proptest
proptest! {
    /// Test that random binary data as passwords doesn't crash
    #[test]
    fn prop_fuzz_passwords(
        password_bytes in prop::collection::vec(any::<u8>(), 1..1000)
    ) {
        // Convert bytes to string (may contain invalid UTF-8, but that's fine for testing)
        let password_string = String::from_utf8_lossy(&password_bytes).to_string();
        let password = SecretString::new(password_string);
        
        let temp_dir = TempDir::new().unwrap();
        let config = StorageConfig {
            storage_path: temp_dir.path().to_path_buf(),
            kdf_iterations: 100,
            auto_backup: false,
            max_backups: 3,
        };
        let mut storage = IdentityStorage::new(config).unwrap();
        
        let (identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        
        // Should not panic regardless of password content
        let store_result = storage.store_identity(&identity, &keypair, &password);
        prop_assert!(store_result.is_ok());
        
        let load_result = storage.load_identity(&identity.id, &password);
        prop_assert!(load_result.is_ok());
    }

    /// Test that random extension data doesn't cause issues
    #[test]
    fn prop_fuzz_extensions(
        extension_name in "[a-zA-Z0-9_-]{1,50}",
        extension_data in prop::collection::vec(any::<u8>(), 0..10000)
    ) {
        let (mut identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        
        // Add extension with random data
        let add_result = identity.add_extension(&keypair, extension_name.clone(), extension_data);
        prop_assert!(add_result.is_ok());
        
        // Verify extension exists and is valid
        prop_assert!(identity.extensions.contains_key(&extension_name));
        prop_assert!(identity.verify_extensions(&keypair).unwrap());
    }

    /// Test storage with random file system stress
    #[test]
    fn prop_fuzz_storage_operations(
        operations in prop::collection::vec(
            prop_oneof![
                Just("store"),
                Just("load"),
                Just("backup"),
                Just("list"),
                Just("delete")
            ],
            1..20
        )
    ) {
        let temp_dir = TempDir::new().unwrap();
        let config = StorageConfig {
            storage_path: temp_dir.path().to_path_buf(),
            kdf_iterations: 100,
            auto_backup: false,
            max_backups: 3,
        };
        let mut storage = IdentityStorage::new(config).unwrap();
        
        let (identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let password = SecretString::new("test_password".to_string());
        
        let mut stored = false;
        
        for operation in operations {
            match operation {
                "store" => {
                    let result = storage.store_identity(&identity, &keypair, &password);
                    prop_assert!(result.is_ok());
                    stored = true;
                }
                "load" => {
                    if stored {
                        let result = storage.load_identity(&identity.id, &password);
                        prop_assert!(result.is_ok());
                    }
                }
                "backup" => {
                    if stored {
                        let result = storage.backup_identity(&identity.id, Some("test".to_string()));
                        prop_assert!(result.is_ok());
                    }
                }
                "list" => {
                    let result = storage.list_identities();
                    prop_assert!(result.is_ok());
                }
                "delete" => {
                    if stored {
                        let result = storage.delete_identity(&identity.id);
                        prop_assert!(result.is_ok());
                        stored = false;
                    }
                }
                _ => unreachable!()
            }
        }
    }

    /// Test that signature verification is resilient to bit flips
    #[test]
    fn prop_signature_bit_flip_resistance(
        message in prop::collection::vec(any::<u8>(), 1..1000),
        flip_position in 0usize..64usize // Signature is up to 128 bytes, test first 64
    ) {
        let (_, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        
        let signature = keypair.sign(&message).unwrap();
        
        // Flip a bit in the signature
        if flip_position < signature.len() {
            let mut corrupted_signature = signature.clone();
            corrupted_signature[flip_position] ^= 1;
            
            // Corrupted signature should not verify (with very high probability)
            let verification_result = keypair.verify(&message, &corrupted_signature);
            prop_assert!(verification_result.is_ok());
            if signature != corrupted_signature {
                prop_assert!(!verification_result.unwrap());
            }
        }
    }

    /// Test that identity IDs are collision resistant
    #[test]
    fn prop_identity_id_collision_resistance(
        _dummy in 0u32..1000u32 // Just to generate multiple test cases
    ) {
        // Generate many identities quickly
        let identities: Vec<_> = (0..100).map(|_| {
            QuIDIdentity::new(SecurityLevel::Level1).unwrap().0
        }).collect();
        
        // Check for ID collisions
        for i in 0..identities.len() {
            for j in i+1..identities.len() {
                prop_assert_ne!(&identities[i].id, &identities[j].id);
            }
        }
    }

    /// Test memory safety with large data structures
    #[test]
    fn prop_memory_safety_large_data(
        large_data_size in 1000usize..50000usize
    ) {
        let (mut identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        
        // Create large extension data
        let large_data = vec![42u8; large_data_size];
        
        // Should handle large data without issues
        let add_result = identity.add_extension(&keypair, "large".to_string(), large_data);
        prop_assert!(add_result.is_ok());
        
        // Verification should still work
        prop_assert!(identity.verify_extensions(&keypair).unwrap());
    }
}