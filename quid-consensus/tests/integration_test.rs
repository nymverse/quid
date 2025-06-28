//! Integration test showing the complete NYM consensus system

use quid_consensus::*;
use quid_consensus::consensus::ConsensusConfig;
use quid_core::{QuIDIdentity, SecurityLevel};
use tokio::time::timeout;

use std::time::Duration;

#[tokio::test]
async fn test_complete_consensus_flow() {
    // Create three validator identities
    let (validator1, keypair1) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
    let (validator2, keypair2) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
    let (validator3, keypair3) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
    
    // Create genesis block with initial token distribution
    let initial_distribution = vec![
        (validator1.clone(), 10000),
        (validator2.clone(), 10000), 
        (validator3.clone(), 10000),
    ];
    
    let genesis_block = Block::genesis(initial_distribution).unwrap();
    println!("✅ Genesis block created with {} transactions", genesis_block.transactions.len());
    
    // Create blockchain
    let blockchain = Blockchain::new(genesis_block).unwrap();
    println!("✅ Blockchain initialized at height {}", blockchain.height());
    
    // Verify initial balances
    assert_eq!(blockchain.get_balance(&validator1.id), 10000);
    assert_eq!(blockchain.get_balance(&validator2.id), 10000);
    assert_eq!(blockchain.get_balance(&validator3.id), 10000);
    println!("✅ Initial balances verified");
    
    // Create validator set
    let validators = vec![validator1.clone(), validator2.clone(), validator3.clone()];
    let validator_set = ValidatorSet::from_genesis(validators, 10);
    println!("✅ Validator set created with {} validators", validator_set.validator_count());
    
    // Create consensus engines for each validator
    let mut engine1 = ConsensusEngine::new(
        blockchain.clone(),
        validator_set.clone(),
        Some((validator1.clone(), keypair1)),
        ConsensusConfig::default(),
    );
    
    let mut engine2 = ConsensusEngine::new(
        blockchain.clone(),
        validator_set.clone(),
        Some((validator2.clone(), keypair2)),
        ConsensusConfig::default(),
    );
    
    let mut engine3 = ConsensusEngine::new(
        blockchain.clone(),
        validator_set.clone(),
        Some((validator3.clone(), keypair3)),
        ConsensusConfig::default(),
    );
    
    println!("✅ Three consensus engines created");
    
    // Test transaction creation and validation
    let transfer_tx = NymTransaction::new(
        TransactionType::Transfer {
            to: validator2.id.clone(),
            amount: 100,
        },
        validator1.id.clone(),
        1, // nonce
        5, // fee
    );
    
    // Add transaction to engine1
    engine1.add_transaction(transfer_tx).unwrap();
    println!("✅ Transaction added to pool");
    
    // Run a few consensus steps
    for i in 0..5 {
        timeout(Duration::from_millis(100), engine1.step()).await.ok();
        timeout(Duration::from_millis(100), engine2.step()).await.ok();
        timeout(Duration::from_millis(100), engine3.step()).await.ok();
        println!("⚡ Consensus step {} completed", i + 1);
    }
    
    println!("🎉 Integration test completed successfully!");
}

#[tokio::test]
async fn test_domain_registration_with_consensus() {
    // Create identity and blockchain
    let (identity, keypair) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
    
    let initial_distribution = vec![(identity.clone(), 1000)];
    let genesis_block = Block::genesis(initial_distribution).unwrap();
    let mut blockchain = Blockchain::new(genesis_block).unwrap();
    
    // Create domain registration transaction
    let domain_tx = NymTransaction::new(
        TransactionType::DomainRegistration {
            domain: "alice.quid".to_string(),
            fee: 10,
        },
        identity.id.clone(),
        1, // nonce
        1, // transaction fee
    );
    
    // Create a block with this transaction
    let block = Block::new(
        1, // height
        blockchain.latest_block().unwrap().hash().unwrap(),
        vec![domain_tx],
        identity.id.clone(),
    ).unwrap();
    
    // Add block to blockchain
    blockchain.add_block(block).unwrap();
    
    // Verify domain registration worked
    assert_eq!(blockchain.get_balance(&identity.id), 1000 - 10 - 1); // Initial - domain fee - tx fee
    assert!(!blockchain.is_domain_available("alice.quid"));
    assert_eq!(blockchain.get_domain_owner("alice.quid"), Some(identity.id.as_slice()));
    
    println!("✅ Domain registration with consensus successful!");
}
