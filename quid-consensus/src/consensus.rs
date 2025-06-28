//! Consensus engine for NYM blockchain
//! 
//! Implements a simplified Byzantine Fault Tolerant (BFT) consensus algorithm
//! where validators propose and vote on blocks in rounds.


use crate::{
    Block, Blockchain, ValidatorSet, TransactionPool, 
    NymTransaction, BlockHeight, Result, ConsensusError
};
use crate::validator::ValidatorOps;  
use quid_core::{QuIDIdentity, crypto::KeyPair};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH, Instant};


/// Current state of the consensus engine
#[derive(Debug, Clone, PartialEq)]
pub enum ConsensusState {
    /// Waiting for transactions to propose a block
    Idle,
    
    /// Proposing a new block
    Proposing {
        height: BlockHeight,
        round: u32,
        proposal: Option<Block>,
    },
    
    /// Voting on a proposed block
    Voting {
        height: BlockHeight,
        round: u32,
        proposal: Block,
        votes: HashMap<Vec<u8>, Vote>,
    },
    
    /// Committing a block to the chain
    Committing {
        height: BlockHeight,
        block: Block,
    },
    
    /// Syncing with the network
    Syncing,
}

/// A vote on a proposed block
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Vote {
    /// Height of the block being voted on
    pub height: BlockHeight,
    
    /// Round number
    pub round: u32,
    
    /// Hash of the block being voted on
    pub block_hash: Vec<u8>,
    
    /// Voter's QuID identity ID
    pub voter: Vec<u8>,
    
    /// Vote type
    pub vote_type: VoteType,
    
    /// Timestamp of the vote
    pub timestamp: u64,
    
    /// Signature of the vote
    pub signature: Vec<u8>,
}

/// Type of vote
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VoteType {
    /// Vote to accept the proposed block
    Accept,
    
    /// Vote to reject the proposed block
    Reject,
    
    /// Timeout vote (no proposal received)
    Timeout,
}

/// Configuration for the consensus engine
#[derive(Debug, Clone)]
pub struct ConsensusConfig {
    /// Maximum time to wait for a proposal (seconds)
    pub proposal_timeout: u64,
    
    /// Maximum time to wait for votes (seconds)
    pub vote_timeout: u64,
    
    /// Maximum time for a complete round (seconds)
    pub round_timeout: u64,
    
    /// Maximum transactions per block
    pub max_transactions_per_block: usize,
    
    /// Minimum transactions to trigger block creation
    pub min_transactions_to_propose: usize,
    
    /// Maximum block creation interval (seconds)
    pub max_block_interval: u64,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            proposal_timeout: 10,
            vote_timeout: 5,
            round_timeout: 30,
            max_transactions_per_block: crate::constants::MAX_TRANSACTIONS_PER_BLOCK,
            min_transactions_to_propose: 1,
            max_block_interval: crate::constants::BLOCK_TIME,
        }
    }
}

/// The main consensus engine
pub struct ConsensusEngine {
    /// Current state of consensus
    state: ConsensusState,
    
    /// The blockchain we're building consensus on
    blockchain: Blockchain,
    
    /// Current validator set
    validator_set: ValidatorSet,
    
    /// Our identity and keypair (if we're a validator)
    our_identity: Option<(QuIDIdentity, KeyPair)>,
    
    /// Transaction pool
    transaction_pool: TransactionPool,
    
    /// Configuration
    config: ConsensusConfig,
    
    /// Last block creation time
    last_block_time: Instant,
    
    /// Current round start time
    round_start_time: Option<Instant>,
    
    /// Pending votes for current height/round
    pending_votes: HashMap<(BlockHeight, u32), HashMap<Vec<u8>, Vote>>,
    
    /// Network abstraction (simplified for now)
    network_tx: Option<tokio::sync::mpsc::UnboundedSender<NetworkMessage>>,
}

/// Network messages for consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    /// Broadcast a block proposal
    BlockProposal {
        proposal: Block,
        proposer: Vec<u8>,
    },
    
    /// Broadcast a vote
    Vote(Vote),
    
    /// Request missing blocks
    BlockRequest {
        from_height: BlockHeight,
        to_height: BlockHeight,
    },
    
    /// Response with requested blocks
    BlockResponse {
        blocks: Vec<Block>,
    },
    
    /// Sync request
    SyncRequest {
        our_height: BlockHeight,
    },
    
    /// Transaction broadcast
    TransactionBroadcast {
        transaction: NymTransaction,
    },
}

impl ConsensusEngine {
    /// Create a new consensus engine
    pub fn new(
        blockchain: Blockchain,
        validator_set: ValidatorSet,
        our_identity: Option<(QuIDIdentity, KeyPair)>,
        config: ConsensusConfig,
    ) -> Self {
        Self {
            state: ConsensusState::Idle,
            blockchain,
            validator_set,
            our_identity,
            transaction_pool: TransactionPool::new(100), // Max 100 tx per sender
            config,
            last_block_time: Instant::now(),
            round_start_time: None,
            pending_votes: HashMap::new(),
            network_tx: None,
        }
    }
    
    /// Set network sender for broadcasting messages
    pub fn set_network_sender(&mut self, sender: tokio::sync::mpsc::UnboundedSender<NetworkMessage>) {
        self.network_tx = Some(sender);
    }
    
    /// Get current consensus state
    pub fn state(&self) -> &ConsensusState {
        &self.state
    }
    
    /// Get current blockchain height
    pub fn height(&self) -> BlockHeight {
        self.blockchain.height()
    }
    
    /// Check if we are a validator
    pub fn is_validator(&self) -> bool {
        if let Some((identity, _)) = &self.our_identity {
            self.validator_set.get_validator(&identity.id).is_some()
        } else {
            false
        }
    }
    
    /// Add a transaction to the pool
    pub fn add_transaction(&mut self, transaction: NymTransaction) -> Result<()> {
        // Validate transaction signature if not from genesis
        if transaction.from != vec![0; 32] {
            // TODO: Verify transaction signature with sender's QuID
            // For now, we trust all transactions
        }
        
        self.transaction_pool.add_transaction(transaction.clone())?;
        
        // Broadcast transaction to network
        if let Some(sender) = &self.network_tx {
            let _ = sender.send(NetworkMessage::TransactionBroadcast { transaction });
        }
        
        Ok(())
    }
    
    /// Main consensus step - call this regularly
    pub async fn step(&mut self) -> Result<()> {
        match &self.state.clone() {
            ConsensusState::Idle => {
                self.handle_idle_state().await?;
            }
            
            ConsensusState::Proposing { height, round, proposal } => {
                self.handle_proposing_state(*height, *round, proposal.clone()).await?;
            }
            
            ConsensusState::Voting { height, round, proposal, votes } => {
                self.handle_voting_state(*height, *round, proposal.clone(), votes.clone()).await?;
            }
            
            ConsensusState::Committing { height, block } => {
                self.handle_committing_state(*height, block.clone()).await?;
            }
            
            ConsensusState::Syncing => {
                self.handle_syncing_state().await?;
            }
        }
        
        Ok(())
    }
    
    /// Handle incoming network messages
    pub async fn handle_network_message(&mut self, message: NetworkMessage) -> Result<()> {
        match message {
            NetworkMessage::BlockProposal { proposal, proposer } => {
                self.handle_block_proposal(proposal, proposer).await?;
            }
            
            NetworkMessage::Vote(vote) => {
                self.handle_vote(vote).await?;
            }
            
            NetworkMessage::BlockRequest { from_height, to_height } => {
                self.handle_block_request(from_height, to_height).await?;
            }
            
            NetworkMessage::BlockResponse { blocks } => {
                self.handle_block_response(blocks).await?;
            }
            
            NetworkMessage::SyncRequest { our_height } => {
                self.handle_sync_request(our_height).await?;
            }
            
            NetworkMessage::TransactionBroadcast { transaction } => {
                let _ = self.add_transaction(transaction);
            }
        }
        
        Ok(())
    }
    
    /// Handle idle state - decide whether to propose a block
    async fn handle_idle_state(&mut self) -> Result<()> {
        let current_height = self.blockchain.height() + 1;
        let should_propose = self.should_propose_block();
        
        if should_propose {
            // Check if we are the proposer for this round
            if let Some(proposer_id) = ValidatorOps::select_proposer(&self.validator_set, current_height, 0) {
                if let Some((our_identity, _)) = &self.our_identity {
                    if proposer_id == our_identity.id {
                        // We are the proposer - create a block
                        self.start_proposing(current_height, 0).await?;
                    } else {
                        // Wait for proposal from the designated proposer
                        self.start_waiting_for_proposal(current_height, 0).await?;
                    }
                } else {
                    // We're not a validator, just wait
                    self.start_waiting_for_proposal(current_height, 0).await?;
                }
            }
        }
        
        Ok(())
    }
    
    /// Check if we should propose a new block
    fn should_propose_block(&self) -> bool {
        let pending_count = self.transaction_pool.pending_count();
        let time_since_last_block = self.last_block_time.elapsed();
        
        // Propose if we have enough transactions or enough time has passed
        pending_count >= self.config.min_transactions_to_propose
            || time_since_last_block.as_secs() >= self.config.max_block_interval
    }
    
    /// Start proposing a new block
    async fn start_proposing(&mut self, height: BlockHeight, round: u32) -> Result<()> {
        // Get transactions for the block
        let transactions = self.transaction_pool.get_next_transactions(
            self.config.max_transactions_per_block
        );
        
        if let Some((our_identity, _)) = &self.our_identity {
            // Create the block
            let previous_hash = if let Some(latest_block) = self.blockchain.latest_block() {
                latest_block.hash()?
            } else {
                vec![0; 32]
            };
            
            let mut block = Block::new(
                height,
                previous_hash,
                transactions,
                our_identity.id.clone(),
            )?;
            
            // Sign the block
            if let Some((_, keypair)) = &self.our_identity {
                let block_signature = ValidatorOps::sign_block(&block, keypair)?;
                block.validator_signatures.insert(our_identity.id.clone(), block_signature);
            }
            
            // Broadcast proposal
            if let Some(sender) = &self.network_tx {
                let _ = sender.send(NetworkMessage::BlockProposal {
                    proposal: block.clone(),
                    proposer: our_identity.id.clone(),
                });
            }
            
            self.state = ConsensusState::Proposing {
                height,
                round,
                proposal: Some(block),
            };
            self.round_start_time = Some(Instant::now());
        }
        
        Ok(())
    }
    
    /// Start waiting for a proposal from another validator
    async fn start_waiting_for_proposal(&mut self, height: BlockHeight, round: u32) -> Result<()> {
        self.state = ConsensusState::Proposing {
            height,
            round,
            proposal: None,
        };
        self.round_start_time = Some(Instant::now());
        
        Ok(())
    }
    
    /// Handle proposing state
    async fn handle_proposing_state(
        &mut self,
        height: BlockHeight,
        round: u32,
        proposal: Option<Block>,
    ) -> Result<()> {
        // Check for timeout
        if let Some(start_time) = self.round_start_time {
            if start_time.elapsed().as_secs() >= self.config.proposal_timeout {
                // Timeout - move to next round or vote timeout
                if proposal.is_some() {
                    // We proposed, wait for votes
                    self.start_voting(height, round, proposal.unwrap()).await?;
                } else {
                    // No proposal received, vote timeout
                    self.vote_timeout(height, round).await?;
                }
            }
        }
        
        Ok(())
    }
    
    /// Handle voting state
    async fn handle_voting_state(
        &mut self,
        height: BlockHeight,
        round: u32,
        proposal: Block,
        votes: HashMap<Vec<u8>, Vote>,
    ) -> Result<()> {
        // Check if we have consensus
        if self.validator_set.has_consensus(&votes.iter().map(|(k, v)| (k.clone(), v.signature.clone())).collect()) {
            // Count accept votes
            let accept_votes = votes.values().filter(|v| v.vote_type == VoteType::Accept).count();
            let required = self.validator_set.required_signatures();
            
            if accept_votes >= required {
                // Consensus reached - commit the block
                self.state = ConsensusState::Committing {
                    height,
                    block: proposal,
                };
                return Ok(());
            }
        }
        
        // Check for timeout
        if let Some(start_time) = self.round_start_time {
            if start_time.elapsed().as_secs() >= self.config.vote_timeout {
                // Voting timeout - move to next round
                self.start_next_round(height, round + 1).await?;
            }
        }
        
        Ok(())
    }
    
    /// Handle committing state
    async fn handle_committing_state(&mut self, height: BlockHeight, block: Block) -> Result<()> {
        // Add block to blockchain
        self.blockchain.add_block(block.clone())?;
        
        // Update validator metrics
        self.validator_set.update_metrics(&block, &block.validator_signatures);
        
        // Reset state
        self.state = ConsensusState::Idle;
        self.last_block_time = Instant::now();
        self.round_start_time = None;
        
        // Clean up votes for this height
        self.pending_votes.retain(|(h, _), _| *h > height);
        
        println!("✅ Block {} committed with {} transactions", height, block.transactions.len());
        
        Ok(())
    }
    
    /// Handle syncing state
    async fn handle_syncing_state(&mut self) -> Result<()> {
        // Simple sync implementation - request missing blocks
        if let Some(sender) = &self.network_tx {
            let our_height = self.blockchain.height();
            let _ = sender.send(NetworkMessage::SyncRequest { our_height });
        }
        
        // For now, just return to idle after attempting sync
        self.state = ConsensusState::Idle;
        
        Ok(())
    }
    
    /// Start voting on a proposed block
    async fn start_voting(&mut self, height: BlockHeight, round: u32, proposal: Block) -> Result<()> {
        // Validate the proposal
        let is_valid = self.validate_proposal(&proposal).await;
        
        // Cast our vote if we're a validator
        if self.is_validator() {
            let vote_type = if is_valid { VoteType::Accept } else { VoteType::Reject };
            self.cast_vote(height, round, &proposal, vote_type).await?;
        }
        
        // Get existing votes for this height/round
        let votes = self.pending_votes
            .get(&(height, round))
            .cloned()
            .unwrap_or_default();
        
        self.state = ConsensusState::Voting {
            height,
            round,
            proposal,
            votes,
        };
        
        Ok(())
    }
    
    /// Validate a block proposal
    async fn validate_proposal(&self, proposal: &Block) -> bool {
        // Basic validation
        if let Err(_) = proposal.validate(self.blockchain.latest_block()) {
            return false;
        }
        
        // Check if proposer is valid
        let expected_proposer = ValidatorOps::select_proposer(
            &self.validator_set,
            proposal.header.height,
            0, // Assume round 0 for now
        );
        
        if expected_proposer != Some(proposal.header.proposer.clone()) {
            return false;
        }
        
        // TODO: Validate all transactions in the proposal
        
        true
    }
    
    /// Cast a vote
    async fn cast_vote(
        &mut self,
        height: BlockHeight,
        round: u32,
        proposal: &Block,
        vote_type: VoteType,
    ) -> Result<()> {
        if let Some((our_identity, keypair)) = &self.our_identity {
            let block_hash = proposal.hash()?;
            
            let vote = Vote {
                height,
                round,
                block_hash,
                voter: our_identity.id.clone(),
                vote_type,
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                signature: Vec::new(),
            };
            
            // Sign the vote
            let vote_data = self.serialize_vote_for_signing(&vote)?;
            let signature = keypair.sign(&vote_data)?;
            
            let mut signed_vote = vote;
            signed_vote.signature = signature;
            
            // Store our vote
            self.pending_votes
                .entry((height, round))
                .or_insert_with(HashMap::new)
                .insert(our_identity.id.clone(), signed_vote.clone());
            
            // Broadcast vote
            if let Some(sender) = &self.network_tx {
                let _ = sender.send(NetworkMessage::Vote(signed_vote));
            }
        }
        
        Ok(())
    }
    
    /// Vote timeout (no proposal received)
    async fn vote_timeout(&mut self, height: BlockHeight, round: u32) -> Result<()> {
        if self.is_validator() {
            if let Some((our_identity, keypair)) = &self.our_identity {
                let vote = Vote {
                    height,
                    round,
                    block_hash: vec![0; 32], // Empty hash for timeout
                    voter: our_identity.id.clone(),
                    vote_type: VoteType::Timeout,
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    signature: Vec::new(),
                };
                
                let vote_data = self.serialize_vote_for_signing(&vote)?;
                let signature = keypair.sign(&vote_data)?;
                
                let mut signed_vote = vote;
                signed_vote.signature = signature;
                
                // Broadcast timeout vote
                if let Some(sender) = &self.network_tx {
                    let _ = sender.send(NetworkMessage::Vote(signed_vote));
                }
            }
        }
        
        // Move to next round
        self.start_next_round(height, round + 1).await?;
        
        Ok(())
    }
    
    /// Start the next round
    async fn start_next_round(&mut self, height: BlockHeight, round: u32) -> Result<()> {
        // Select new proposer for this round
        if let Some(proposer_id) = ValidatorOps::select_proposer(&self.validator_set, height, round) {
            if let Some((our_identity, _)) = &self.our_identity {
                if proposer_id == our_identity.id {
                    self.start_proposing(height, round).await?;
                } else {
                    self.start_waiting_for_proposal(height, round).await?;
                }
            } else {
                self.start_waiting_for_proposal(height, round).await?;
            }
        }
        
        Ok(())
    }
    
    /// Handle incoming block proposal
    async fn handle_block_proposal(&mut self, proposal: Block, _proposer: Vec<u8>) -> Result<()> {
        let height = proposal.header.height;
        let current_height = self.blockchain.height() + 1;
        
        if height == current_height {
            // This is for the current height we're working on
            if let ConsensusState::Proposing { height: state_height, round, .. } = &self.state {
                if *state_height == height {
                    // Start voting on this proposal
                    self.start_voting(height, *round, proposal).await?;
                }
            }
        } else if height > current_height {
            // Future block - we might be behind
            self.state = ConsensusState::Syncing;
        }
        // Ignore old proposals
        
        Ok(())
    }
    
    /// Handle incoming vote
    async fn handle_vote(&mut self, vote: Vote) -> Result<()> {
        // Store the vote (clone it first)
        let vote_key = (vote.height, vote.round);
        let vote_height = vote.height;
        let vote_round = vote.round;
        
        self.pending_votes
            .entry(vote_key)
            .or_insert_with(HashMap::new)
            .insert(vote.voter.clone(), vote.clone());  // Clone here
        
        // Update current voting state if applicable
        if let ConsensusState::Voting { height, round, proposal, .. } = &self.state.clone() {
            if vote_height == *height && vote_round == *round { 
                let votes = self.pending_votes
                    .get(&(*height, *round))
                    .cloned()
                    .unwrap_or_default();
                
                self.state = ConsensusState::Voting {
                    height: *height,
                    round: *round,
                    proposal: proposal.clone(),
                    votes,
                };
            }
        }
        
        Ok(())
    }
    
    /// Handle block request
    async fn handle_block_request(&mut self, from_height: BlockHeight, to_height: BlockHeight) -> Result<()> {
        let mut blocks = Vec::new();
        
        for height in from_height..=to_height {
            if let Some(block) = self.blockchain.get_block(height) {
                blocks.push(block.clone());
            }
        }
        
        if let Some(sender) = &self.network_tx {
            let _ = sender.send(NetworkMessage::BlockResponse { blocks });
        }
        
        Ok(())
    }
    
    /// Handle block response
    async fn handle_block_response(&mut self, blocks: Vec<Block>) -> Result<()> {
        // Simple sync - add blocks in order
        for block in blocks {
            if block.header.height == self.blockchain.height() + 1 {
                // This is the next block we need
                match self.blockchain.add_block(block) {
                    Ok(_) => {
                        println!("📥 Synced block {}", self.blockchain.height());
                    }
                    Err(e) => {
                        println!("❌ Failed to sync block: {}", e);
                        break;
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Handle sync request
    async fn handle_sync_request(&mut self, their_height: BlockHeight) -> Result<()> {
        let our_height = self.blockchain.height();
        
        if our_height > their_height {
            // Send them blocks they're missing
            let blocks_to_send = (their_height + 1)..=(our_height.min(their_height + 10)); // Send up to 10 blocks
            
            if let Some(sender) = &self.network_tx {
                let _ = sender.send(NetworkMessage::BlockRequest {
                    from_height: blocks_to_send.start().clone(),
                    to_height: blocks_to_send.end().clone(),
                });
            }
        }
        
        Ok(())
    }
    
    /// Serialize vote for signing
    fn serialize_vote_for_signing(&self, vote: &Vote) -> Result<Vec<u8>> {
        let signable_vote = SignableVote {
            height: vote.height,
            round: vote.round,
            block_hash: &vote.block_hash,
            voter: &vote.voter,
            vote_type: &vote.vote_type,
            timestamp: vote.timestamp,
        };
        
        serde_json::to_vec(&signable_vote)
            .map_err(|e| ConsensusError::SerializationError(e.to_string()))
    }
}

/// Vote data for signing (excludes signature)
#[derive(Serialize)]
struct SignableVote<'a> {
    height: BlockHeight,
    round: u32,
    block_hash: &'a [u8],
    voter: &'a [u8],
    vote_type: &'a VoteType,
    timestamp: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use quid_core::SecurityLevel;

    #[test]
    fn test_consensus_config_default() {
        let config = ConsensusConfig::default();
        assert!(config.proposal_timeout > 0);
        assert!(config.vote_timeout > 0);
        assert!(config.max_transactions_per_block > 0);
    }

    #[test]
    fn test_vote_creation() {
        let vote = Vote {
            height: 1,
            round: 0,
            block_hash: vec![1, 2, 3, 4],
            voter: vec![5, 6, 7, 8],
            vote_type: VoteType::Accept,
            timestamp: 1234567890,
            signature: vec![],
        };
        
        assert_eq!(vote.height, 1);
        assert_eq!(vote.vote_type, VoteType::Accept);
    }

    #[tokio::test]
    async fn test_consensus_engine_creation() {
        let (identity1, _) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        let (identity2, keypair2) = QuIDIdentity::new(SecurityLevel::Level1).unwrap();
        
        let initial_distribution = vec![(identity1.clone(), 1000)];
        let genesis = Block::genesis(initial_distribution).unwrap();
        let blockchain = Blockchain::new(genesis).unwrap();
        
        let validators = vec![identity1.clone()];
        let validator_set = ValidatorSet::from_genesis(validators, 10);
        
        let engine = ConsensusEngine::new(
            blockchain,
            validator_set,
            Some((identity2, keypair2)),
            ConsensusConfig::default(),
        );
        
        assert_eq!(engine.state(), &ConsensusState::Idle);
        assert_eq!(engine.height(), 0);
    }
}
