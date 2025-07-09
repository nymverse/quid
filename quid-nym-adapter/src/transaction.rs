//! Transaction building for Nym blockchain

use crate::{NymAdapterResult, NymAdapterError, PrivacyLevel, config::TransactionConfig, types::NymTransaction};
use chrono::Utc;
use uuid::Uuid;

/// Nym transaction builder
#[derive(Debug, Clone)]
pub struct NymTransactionBuilder {
    config: TransactionConfig,
}

impl NymTransactionBuilder {
    /// Create new transaction builder
    pub fn new(config: &TransactionConfig) -> NymAdapterResult<Self> {
        Ok(Self {
            config: config.clone(),
        })
    }

    /// Build public transaction
    pub async fn build_public_transaction(
        &self,
        from: &str,
        to: &str,
        amount: u128,
    ) -> NymAdapterResult<NymTransaction> {
        Ok(NymTransaction {
            id: Uuid::new_v4().to_string(),
            from: from.to_string(),
            to: to.to_string(),
            amount,
            fee: self.calculate_fee(amount, PrivacyLevel::Public)?,
            privacy_level: PrivacyLevel::Public,
            nonce: 0, // Would be retrieved from account state
            data: vec![],
            privacy_proof: None,
            mixnet_routing: None,
            timestamp: Utc::now(),
        })
    }

    /// Calculate transaction fee
    fn calculate_fee(&self, amount: u128, privacy_level: PrivacyLevel) -> NymAdapterResult<u128> {
        let base_fee = self.config.gas_price * self.config.default_gas_limit as u128;
        let privacy_premium = match privacy_level {
            PrivacyLevel::Public => 0,
            PrivacyLevel::Shielded => base_fee / 10,
            PrivacyLevel::Anonymous => base_fee / 5,
            PrivacyLevel::Mixnet => base_fee / 2,
        };
        
        Ok(base_fee + privacy_premium)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_public_transaction_building() {
        let config = TransactionConfig::default();
        let builder = NymTransactionBuilder::new(&config).unwrap();
        
        let tx = builder.build_public_transaction("nym1sender", "nym1recipient", 1000).await.unwrap();
        
        assert_eq!(tx.from, "nym1sender");
        assert_eq!(tx.to, "nym1recipient");
        assert_eq!(tx.amount, 1000);
        assert_eq!(tx.privacy_level, PrivacyLevel::Public);
        assert!(tx.privacy_proof.is_none());
    }

    #[test]
    fn test_fee_calculation() {
        let config = TransactionConfig::default();
        let builder = NymTransactionBuilder::new(&config).unwrap();
        
        let public_fee = builder.calculate_fee(1000, PrivacyLevel::Public).unwrap();
        let shielded_fee = builder.calculate_fee(1000, PrivacyLevel::Shielded).unwrap();
        let anonymous_fee = builder.calculate_fee(1000, PrivacyLevel::Anonymous).unwrap();
        let mixnet_fee = builder.calculate_fee(1000, PrivacyLevel::Mixnet).unwrap();
        
        assert!(public_fee < shielded_fee);
        assert!(shielded_fee < anonymous_fee);
        assert!(anonymous_fee < mixnet_fee);
    }
}