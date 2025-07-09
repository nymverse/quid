//! Coinbase exchange implementation

use crate::{Exchange, ExchangeFactory, ExchangeType, ExchangeResult, ExchangeError};
use quid_core::QuIDIdentity;
use crate::config::ExchangeConfig;
use std::sync::Arc;

/// Coinbase exchange implementation
#[derive(Debug)]
pub struct CoinbaseExchange {
    // TODO: Implementation
}

/// Coinbase exchange factory
#[derive(Debug)]
pub struct CoinbaseFactory;

impl CoinbaseFactory {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl ExchangeFactory for CoinbaseFactory {
    async fn create_exchange(&self, _config: &ExchangeConfig, _identity: &QuIDIdentity) -> ExchangeResult<Arc<dyn Exchange>> {
        Err(ExchangeError::UnsupportedExchange("Coinbase implementation not yet complete".to_string()))
    }
    
    fn exchange_type(&self) -> ExchangeType {
        ExchangeType::Coinbase
    }
    
    fn validate_config(&self, _config: &ExchangeConfig) -> ExchangeResult<()> {
        Ok(())
    }
}