//! Kraken exchange implementation

use crate::{Exchange, ExchangeFactory, ExchangeType, ExchangeResult, ExchangeError};
use quid_core::QuIDIdentity;
use crate::config::ExchangeConfig;
use std::sync::Arc;

/// Kraken exchange implementation
#[derive(Debug)]
pub struct KrakenExchange {
    // TODO: Implementation
}

/// Kraken exchange factory
#[derive(Debug)]
pub struct KrakenFactory;

impl KrakenFactory {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl ExchangeFactory for KrakenFactory {
    async fn create_exchange(&self, _config: &ExchangeConfig, _identity: &QuIDIdentity) -> ExchangeResult<Arc<dyn Exchange>> {
        Err(ExchangeError::UnsupportedExchange("Kraken implementation not yet complete".to_string()))
    }
    
    fn exchange_type(&self) -> ExchangeType {
        ExchangeType::Kraken
    }
    
    fn validate_config(&self, _config: &ExchangeConfig) -> ExchangeResult<()> {
        Ok(())
    }
}