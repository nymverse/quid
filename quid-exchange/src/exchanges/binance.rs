//! Binance exchange implementation

use crate::{Exchange, ExchangeFactory, ExchangeType, ExchangeResult, ExchangeError};
use quid_core::QuIDIdentity;
use crate::config::ExchangeConfig;
use std::sync::Arc;

/// Binance exchange implementation
#[derive(Debug)]
pub struct BinanceExchange {
    // TODO: Implementation
}

/// Binance exchange factory
#[derive(Debug)]
pub struct BinanceFactory;

impl BinanceFactory {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl ExchangeFactory for BinanceFactory {
    async fn create_exchange(&self, _config: &ExchangeConfig, _identity: &QuIDIdentity) -> ExchangeResult<Arc<dyn Exchange>> {
        Err(ExchangeError::UnsupportedExchange("Binance implementation not yet complete".to_string()))
    }
    
    fn exchange_type(&self) -> ExchangeType {
        ExchangeType::Binance
    }
    
    fn validate_config(&self, _config: &ExchangeConfig) -> ExchangeResult<()> {
        Ok(())
    }
}