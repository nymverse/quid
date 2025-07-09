//! Trading utilities and strategies

use crate::{ExchangeResult, ExchangeError};
use crate::types::{OrderRequest, Order, TradingPair};

/// Trading utilities
pub mod utils {
    use super::*;
    
    /// Validate order request
    pub fn validate_order(order: &OrderRequest) -> ExchangeResult<()> {
        if order.quantity <= 0.0 {
            return Err(ExchangeError::InvalidOrder("Quantity must be positive".to_string()));
        }
        
        if let Some(price) = order.price {
            if price <= 0.0 {
                return Err(ExchangeError::InvalidOrder("Price must be positive".to_string()));
            }
        }
        
        Ok(())
    }
    
    /// Calculate order value
    pub fn calculate_order_value(order: &OrderRequest) -> ExchangeResult<f64> {
        match order.price {
            Some(price) => Ok(order.quantity * price),
            None => Err(ExchangeError::InvalidOrder("Cannot calculate value for market order".to_string())),
        }
    }
}

/// Trading strategies
pub mod strategies {
    use super::*;
    
    /// Basic trading strategy interface
    pub trait TradingStrategy {
        fn name(&self) -> &str;
        fn analyze(&self, pair: &TradingPair) -> ExchangeResult<Option<OrderRequest>>;
    }
    
    /// Simple buy and hold strategy
    pub struct BuyAndHoldStrategy {
        pub name: String,
    }
    
    impl TradingStrategy for BuyAndHoldStrategy {
        fn name(&self) -> &str {
            &self.name
        }
        
        fn analyze(&self, _pair: &TradingPair) -> ExchangeResult<Option<OrderRequest>> {
            // TODO: Implement strategy logic
            Ok(None)
        }
    }
}