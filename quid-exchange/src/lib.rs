//! QuID Exchange Integration
//!
//! This crate provides secure cryptocurrency exchange integration using QuID quantum-resistant
//! authentication. It enables users to authenticate to multiple exchanges with a single QuID
//! identity while maintaining the highest security standards.
//!
//! Features:
//! - Quantum-resistant API authentication for major exchanges
//! - Secure API key management and derivation
//! - Cross-exchange authentication with unified identity
//! - Rate limiting and error handling
//! - Trading operations with enhanced security
//! - Portfolio synchronization across exchanges

use quid_core::{QuIDIdentity, SecurityLevel};
use quid_wallet::{QuIDWalletManager, BlockchainType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use secrecy::{SecretString, ExposeSecret};

pub mod error;
pub mod types;
pub mod config;
pub mod auth;
pub mod api;
pub mod exchanges {
    #[cfg(feature = "binance")]
    pub mod binance;
    #[cfg(feature = "coinbase")]
    pub mod coinbase;
    #[cfg(feature = "kraken")]
    pub mod kraken;
    #[cfg(feature = "okx")]
    pub mod okx;
}
pub mod trading;
pub mod portfolio;

pub use error::{ExchangeError, ExchangeResult};
pub use types::*;
pub use config::ExchangeConfig;

/// QuID exchange manager for unified cryptocurrency exchange access
#[derive(Debug)]
pub struct QuIDExchangeManager {
    /// Configuration
    config: ExchangeConfig,
    /// QuID identity for authentication
    identity: QuIDIdentity,
    /// Wallet manager for transaction signing
    wallet_manager: Arc<QuIDWalletManager>,
    /// Connected exchanges
    exchanges: Arc<RwLock<HashMap<String, Arc<dyn Exchange>>>>,
    /// API key manager for secure key derivation
    api_key_manager: Arc<auth::APIKeyManager>,
    /// Portfolio synchronizer
    portfolio_sync: Arc<portfolio::PortfolioSynchronizer>,
    /// Rate limiter for API calls
    rate_limiter: Arc<governor::RateLimiter<governor::state::NotKeyed, governor::state::InMemoryState, governor::clock::DefaultClock>>,
}

/// Exchange trait for unified interface across different trading platforms
#[async_trait::async_trait]
pub trait Exchange: Send + Sync + std::fmt::Debug {
    /// Get exchange name
    fn name(&self) -> &str;
    
    /// Get exchange type
    fn exchange_type(&self) -> ExchangeType;
    
    /// Authenticate with exchange using QuID identity
    async fn authenticate(&self, identity: &QuIDIdentity) -> ExchangeResult<()>;
    
    /// Get account information
    async fn get_account_info(&self) -> ExchangeResult<AccountInfo>;
    
    /// Get account balances
    async fn get_balances(&self) -> ExchangeResult<Vec<Balance>>;
    
    /// Get trading pairs
    async fn get_trading_pairs(&self) -> ExchangeResult<Vec<TradingPair>>;
    
    /// Get order book
    async fn get_order_book(&self, pair: &TradingPair) -> ExchangeResult<OrderBook>;
    
    /// Get recent trades
    async fn get_recent_trades(&self, pair: &TradingPair, limit: Option<u32>) -> ExchangeResult<Vec<Trade>>;
    
    /// Place order
    async fn place_order(&self, order: &OrderRequest) -> ExchangeResult<Order>;
    
    /// Cancel order
    async fn cancel_order(&self, order_id: &str) -> ExchangeResult<()>;
    
    /// Get order status
    async fn get_order_status(&self, order_id: &str) -> ExchangeResult<Order>;
    
    /// Get order history
    async fn get_order_history(&self, pair: Option<&TradingPair>, limit: Option<u32>) -> ExchangeResult<Vec<Order>>;
    
    /// Get trade history
    async fn get_trade_history(&self, pair: Option<&TradingPair>, limit: Option<u32>) -> ExchangeResult<Vec<Trade>>;
    
    /// Get deposit address
    async fn get_deposit_address(&self, asset: &str) -> ExchangeResult<DepositAddress>;
    
    /// Withdraw funds
    async fn withdraw(&self, request: &WithdrawRequest) -> ExchangeResult<Withdrawal>;
    
    /// Get withdrawal history
    async fn get_withdrawal_history(&self, asset: Option<&str>, limit: Option<u32>) -> ExchangeResult<Vec<Withdrawal>>;
    
    /// Get deposit history
    async fn get_deposit_history(&self, asset: Option<&str>, limit: Option<u32>) -> ExchangeResult<Vec<Deposit>>;
    
    /// Check exchange health
    async fn health_check(&self) -> ExchangeResult<HealthStatus>;
}

/// Exchange factory trait for creating exchange instances
#[async_trait::async_trait]
pub trait ExchangeFactory: Send + Sync {
    /// Create exchange instance
    async fn create_exchange(&self, config: &ExchangeConfig, identity: &QuIDIdentity) -> ExchangeResult<Arc<dyn Exchange>>;
    
    /// Get supported exchange type
    fn exchange_type(&self) -> ExchangeType;
    
    /// Validate configuration
    fn validate_config(&self, config: &ExchangeConfig) -> ExchangeResult<()>;
}

impl QuIDExchangeManager {
    /// Create new QuID exchange manager
    pub async fn new(
        config: ExchangeConfig,
        identity: QuIDIdentity,
        wallet_manager: Arc<QuIDWalletManager>,
    ) -> ExchangeResult<Self> {
        let exchanges = Arc::new(RwLock::new(HashMap::new()));
        
        let api_key_manager = Arc::new(auth::APIKeyManager::new(identity.clone()).await?);
        
        let portfolio_sync = Arc::new(portfolio::PortfolioSynchronizer::new(
            config.portfolio.clone(),
            wallet_manager.clone(),
        ).await?);
        
        // Create rate limiter (1000 requests per minute by default)
        let rate_limiter = Arc::new(governor::RateLimiter::direct(
            governor::Quota::per_minute(nonzero_ext::nonzero!(1000_u32))
        ));
        
        Ok(Self {
            config,
            identity,
            wallet_manager,
            exchanges,
            api_key_manager,
            portfolio_sync,
            rate_limiter,
        })
    }
    
    /// Connect to an exchange
    pub async fn connect_exchange(&self, exchange_name: &str, exchange_type: ExchangeType) -> ExchangeResult<()> {
        let factory = self.get_exchange_factory(exchange_type)?;
        let exchange = factory.create_exchange(&self.config, &self.identity).await?;
        
        // Authenticate with the exchange
        exchange.authenticate(&self.identity).await?;
        
        // Store the exchange connection
        let mut exchanges = self.exchanges.write().await;
        exchanges.insert(exchange_name.to_string(), exchange);
        
        tracing::info!("Connected to exchange: {} ({})", exchange_name, exchange_type);
        
        Ok(())
    }
    
    /// Disconnect from an exchange
    pub async fn disconnect_exchange(&self, exchange_name: &str) -> ExchangeResult<()> {
        let mut exchanges = self.exchanges.write().await;
        if exchanges.remove(exchange_name).is_some() {
            tracing::info!("Disconnected from exchange: {}", exchange_name);
            Ok(())
        } else {
            Err(ExchangeError::ExchangeNotFound(exchange_name.to_string()))
        }
    }
    
    /// Get connected exchanges
    pub async fn get_connected_exchanges(&self) -> Vec<String> {
        let exchanges = self.exchanges.read().await;
        exchanges.keys().cloned().collect()
    }
    
    /// Get exchange by name
    pub async fn get_exchange(&self, exchange_name: &str) -> ExchangeResult<Arc<dyn Exchange>> {
        let exchanges = self.exchanges.read().await;
        exchanges.get(exchange_name)
            .cloned()
            .ok_or_else(|| ExchangeError::ExchangeNotFound(exchange_name.to_string()))
    }
    
    /// Get unified account information across all exchanges
    pub async fn get_unified_account_info(&self) -> ExchangeResult<UnifiedAccountInfo> {
        let mut account_infos = Vec::new();
        
        let exchanges = self.exchanges.read().await;
        for (name, exchange) in exchanges.iter() {
            match exchange.get_account_info().await {
                Ok(info) => account_infos.push((name.clone(), info)),
                Err(e) => tracing::warn!("Failed to get account info from {}: {}", name, e),
            }
        }
        
        Ok(UnifiedAccountInfo {
            exchange_accounts: account_infos,
            total_exchanges: exchanges.len(),
            last_updated: Utc::now(),
        })
    }
    
    /// Get unified balances across all exchanges
    pub async fn get_unified_balances(&self) -> ExchangeResult<Vec<UnifiedBalance>> {
        let mut unified_balances: HashMap<String, UnifiedBalance> = HashMap::new();
        
        let exchanges = self.exchanges.read().await;
        for (exchange_name, exchange) in exchanges.iter() {
            match exchange.get_balances().await {
                Ok(balances) => {
                    for balance in balances {
                        let entry = unified_balances.entry(balance.asset.clone()).or_insert(UnifiedBalance {
                            asset: balance.asset.clone(),
                            total_available: 0.0,
                            total_locked: 0.0,
                            exchange_balances: Vec::new(),
                        });
                        
                        entry.total_available += balance.available;
                        entry.total_locked += balance.locked;
                        entry.exchange_balances.push(ExchangeBalance {
                            exchange_name: exchange_name.clone(),
                            available: balance.available,
                            locked: balance.locked,
                        });
                    }
                }
                Err(e) => tracing::warn!("Failed to get balances from {}: {}", exchange_name, e),
            }
        }
        
        Ok(unified_balances.into_values().collect())
    }
    
    /// Place order on specific exchange
    pub async fn place_order(&self, exchange_name: &str, order: &OrderRequest) -> ExchangeResult<Order> {
        // Check rate limit
        self.rate_limiter.check().map_err(|_| ExchangeError::RateLimitExceeded)?;
        
        let exchange = self.get_exchange(exchange_name).await?;
        
        // Validate order with wallet manager
        self.validate_order_with_wallet(order).await?;
        
        let result = exchange.place_order(order).await?;
        
        // Update portfolio
        self.portfolio_sync.update_order(&result).await?;
        
        tracing::info!("Order placed on {}: {:?}", exchange_name, result);
        
        Ok(result)
    }
    
    /// Cancel order on specific exchange
    pub async fn cancel_order(&self, exchange_name: &str, order_id: &str) -> ExchangeResult<()> {
        let exchange = self.get_exchange(exchange_name).await?;
        exchange.cancel_order(order_id).await?;
        
        tracing::info!("Order cancelled on {}: {}", exchange_name, order_id);
        
        Ok(())
    }
    
    /// Get order status from specific exchange
    pub async fn get_order_status(&self, exchange_name: &str, order_id: &str) -> ExchangeResult<Order> {
        let exchange = self.get_exchange(exchange_name).await?;
        exchange.get_order_status(order_id).await
    }
    
    /// Sync portfolio across all exchanges
    pub async fn sync_portfolio(&self) -> ExchangeResult<()> {
        let exchanges = self.exchanges.read().await;
        let exchange_refs: Vec<_> = exchanges.values().cloned().collect();
        drop(exchanges);
        
        self.portfolio_sync.sync_all_exchanges(&exchange_refs).await?;
        
        Ok(())
    }
    
    /// Get API key manager
    pub fn api_key_manager(&self) -> Arc<auth::APIKeyManager> {
        self.api_key_manager.clone()
    }
    
    /// Get portfolio synchronizer
    pub fn portfolio_sync(&self) -> Arc<portfolio::PortfolioSynchronizer> {
        self.portfolio_sync.clone()
    }
    
    /// Validate order with wallet manager
    async fn validate_order_with_wallet(&self, order: &OrderRequest) -> ExchangeResult<()> {
        // Check if we have sufficient balance
        let balances = self.get_unified_balances().await?;
        
        let base_asset = &order.pair.base_asset;
        let quote_asset = &order.pair.quote_asset;
        
        match order.side {
            OrderSide::Buy => {
                // Check quote asset balance
                let quote_balance = balances.iter()
                    .find(|b| b.asset == *quote_asset)
                    .map(|b| b.total_available)
                    .unwrap_or(0.0);
                
                let required_amount = order.quantity * order.price.unwrap_or(0.0);
                if quote_balance < required_amount {
                    return Err(ExchangeError::InsufficientBalance {
                        asset: quote_asset.clone(),
                        required: required_amount,
                        available: quote_balance,
                    });
                }
            }
            OrderSide::Sell => {
                // Check base asset balance
                let base_balance = balances.iter()
                    .find(|b| b.asset == *base_asset)
                    .map(|b| b.total_available)
                    .unwrap_or(0.0);
                
                if base_balance < order.quantity {
                    return Err(ExchangeError::InsufficientBalance {
                        asset: base_asset.clone(),
                        required: order.quantity,
                        available: base_balance,
                    });
                }
            }
        }
        
        Ok(())
    }
    
    /// Get exchange factory for exchange type
    fn get_exchange_factory(&self, exchange_type: ExchangeType) -> ExchangeResult<Box<dyn ExchangeFactory>> {
        match exchange_type {
            #[cfg(feature = "binance")]
            ExchangeType::Binance => Ok(Box::new(exchanges::binance::BinanceFactory::new())),
            #[cfg(feature = "coinbase")]
            ExchangeType::Coinbase => Ok(Box::new(exchanges::coinbase::CoinbaseFactory::new())),
            #[cfg(feature = "kraken")]
            ExchangeType::Kraken => Ok(Box::new(exchanges::kraken::KrakenFactory::new())),
            #[cfg(feature = "okx")]
            ExchangeType::OKX => Ok(Box::new(exchanges::okx::OKXFactory::new())),
            _ => Err(ExchangeError::UnsupportedExchange(exchange_type.to_string())),
        }
    }
}

/// Unified account information across exchanges
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedAccountInfo {
    pub exchange_accounts: Vec<(String, AccountInfo)>,
    pub total_exchanges: usize,
    pub last_updated: DateTime<Utc>,
}

/// Unified balance across exchanges
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedBalance {
    pub asset: String,
    pub total_available: f64,
    pub total_locked: f64,
    pub exchange_balances: Vec<ExchangeBalance>,
}

/// Exchange-specific balance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeBalance {
    pub exchange_name: String,
    pub available: f64,
    pub locked: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use quid_core::SecurityLevel;
    use quid_wallet::WalletConfig;
    
    #[tokio::test]
    async fn test_exchange_manager_creation() {
        let config = ExchangeConfig::default();
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        let wallet_config = WalletConfig::default();
        let wallet_manager = Arc::new(QuIDWalletManager::new(wallet_config).await.unwrap());
        
        let manager = QuIDExchangeManager::new(config, identity, wallet_manager).await.unwrap();
        
        let exchanges = manager.get_connected_exchanges().await;
        assert_eq!(exchanges.len(), 0);
    }
    
    #[tokio::test]
    async fn test_unified_account_info() {
        let config = ExchangeConfig::default();
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        let wallet_config = WalletConfig::default();
        let wallet_manager = Arc::new(QuIDWalletManager::new(wallet_config).await.unwrap());
        
        let manager = QuIDExchangeManager::new(config, identity, wallet_manager).await.unwrap();
        
        let account_info = manager.get_unified_account_info().await.unwrap();
        assert_eq!(account_info.total_exchanges, 0);
        assert_eq!(account_info.exchange_accounts.len(), 0);
    }
    
    #[tokio::test]
    async fn test_unified_balances() {
        let config = ExchangeConfig::default();
        let identity = QuIDIdentity::generate(SecurityLevel::High).unwrap();
        let wallet_config = WalletConfig::default();
        let wallet_manager = Arc::new(QuIDWalletManager::new(wallet_config).await.unwrap());
        
        let manager = QuIDExchangeManager::new(config, identity, wallet_manager).await.unwrap();
        
        let balances = manager.get_unified_balances().await.unwrap();
        assert_eq!(balances.len(), 0);
    }
}