//! Portfolio management for QuID wallets

// use quid_blockchain::{BlockchainType, Transaction};
use crate::{BlockchainType, Transaction};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{WalletError, WalletResult, WalletBalance, config::PortfolioConfig};

/// Portfolio manager for tracking wallet assets and transactions
#[derive(Debug)]
pub struct PortfolioManager {
    /// Configuration
    config: PortfolioConfig,
    /// Asset balances by network and address
    balances: Arc<RwLock<HashMap<(BlockchainType, String), WalletBalance>>>,
    /// Transaction history
    transactions: Arc<RwLock<Vec<PortfolioTransaction>>>,
    /// Price cache
    price_cache: Arc<RwLock<HashMap<BlockchainType, AssetPrice>>>,
    /// Portfolio statistics
    statistics: Arc<RwLock<PortfolioStatistics>>,
}

/// Portfolio transaction record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortfolioTransaction {
    pub id: String,
    pub network: BlockchainType,
    pub from_address: String,
    pub to_address: String,
    pub amount: u64,
    pub fee: u64,
    pub transaction_type: TransactionType,
    pub status: TransactionStatus,
    pub timestamp: DateTime<Utc>,
    pub block_height: Option<u64>,
    pub confirmations: u32,
}

/// Transaction type for portfolio tracking
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TransactionType {
    Send,
    Receive,
    Swap,
    Stake,
    Unstake,
    Reward,
    Fee,
}

/// Transaction status for portfolio tracking
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TransactionStatus {
    Pending,
    Confirmed,
    Failed,
    Cancelled,
}

/// Asset price information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetPrice {
    pub network: BlockchainType,
    pub price_usd: f64,
    pub price_btc: f64,
    pub market_cap: Option<u64>,
    pub volume_24h: Option<f64>,
    pub change_24h: Option<f64>,
    pub last_updated: DateTime<Utc>,
}

/// Portfolio statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortfolioStatistics {
    pub total_value_usd: f64,
    pub total_value_btc: f64,
    pub asset_allocation: HashMap<BlockchainType, f64>,
    pub profit_loss_24h: f64,
    pub profit_loss_7d: f64,
    pub profit_loss_30d: f64,
    pub transaction_count: u64,
    pub last_updated: DateTime<Utc>,
}

/// Portfolio summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortfolioSummary {
    pub total_assets: u32,
    pub total_value_usd: f64,
    pub total_value_btc: f64,
    pub top_holdings: Vec<AssetHolding>,
    pub recent_transactions: Vec<PortfolioTransaction>,
    pub performance: PortfolioPerformance,
    pub last_updated: DateTime<Utc>,
}

/// Asset holding information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetHolding {
    pub network: BlockchainType,
    pub symbol: String,
    pub balance: u64,
    pub value_usd: f64,
    pub value_btc: f64,
    pub percentage: f64,
    pub price_change_24h: Option<f64>,
}

/// Portfolio performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortfolioPerformance {
    pub total_return_usd: f64,
    pub total_return_percentage: f64,
    pub return_24h: f64,
    pub return_7d: f64,
    pub return_30d: f64,
    pub volatility: f64,
    pub sharpe_ratio: Option<f64>,
}

impl PortfolioManager {
    /// Create new portfolio manager
    pub async fn new(config: PortfolioConfig) -> WalletResult<Self> {
        let balances = Arc::new(RwLock::new(HashMap::new()));
        let transactions = Arc::new(RwLock::new(Vec::new()));
        let price_cache = Arc::new(RwLock::new(HashMap::new()));
        let statistics = Arc::new(RwLock::new(PortfolioStatistics {
            total_value_usd: 0.0,
            total_value_btc: 0.0,
            asset_allocation: HashMap::new(),
            profit_loss_24h: 0.0,
            profit_loss_7d: 0.0,
            profit_loss_30d: 0.0,
            transaction_count: 0,
            last_updated: Utc::now(),
        }));
        
        Ok(Self {
            config,
            balances,
            transactions,
            price_cache,
            statistics,
        })
    }
    
    /// Update balance for a specific address and network
    pub async fn update_balance(&self, network: BlockchainType, address: String, balance: u64) -> WalletResult<()> {
        let wallet_balance = WalletBalance {
            network,
            address: address.clone(),
            balance,
            confirmed_balance: balance,
            pending_balance: 0,
            last_updated: Utc::now(),
        };
        
        let mut balances = self.balances.write().await;
        balances.insert((network, address), wallet_balance);
        
        // Update statistics
        self.update_statistics().await?;
        
        Ok(())
    }
    
    /// Get balance for a specific address and network
    pub async fn get_balance(&self, network: BlockchainType, address: &str) -> Option<WalletBalance> {
        let balances = self.balances.read().await;
        balances.get(&(network, address.to_string())).cloned()
    }
    
    /// Get total balance for a network across all addresses
    pub async fn get_total_balance(&self, network: BlockchainType) -> u64 {
        let balances = self.balances.read().await;
        balances.iter()
            .filter(|((net, _), _)| *net == network)
            .map(|(_, balance)| balance.balance)
            .sum()
    }
    
    /// Add transaction to portfolio
    pub async fn add_transaction(&self, transaction: PortfolioTransaction) -> WalletResult<()> {
        let mut transactions = self.transactions.write().await;
        transactions.push(transaction);
        
        // Sort by timestamp (newest first)
        transactions.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        
        // Update statistics
        self.update_statistics().await?;
        
        Ok(())
    }
    
    /// Get transaction history
    pub async fn get_transactions(&self, limit: Option<usize>) -> Vec<PortfolioTransaction> {
        let transactions = self.transactions.read().await;
        
        match limit {
            Some(limit) => transactions.iter().take(limit).cloned().collect(),
            None => transactions.clone(),
        }
    }
    
    /// Get transactions for a specific network
    pub async fn get_transactions_for_network(&self, network: BlockchainType, limit: Option<usize>) -> Vec<PortfolioTransaction> {
        let transactions = self.transactions.read().await;
        
        let filtered: Vec<_> = transactions.iter()
            .filter(|tx| tx.network == network)
            .cloned()
            .collect();
        
        match limit {
            Some(limit) => filtered.into_iter().take(limit).collect(),
            None => filtered,
        }
    }
    
    /// Update asset price
    pub async fn update_price(&self, network: BlockchainType, price: AssetPrice) -> WalletResult<()> {
        let mut price_cache = self.price_cache.write().await;
        price_cache.insert(network, price);
        
        // Update statistics with new prices
        self.update_statistics().await?;
        
        Ok(())
    }
    
    /// Get asset price
    pub async fn get_price(&self, network: BlockchainType) -> Option<AssetPrice> {
        let price_cache = self.price_cache.read().await;
        price_cache.get(&network).cloned()
    }
    
    /// Update portfolio statistics
    async fn update_statistics(&self) -> WalletResult<()> {
        let balances = self.balances.read().await;
        let price_cache = self.price_cache.read().await;
        let transactions = self.transactions.read().await;
        
        let mut total_value_usd = 0.0;
        let mut total_value_btc = 0.0;
        let mut asset_allocation = HashMap::new();
        
        // Calculate total value and allocation
        for ((network, _), balance) in balances.iter() {
            if let Some(price) = price_cache.get(network) {
                let balance_f64 = balance.balance as f64;
                let value_usd = balance_f64 * price.price_usd;
                let value_btc = balance_f64 * price.price_btc;
                
                total_value_usd += value_usd;
                total_value_btc += value_btc;
                
                *asset_allocation.entry(*network).or_insert(0.0) += value_usd;
            }
        }
        
        // Convert allocation to percentages
        for (_, allocation) in asset_allocation.iter_mut() {
            *allocation = (*allocation / total_value_usd) * 100.0;
        }
        
        let transaction_count = transactions.len() as u64;
        
        let mut statistics = self.statistics.write().await;
        statistics.total_value_usd = total_value_usd;
        statistics.total_value_btc = total_value_btc;
        statistics.asset_allocation = asset_allocation;
        statistics.transaction_count = transaction_count;
        statistics.last_updated = Utc::now();
        
        Ok(())
    }
    
    /// Get portfolio statistics
    pub async fn get_statistics(&self) -> PortfolioStatistics {
        let statistics = self.statistics.read().await;
        statistics.clone()
    }
    
    /// Get portfolio summary
    pub async fn get_summary(&self) -> WalletResult<PortfolioSummary> {
        let statistics = self.get_statistics().await;
        let recent_transactions = self.get_transactions(Some(10)).await;
        
        let mut top_holdings = Vec::new();
        let balances = self.balances.read().await;
        let price_cache = self.price_cache.read().await;
        
        // Group balances by network
        let mut network_balances: HashMap<BlockchainType, u64> = HashMap::new();
        for ((network, _), balance) in balances.iter() {
            *network_balances.entry(*network).or_insert(0) += balance.balance;
        }
        
        // Create holdings
        for (network, balance) in network_balances.iter() {
            if let Some(price) = price_cache.get(network) {
                let balance_f64 = *balance as f64;
                let value_usd = balance_f64 * price.price_usd;
                let value_btc = balance_f64 * price.price_btc;
                let percentage = if statistics.total_value_usd > 0.0 {
                    (value_usd / statistics.total_value_usd) * 100.0
                } else {
                    0.0
                };
                
                top_holdings.push(AssetHolding {
                    network: *network,
                    symbol: network.to_string().to_uppercase(),
                    balance: *balance,
                    value_usd,
                    value_btc,
                    percentage,
                    price_change_24h: price.change_24h,
                });
            }
        }
        
        // Sort by value
        top_holdings.sort_by(|a, b| b.value_usd.partial_cmp(&a.value_usd).unwrap_or(std::cmp::Ordering::Equal));
        
        let performance = PortfolioPerformance {
            total_return_usd: statistics.profit_loss_24h,
            total_return_percentage: if statistics.total_value_usd > 0.0 {
                (statistics.profit_loss_24h / statistics.total_value_usd) * 100.0
            } else {
                0.0
            },
            return_24h: statistics.profit_loss_24h,
            return_7d: statistics.profit_loss_7d,
            return_30d: statistics.profit_loss_30d,
            volatility: 0.0, // TODO: Calculate volatility
            sharpe_ratio: None, // TODO: Calculate Sharpe ratio
        };
        
        Ok(PortfolioSummary {
            total_assets: network_balances.len() as u32,
            total_value_usd: statistics.total_value_usd,
            total_value_btc: statistics.total_value_btc,
            top_holdings,
            recent_transactions,
            performance,
            last_updated: Utc::now(),
        })
    }
    
    /// Calculate profit/loss for a specific period
    pub async fn calculate_profit_loss(&self, days: u32) -> WalletResult<f64> {
        let now = Utc::now();
        let start_date = now - chrono::Duration::days(days as i64);
        
        let transactions = self.transactions.read().await;
        let mut profit_loss = 0.0;
        
        for transaction in transactions.iter() {
            if transaction.timestamp >= start_date {
                match transaction.transaction_type {
                    TransactionType::Receive | TransactionType::Reward => {
                        // TODO: Calculate value based on price at transaction time
                        profit_loss += transaction.amount as f64;
                    }
                    TransactionType::Send | TransactionType::Fee => {
                        // TODO: Calculate value based on price at transaction time
                        profit_loss -= transaction.amount as f64;
                    }
                    _ => {}
                }
            }
        }
        
        Ok(profit_loss)
    }
    
    /// Get asset allocation
    pub async fn get_asset_allocation(&self) -> HashMap<BlockchainType, f64> {
        let statistics = self.statistics.read().await;
        statistics.asset_allocation.clone()
    }
    
    /// Export portfolio data
    pub async fn export_data(&self, format: ExportFormat) -> WalletResult<String> {
        let summary = self.get_summary().await?;
        let transactions = self.get_transactions(None).await;
        
        let export_data = PortfolioExportData {
            summary,
            transactions,
            exported_at: Utc::now(),
        };
        
        match format {
            ExportFormat::Json => {
                serde_json::to_string_pretty(&export_data)
                    .map_err(|e| WalletError::SerializationError(e))
            }
            ExportFormat::Csv => {
                // TODO: Implement CSV export
                Ok("CSV export not yet implemented".to_string())
            }
        }
    }
}

/// Export format for portfolio data
#[derive(Debug, Clone)]
pub enum ExportFormat {
    Json,
    Csv,
}

/// Portfolio export data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortfolioExportData {
    pub summary: PortfolioSummary,
    pub transactions: Vec<PortfolioTransaction>,
    pub exported_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PortfolioConfig;
    
    #[tokio::test]
    async fn test_portfolio_manager_creation() {
        let config = PortfolioConfig::default();
        let manager = PortfolioManager::new(config).await.unwrap();
        
        let statistics = manager.get_statistics().await;
        assert_eq!(statistics.total_value_usd, 0.0);
        assert_eq!(statistics.transaction_count, 0);
    }
    
    #[tokio::test]
    async fn test_balance_management() {
        let config = PortfolioConfig::default();
        let manager = PortfolioManager::new(config).await.unwrap();
        
        let address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string();
        manager.update_balance(BlockchainType::Bitcoin, address.clone(), 100_000_000).await.unwrap();
        
        let balance = manager.get_balance(BlockchainType::Bitcoin, &address).await.unwrap();
        assert_eq!(balance.balance, 100_000_000);
        
        let total_balance = manager.get_total_balance(BlockchainType::Bitcoin).await;
        assert_eq!(total_balance, 100_000_000);
    }
    
    #[tokio::test]
    async fn test_transaction_management() {
        let config = PortfolioConfig::default();
        let manager = PortfolioManager::new(config).await.unwrap();
        
        let transaction = PortfolioTransaction {
            id: Uuid::new_v4().to_string(),
            network: BlockchainType::Bitcoin,
            from_address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
            to_address: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
            amount: 50_000_000,
            fee: 10_000,
            transaction_type: TransactionType::Send,
            status: TransactionStatus::Confirmed,
            timestamp: Utc::now(),
            block_height: Some(700_000),
            confirmations: 6,
        };
        
        manager.add_transaction(transaction).await.unwrap();
        
        let transactions = manager.get_transactions(Some(10)).await;
        assert_eq!(transactions.len(), 1);
        assert_eq!(transactions[0].transaction_type, TransactionType::Send);
    }
    
    #[tokio::test]
    async fn test_price_management() {
        let config = PortfolioConfig::default();
        let manager = PortfolioManager::new(config).await.unwrap();
        
        let price = AssetPrice {
            network: BlockchainType::Bitcoin,
            price_usd: 45_000.0,
            price_btc: 1.0,
            market_cap: Some(850_000_000_000),
            volume_24h: Some(20_000_000_000.0),
            change_24h: Some(2.5),
            last_updated: Utc::now(),
        };
        
        manager.update_price(BlockchainType::Bitcoin, price).await.unwrap();
        
        let retrieved_price = manager.get_price(BlockchainType::Bitcoin).await.unwrap();
        assert_eq!(retrieved_price.price_usd, 45_000.0);
    }
    
    #[tokio::test]
    async fn test_portfolio_summary() {
        let config = PortfolioConfig::default();
        let manager = PortfolioManager::new(config).await.unwrap();
        
        // Add balance
        let address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string();
        manager.update_balance(BlockchainType::Bitcoin, address, 100_000_000).await.unwrap();
        
        // Add price
        let price = AssetPrice {
            network: BlockchainType::Bitcoin,
            price_usd: 45_000.0,
            price_btc: 1.0,
            market_cap: Some(850_000_000_000),
            volume_24h: Some(20_000_000_000.0),
            change_24h: Some(2.5),
            last_updated: Utc::now(),
        };
        manager.update_price(BlockchainType::Bitcoin, price).await.unwrap();
        
        let summary = manager.get_summary().await.unwrap();
        assert_eq!(summary.total_assets, 1);
        assert!(summary.total_value_usd > 0.0);
        assert_eq!(summary.top_holdings.len(), 1);
    }
}