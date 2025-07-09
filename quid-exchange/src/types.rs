//! Type definitions for QuID exchange integration

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::collections::HashMap;

/// Exchange type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExchangeType {
    Binance,
    Coinbase,
    Kraken,
    OKX,
    Bitfinex,
    Huobi,
    KuCoin,
    Bybit,
    Generic,
}

impl ToString for ExchangeType {
    fn to_string(&self) -> String {
        match self {
            ExchangeType::Binance => "binance".to_string(),
            ExchangeType::Coinbase => "coinbase".to_string(),
            ExchangeType::Kraken => "kraken".to_string(),
            ExchangeType::OKX => "okx".to_string(),
            ExchangeType::Bitfinex => "bitfinex".to_string(),
            ExchangeType::Huobi => "huobi".to_string(),
            ExchangeType::KuCoin => "kucoin".to_string(),
            ExchangeType::Bybit => "bybit".to_string(),
            ExchangeType::Generic => "generic".to_string(),
        }
    }
}

/// Account information from exchange
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    pub user_id: String,
    pub account_type: AccountType,
    pub status: AccountStatus,
    pub permissions: Vec<Permission>,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub two_factor_enabled: bool,
    pub kyc_level: KYCLevel,
    pub trading_fees: TradingFees,
}

/// Account type
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AccountType {
    Spot,
    Margin,
    Futures,
    Options,
    Institutional,
}

/// Account status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AccountStatus {
    Active,
    Suspended,
    Restricted,
    Closed,
    PendingVerification,
}

/// Account permissions
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Permission {
    SpotTrading,
    MarginTrading,
    FuturesTrading,
    OptionsTrading,
    Withdrawal,
    Deposit,
    APITrading,
    Reading,
}

/// KYC verification level
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KYCLevel {
    None,
    Level1,
    Level2,
    Level3,
    Institutional,
}

/// Trading fees structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TradingFees {
    pub maker_fee: f64,
    pub taker_fee: f64,
    pub fee_tier: String,
    pub discount_enabled: bool,
    pub volume_30d: f64,
}

/// Balance information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Balance {
    pub asset: String,
    pub available: f64,
    pub locked: f64,
    pub total: f64,
    pub usd_value: Option<f64>,
    pub last_updated: DateTime<Utc>,
}

/// Trading pair information
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TradingPair {
    pub symbol: String,
    pub base_asset: String,
    pub quote_asset: String,
    pub status: TradingPairStatus,
    pub min_order_size: f64,
    pub max_order_size: f64,
    pub price_precision: u8,
    pub quantity_precision: u8,
    pub tick_size: f64,
    pub step_size: f64,
}

/// Trading pair status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TradingPairStatus {
    Trading,
    Halted,
    Maintenance,
    Delisted,
}

/// Order book data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderBook {
    pub symbol: String,
    pub bids: Vec<OrderBookEntry>,
    pub asks: Vec<OrderBookEntry>,
    pub last_update_id: u64,
    pub timestamp: DateTime<Utc>,
}

/// Order book entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderBookEntry {
    pub price: f64,
    pub quantity: f64,
}

/// Trade information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trade {
    pub id: String,
    pub symbol: String,
    pub price: f64,
    pub quantity: f64,
    pub timestamp: DateTime<Utc>,
    pub side: OrderSide,
    pub is_maker: bool,
    pub fee: f64,
    pub fee_asset: String,
}

/// Order request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderRequest {
    pub pair: TradingPair,
    pub side: OrderSide,
    pub order_type: OrderType,
    pub quantity: f64,
    pub price: Option<f64>,
    pub stop_price: Option<f64>,
    pub time_in_force: TimeInForce,
    pub client_order_id: Option<String>,
    pub reduce_only: bool,
    pub post_only: bool,
}

/// Order side
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OrderSide {
    Buy,
    Sell,
}

/// Order type
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OrderType {
    Market,
    Limit,
    StopLoss,
    StopLossLimit,
    TakeProfit,
    TakeProfitLimit,
    LimitMaker,
}

/// Time in force
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TimeInForce {
    GTC, // Good Till Cancelled
    IOC, // Immediate Or Cancel
    FOK, // Fill Or Kill
    GTX, // Good Till Crossing
}

/// Order information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Order {
    pub id: String,
    pub client_order_id: Option<String>,
    pub symbol: String,
    pub side: OrderSide,
    pub order_type: OrderType,
    pub quantity: f64,
    pub price: Option<f64>,
    pub stop_price: Option<f64>,
    pub status: OrderStatus,
    pub time_in_force: TimeInForce,
    pub executed_quantity: f64,
    pub executed_value: f64,
    pub fee: f64,
    pub fee_asset: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub trades: Vec<Trade>,
}

/// Order status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OrderStatus {
    New,
    PartiallyFilled,
    Filled,
    Cancelled,
    Rejected,
    Expired,
    PendingCancel,
}

/// Deposit address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositAddress {
    pub asset: String,
    pub address: String,
    pub tag: Option<String>,
    pub network: Option<String>,
    pub address_type: DepositAddressType,
}

/// Deposit address type
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DepositAddressType {
    Legacy,
    SegWit,
    Native,
    Smart,
}

/// Withdrawal request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawRequest {
    pub asset: String,
    pub address: String,
    pub amount: f64,
    pub tag: Option<String>,
    pub network: Option<String>,
    pub client_id: Option<String>,
}

/// Withdrawal information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Withdrawal {
    pub id: String,
    pub asset: String,
    pub amount: f64,
    pub address: String,
    pub tag: Option<String>,
    pub network: Option<String>,
    pub status: WithdrawalStatus,
    pub tx_id: Option<String>,
    pub fee: f64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Withdrawal status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum WithdrawalStatus {
    Pending,
    Processing,
    Completed,
    Failed,
    Cancelled,
}

/// Deposit information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deposit {
    pub id: String,
    pub asset: String,
    pub amount: f64,
    pub address: String,
    pub tag: Option<String>,
    pub network: Option<String>,
    pub status: DepositStatus,
    pub tx_id: Option<String>,
    pub confirmations: u32,
    pub required_confirmations: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Deposit status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DepositStatus {
    Pending,
    Processing,
    Completed,
    Failed,
}

/// Health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: ServiceStatus,
    pub message: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub response_time_ms: u64,
}

/// Service status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ServiceStatus {
    Online,
    Maintenance,
    Degraded,
    Offline,
}

/// API credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct APICredentials {
    pub api_key: String,
    pub api_secret: String,
    pub passphrase: Option<String>,
    pub sandbox: bool,
}

/// API request info
#[derive(Debug, Clone)]
pub struct APIRequest {
    pub method: String,
    pub path: String,
    pub query_params: HashMap<String, String>,
    pub body: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// API response info
#[derive(Debug, Clone)]
pub struct APIResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub timestamp: DateTime<Utc>,
    pub response_time_ms: u64,
}

/// Exchange configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeSettings {
    pub exchange_type: ExchangeType,
    pub api_credentials: APICredentials,
    pub rate_limit: RateLimitConfig,
    pub timeout_ms: u64,
    pub retry_attempts: u32,
    pub sandbox_mode: bool,
}

/// Rate limit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub requests_per_second: u32,
    pub requests_per_minute: u32,
    pub burst_size: u32,
}

/// Portfolio sync settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortfolioSyncSettings {
    pub enabled: bool,
    pub sync_interval_seconds: u64,
    pub auto_sync_on_trade: bool,
    pub include_history: bool,
    pub history_days: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_exchange_type_to_string() {
        assert_eq!(ExchangeType::Binance.to_string(), "binance");
        assert_eq!(ExchangeType::Coinbase.to_string(), "coinbase");
        assert_eq!(ExchangeType::Kraken.to_string(), "kraken");
        assert_eq!(ExchangeType::OKX.to_string(), "okx");
    }
    
    #[test]
    fn test_order_serialization() {
        let order = OrderRequest {
            pair: TradingPair {
                symbol: "BTCUSDT".to_string(),
                base_asset: "BTC".to_string(),
                quote_asset: "USDT".to_string(),
                status: TradingPairStatus::Trading,
                min_order_size: 0.001,
                max_order_size: 1000.0,
                price_precision: 2,
                quantity_precision: 8,
                tick_size: 0.01,
                step_size: 0.00000001,
            },
            side: OrderSide::Buy,
            order_type: OrderType::Limit,
            quantity: 0.1,
            price: Some(50000.0),
            stop_price: None,
            time_in_force: TimeInForce::GTC,
            client_order_id: None,
            reduce_only: false,
            post_only: false,
        };
        
        let serialized = serde_json::to_string(&order).unwrap();
        let deserialized: OrderRequest = serde_json::from_str(&serialized).unwrap();
        
        assert_eq!(order.side, deserialized.side);
        assert_eq!(order.order_type, deserialized.order_type);
        assert_eq!(order.quantity, deserialized.quantity);
        assert_eq!(order.price, deserialized.price);
    }
    
    #[test]
    fn test_balance_calculation() {
        let balance = Balance {
            asset: "BTC".to_string(),
            available: 1.0,
            locked: 0.5,
            total: 1.5,
            usd_value: Some(75000.0),
            last_updated: Utc::now(),
        };
        
        assert_eq!(balance.available + balance.locked, balance.total);
    }
    
    #[test]
    fn test_order_book_entry() {
        let entry = OrderBookEntry {
            price: 50000.0,
            quantity: 0.1,
        };
        
        assert_eq!(entry.price * entry.quantity, 5000.0);
    }
}