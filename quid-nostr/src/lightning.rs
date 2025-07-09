//! Lightning Network integration for Nostr Zaps

use crate::{NostrResult, NostrError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Lightning Network node interface
#[derive(Debug)]
pub struct LightningNode {
    /// Node configuration
    config: LightningConfig,
    /// Connected peers
    peers: HashMap<String, PeerInfo>,
    /// Payment history
    payments: Vec<PaymentRecord>,
}

/// Lightning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningConfig {
    /// Node alias
    pub alias: String,
    /// Node public key
    pub pubkey: String,
    /// Network (mainnet, testnet, signet)
    pub network: String,
    /// RPC endpoint
    pub rpc_endpoint: String,
    /// Macaroon path (for authentication)
    pub macaroon_path: Option<String>,
    /// TLS cert path
    pub tls_cert_path: Option<String>,
}

/// Peer information
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Peer public key
    pub pubkey: String,
    /// Connection address
    pub address: String,
    /// Connected status
    pub connected: bool,
    /// Channels with this peer
    pub channels: u32,
}

/// Payment record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentRecord {
    /// Payment hash
    pub payment_hash: String,
    /// Payment preimage
    pub preimage: Option<String>,
    /// Amount in millisatoshis
    pub amount_msat: u64,
    /// Payment status
    pub status: PaymentStatus,
    /// Creation time
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Completion time
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Fee paid
    pub fee_msat: Option<u64>,
    /// Associated Nostr event ID
    pub nostr_event_id: Option<String>,
}

/// Payment status
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum PaymentStatus {
    /// Payment is pending
    Pending,
    /// Payment succeeded
    Succeeded,
    /// Payment failed
    Failed,
    /// Payment was cancelled
    Cancelled,
}

/// Lightning invoice
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningInvoice {
    /// BOLT11 payment request
    pub bolt11: String,
    /// Payment hash
    pub payment_hash: String,
    /// Amount in millisatoshis
    pub amount_msat: u64,
    /// Description
    pub description: String,
    /// Expiry time
    pub expiry: chrono::DateTime<chrono::Utc>,
    /// Invoice status
    pub status: InvoiceStatus,
}

/// Invoice status
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum InvoiceStatus {
    /// Invoice is unpaid
    Unpaid,
    /// Invoice is paid
    Paid,
    /// Invoice is expired
    Expired,
    /// Invoice is cancelled
    Cancelled,
}

/// Zap payment parameters
#[derive(Debug, Clone)]
pub struct ZapPayment {
    /// Recipient LNURL or Lightning address
    pub recipient: String,
    /// Amount in millisatoshis
    pub amount_msat: u64,
    /// Comment/message
    pub comment: Option<String>,
    /// Nostr event being zapped
    pub event_id: Option<String>,
    /// Sender pubkey
    pub sender_pubkey: Option<String>,
}

impl LightningNode {
    /// Create new Lightning node instance
    pub fn new(config: LightningConfig) -> Self {
        Self {
            config,
            peers: HashMap::new(),
            payments: Vec::new(),
        }
    }
    
    /// Connect to Lightning node
    pub async fn connect(&mut self) -> NostrResult<()> {
        // In production, establish connection to Lightning node via gRPC/REST API
        tracing::info!("Connecting to Lightning node at {}", self.config.rpc_endpoint);
        
        // Simulate connection
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        Ok(())
    }
    
    /// Create Lightning invoice for Zap
    pub async fn create_zap_invoice(
        &self,
        amount_msat: u64,
        description: String,
        expiry_seconds: Option<u64>,
    ) -> NostrResult<LightningInvoice> {
        let payment_hash = self.generate_payment_hash();
        let expiry = chrono::Utc::now() + chrono::Duration::seconds(expiry_seconds.unwrap_or(3600) as i64);
        
        // Generate mock BOLT11 invoice
        let bolt11 = format!(
            "lnbc{}u1p{}x{}",
            amount_msat / 1000 / 1000, // Convert to BTC units
            payment_hash[..10].to_lowercase(),
            "mockvalue123" // In production, proper BOLT11 encoding
        );
        
        Ok(LightningInvoice {
            bolt11,
            payment_hash,
            amount_msat,
            description,
            expiry,
            status: InvoiceStatus::Unpaid,
        })
    }
    
    /// Pay Lightning invoice
    pub async fn pay_invoice(&mut self, bolt11: &str) -> NostrResult<PaymentRecord> {
        // Parse invoice (simplified)
        let payment_hash = self.extract_payment_hash_from_bolt11(bolt11)?;
        let amount_msat = self.extract_amount_from_bolt11(bolt11)?;
        
        let payment = PaymentRecord {
            payment_hash: payment_hash.clone(),
            preimage: None,
            amount_msat,
            status: PaymentStatus::Pending,
            created_at: chrono::Utc::now(),
            completed_at: None,
            fee_msat: None,
            nostr_event_id: None,
        };
        
        self.payments.push(payment.clone());
        
        // Simulate payment processing
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        
        // Update payment status (simulate success)
        if let Some(payment) = self.payments.iter_mut().find(|p| p.payment_hash == payment_hash) {
            payment.status = PaymentStatus::Succeeded;
            payment.completed_at = Some(chrono::Utc::now());
            payment.preimage = Some(self.generate_preimage());
            payment.fee_msat = Some(1000); // 1 sat fee
        }
        
        Ok(payment)
    }
    
    /// Send Zap payment
    pub async fn send_zap(&mut self, zap: ZapPayment) -> NostrResult<PaymentRecord> {
        // Resolve Lightning address or LNURL
        let invoice = self.resolve_lightning_address(&zap.recipient, zap.amount_msat, zap.comment.as_deref()).await?;
        
        // Pay the invoice
        let mut payment = self.pay_invoice(&invoice.bolt11).await?;
        payment.nostr_event_id = zap.event_id;
        
        Ok(payment)
    }
    
    /// Get payment by hash
    pub fn get_payment(&self, payment_hash: &str) -> Option<&PaymentRecord> {
        self.payments.iter().find(|p| p.payment_hash == payment_hash)
    }
    
    /// Get all payments
    pub fn get_payments(&self) -> &[PaymentRecord] {
        &self.payments
    }
    
    /// Get node info
    pub async fn get_node_info(&self) -> NostrResult<NodeInfo> {
        Ok(NodeInfo {
            alias: self.config.alias.clone(),
            pubkey: self.config.pubkey.clone(),
            network: self.config.network.clone(),
            channels: self.peers.values().map(|p| p.channels).sum(),
            peers: self.peers.len() as u32,
            balance_sat: 1000000, // Mock balance
        })
    }
    
    /// Check invoice status
    pub async fn check_invoice_status(&self, payment_hash: &str) -> NostrResult<InvoiceStatus> {
        // In production, query Lightning node for invoice status
        // For now, return mock status
        if let Some(payment) = self.get_payment(payment_hash) {
            match payment.status {
                PaymentStatus::Succeeded => Ok(InvoiceStatus::Paid),
                PaymentStatus::Failed => Ok(InvoiceStatus::Expired),
                PaymentStatus::Cancelled => Ok(InvoiceStatus::Cancelled),
                PaymentStatus::Pending => Ok(InvoiceStatus::Unpaid),
            }
        } else {
            Ok(InvoiceStatus::Unpaid)
        }
    }
    
    // Private helper methods
    
    /// Generate payment hash
    fn generate_payment_hash(&self) -> String {
        use sha3::{Sha3_256, Digest};
        let mut hasher = Sha3_256::new();
        hasher.update(chrono::Utc::now().timestamp().to_string());
        hasher.update(&rand::random::<[u8; 32]>());
        hex::encode(hasher.finalize())
    }
    
    /// Generate payment preimage
    fn generate_preimage(&self) -> String {
        hex::encode(rand::random::<[u8; 32]>())
    }
    
    /// Extract payment hash from BOLT11 invoice
    fn extract_payment_hash_from_bolt11(&self, bolt11: &str) -> NostrResult<String> {
        // Simplified extraction - in production, use proper BOLT11 decoder
        if bolt11.starts_with("lnbc") {
            Ok(self.generate_payment_hash()) // Mock hash
        } else {
            Err(NostrError::LightningError("Invalid BOLT11 format".to_string()))
        }
    }
    
    /// Extract amount from BOLT11 invoice
    fn extract_amount_from_bolt11(&self, _bolt11: &str) -> NostrResult<u64> {
        // Simplified extraction - in production, use proper BOLT11 decoder
        Ok(1000000) // Mock 1000 sats
    }
    
    /// Resolve Lightning address to invoice
    async fn resolve_lightning_address(
        &self,
        address: &str,
        amount_msat: u64,
        comment: Option<&str>,
    ) -> NostrResult<LightningInvoice> {
        // In production, this would:
        // 1. Parse Lightning address (user@domain.com)
        // 2. Make HTTPS request to /.well-known/lnurlp/{user}
        // 3. Follow LNURL flow to get invoice
        
        self.create_zap_invoice(
            amount_msat,
            comment.unwrap_or("Nostr Zap").to_string(),
            Some(3600),
        ).await
    }
}

/// Node information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Node alias
    pub alias: String,
    /// Node public key
    pub pubkey: String,
    /// Network
    pub network: String,
    /// Number of channels
    pub channels: u32,
    /// Number of peers
    pub peers: u32,
    /// Balance in satoshis
    pub balance_sat: u64,
}

/// LNURL utilities
pub mod lnurl {
    use super::*;
    
    /// Parse Lightning address (user@domain.com)
    pub fn parse_lightning_address(address: &str) -> NostrResult<(String, String)> {
        if let Some(at_pos) = address.find('@') {
            let user = address[..at_pos].to_string();
            let domain = address[at_pos + 1..].to_string();
            Ok((user, domain))
        } else {
            Err(NostrError::LightningError("Invalid Lightning address format".to_string()))
        }
    }
    
    /// Generate LNURL for Lightning address
    pub fn generate_lnurl(domain: &str, user: &str) -> String {
        let url = format!("https://{}/.well-known/lnurlp/{}", domain, user);
        // In production, encode as bech32 LNURL
        format!("lnurl{}", base64::encode(url))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_lightning_node_creation() {
        let config = LightningConfig {
            alias: "QuID Node".to_string(),
            pubkey: "test_pubkey".to_string(),
            network: "testnet".to_string(),
            rpc_endpoint: "localhost:10009".to_string(),
            macaroon_path: None,
            tls_cert_path: None,
        };
        
        let mut node = LightningNode::new(config);
        node.connect().await.unwrap();
        
        let info = node.get_node_info().await.unwrap();
        assert_eq!(info.alias, "QuID Node");
        assert_eq!(info.network, "testnet");
    }
    
    #[tokio::test]
    async fn test_invoice_creation() {
        let config = LightningConfig {
            alias: "Test Node".to_string(),
            pubkey: "test_pubkey".to_string(),
            network: "testnet".to_string(),
            rpc_endpoint: "localhost:10009".to_string(),
            macaroon_path: None,
            tls_cert_path: None,
        };
        
        let node = LightningNode::new(config);
        
        let invoice = node.create_zap_invoice(
            100000, // 100 sats
            "Test Zap".to_string(),
            Some(3600),
        ).await.unwrap();
        
        assert_eq!(invoice.amount_msat, 100000);
        assert_eq!(invoice.description, "Test Zap");
        assert_eq!(invoice.status, InvoiceStatus::Unpaid);
        assert!(invoice.bolt11.starts_with("lnbc"));
    }
    
    #[tokio::test]
    async fn test_payment_flow() {
        let config = LightningConfig {
            alias: "Test Node".to_string(),
            pubkey: "test_pubkey".to_string(),
            network: "testnet".to_string(),
            rpc_endpoint: "localhost:10009".to_string(),
            macaroon_path: None,
            tls_cert_path: None,
        };
        
        let mut node = LightningNode::new(config);
        
        // Create invoice
        let invoice = node.create_zap_invoice(50000, "Test payment".to_string(), None).await.unwrap();
        
        // Pay invoice
        let payment = node.pay_invoice(&invoice.bolt11).await.unwrap();
        
        assert_eq!(payment.status, PaymentStatus::Succeeded);
        assert!(payment.preimage.is_some());
        assert!(payment.completed_at.is_some());
        
        // Check payment exists
        let stored_payment = node.get_payment(&payment.payment_hash).unwrap();
        assert_eq!(stored_payment.status, PaymentStatus::Succeeded);
    }
    
    #[tokio::test]
    async fn test_zap_payment() {
        let config = LightningConfig {
            alias: "Test Node".to_string(),
            pubkey: "test_pubkey".to_string(),
            network: "testnet".to_string(),
            rpc_endpoint: "localhost:10009".to_string(),
            macaroon_path: None,
            tls_cert_path: None,
        };
        
        let mut node = LightningNode::new(config);
        
        let zap = ZapPayment {
            recipient: "user@example.com".to_string(),
            amount_msat: 21000,
            comment: Some("Great post!".to_string()),
            event_id: Some("event123".to_string()),
            sender_pubkey: Some("sender_pubkey".to_string()),
        };
        
        let payment = node.send_zap(zap).await.unwrap();
        
        assert_eq!(payment.status, PaymentStatus::Succeeded);
        assert_eq!(payment.nostr_event_id, Some("event123".to_string()));
    }
    
    #[test]
    fn test_lightning_address_parsing() {
        let (user, domain) = lnurl::parse_lightning_address("alice@example.com").unwrap();
        assert_eq!(user, "alice");
        assert_eq!(domain, "example.com");
        
        let result = lnurl::parse_lightning_address("invalid-address");
        assert!(result.is_err());
    }
    
    #[test]
    fn test_lnurl_generation() {
        let lnurl = lnurl::generate_lnurl("example.com", "alice");
        assert!(lnurl.starts_with("lnurl"));
    }
    
    #[tokio::test]
    async fn test_invoice_status_check() {
        let config = LightningConfig {
            alias: "Test Node".to_string(),
            pubkey: "test_pubkey".to_string(),
            network: "testnet".to_string(),
            rpc_endpoint: "localhost:10009".to_string(),
            macaroon_path: None,
            tls_cert_path: None,
        };
        
        let mut node = LightningNode::new(config);
        
        // Create and pay invoice
        let invoice = node.create_zap_invoice(10000, "Status test".to_string(), None).await.unwrap();
        let payment = node.pay_invoice(&invoice.bolt11).await.unwrap();
        
        // Check status
        let status = node.check_invoice_status(&payment.payment_hash).await.unwrap();
        assert_eq!(status, InvoiceStatus::Paid);
        
        // Check non-existent invoice
        let status = node.check_invoice_status("non_existent_hash").await.unwrap();
        assert_eq!(status, InvoiceStatus::Unpaid);
    }
}