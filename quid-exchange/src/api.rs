//! API client utilities for QuID exchange integration

use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::timeout;

use crate::{ExchangeError, ExchangeResult, auth::APISignature};

/// HTTP client wrapper with exchange-specific functionality
#[derive(Debug, Clone)]
pub struct APIClient {
    client: Client,
    base_url: String,
    timeout: Duration,
}

impl APIClient {
    /// Create new API client
    pub fn new(base_url: String, timeout_ms: u64) -> ExchangeResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .build()
            .map_err(|e| ExchangeError::HttpError(e))?;
        
        Ok(Self {
            client,
            base_url,
            timeout: Duration::from_millis(timeout_ms),
        })
    }
    
    /// Make authenticated GET request
    pub async fn get_authenticated(
        &self,
        path: &str,
        query_params: &HashMap<String, String>,
        headers: &HashMap<String, String>,
    ) -> ExchangeResult<Response> {
        let url = format!("{}{}", self.base_url, path);
        
        let mut request = self.client.get(&url);
        
        // Add query parameters
        for (key, value) in query_params {
            request = request.query(&[(key, value)]);
        }
        
        // Add headers
        for (key, value) in headers {
            request = request.header(key, value);
        }
        
        let response = timeout(self.timeout, request.send()).await
            .map_err(|_| ExchangeError::Timeout("Request timeout".to_string()))?
            .map_err(|e| ExchangeError::HttpError(e))?;
        
        Ok(response)
    }
    
    /// Make authenticated POST request
    pub async fn post_authenticated(
        &self,
        path: &str,
        body: &str,
        headers: &HashMap<String, String>,
    ) -> ExchangeResult<Response> {
        let url = format!("{}{}", self.base_url, path);
        
        let mut request = self.client.post(&url);
        
        // Add headers
        for (key, value) in headers {
            request = request.header(key, value);
        }
        
        // Add body
        request = request.body(body.to_string());
        
        let response = timeout(self.timeout, request.send()).await
            .map_err(|_| ExchangeError::Timeout("Request timeout".to_string()))?
            .map_err(|e| ExchangeError::HttpError(e))?;
        
        Ok(response)
    }
}

/// API response wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct APIResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
    pub code: Option<i32>,
}

/// Placeholder for API utilities
pub mod utils {
    use super::*;
    
    /// Parse API response
    pub async fn parse_response<T: for<'de> Deserialize<'de>>(
        response: Response,
    ) -> ExchangeResult<T> {
        let text = response.text().await
            .map_err(|e| ExchangeError::HttpError(e))?;
        
        serde_json::from_str(&text)
            .map_err(|e| ExchangeError::ResponseParsingFailed(e.to_string()))
    }
}