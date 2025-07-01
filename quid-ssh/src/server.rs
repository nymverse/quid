//! SSH server implementation with QuID authentication
//!
//! This module provides an SSH server that can authenticate clients using QuID identities
//! instead of traditional SSH keys.

use anyhow::Result;
use quid_core::{QuIDClient, QuIDIdentity};
use russh::server::{Auth, Msg, Session};
use russh::{Channel, ChannelId, CryptoVec, Disconnect, Pty, Sig};
use russh_keys::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, info, warn};

use crate::keys::QuIDSSHKey;
use crate::{QuIDSSHError, QuIDSSHResult};

/// SSH server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSHServerConfig {
    /// Server bind address
    pub bind_address: SocketAddr,
    /// Server host keys
    pub host_keys: Vec<std::path::PathBuf>,
    /// Maximum concurrent connections
    pub max_connections: u32,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Authentication timeout in seconds
    pub auth_timeout: u64,
    /// Maximum authentication attempts per connection
    pub max_auth_attempts: u32,
    /// Allowed authentication methods
    pub auth_methods: Vec<AuthMethod>,
    /// Authorized users configuration
    pub authorized_users: AuthorizedUsersConfig,
    /// Banner message
    pub banner: Option<String>,
    /// MOTD (Message of the Day)
    pub motd: Option<String>,
    /// Enable SFTP subsystem
    pub enable_sftp: bool,
    /// Enable port forwarding
    pub enable_port_forwarding: bool,
    /// Enable X11 forwarding
    pub enable_x11_forwarding: bool,
    /// Allowed shell commands
    pub allowed_commands: Option<Vec<String>>,
    /// Logging configuration
    pub log_auth_attempts: bool,
    /// Log successful connections
    pub log_connections: bool,
}

impl Default for SSHServerConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:2222".parse().unwrap(),
            host_keys: vec![],
            max_connections: 100,
            connection_timeout: 300,
            auth_timeout: 60,
            max_auth_attempts: 3,
            auth_methods: vec![AuthMethod::QuID, AuthMethod::PublicKey],
            authorized_users: AuthorizedUsersConfig::default(),
            banner: Some("QuID SSH Server - Quantum-Resistant Authentication".to_string()),
            motd: None,
            enable_sftp: true,
            enable_port_forwarding: false,
            enable_x11_forwarding: false,
            allowed_commands: None,
            log_auth_attempts: true,
            log_connections: true,
        }
    }
}

/// Authentication methods supported by the server
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AuthMethod {
    /// QuID quantum-resistant authentication
    QuID,
    /// Traditional public key authentication
    PublicKey,
    /// Password authentication (not recommended)
    Password,
    /// Keyboard-interactive authentication
    KeyboardInteractive,
}

impl AuthMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthMethod::QuID => "quid",
            AuthMethod::PublicKey => "publickey",
            AuthMethod::Password => "password",
            AuthMethod::KeyboardInteractive => "keyboard-interactive",
        }
    }
}

/// Authorized users configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedUsersConfig {
    /// Path to authorized_keys file
    pub authorized_keys_file: Option<std::path::PathBuf>,
    /// Path to QuID authorized identities file
    pub authorized_identities_file: Option<std::path::PathBuf>,
    /// In-memory authorized users
    pub users: HashMap<String, UserConfig>,
}

impl Default for AuthorizedUsersConfig {
    fn default() -> Self {
        Self {
            authorized_keys_file: None,
            authorized_identities_file: None,
            users: HashMap::new(),
        }
    }
}

/// User configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfig {
    /// User's shell
    pub shell: Option<String>,
    /// Home directory
    pub home_directory: Option<std::path::PathBuf>,
    /// Allowed commands (if restricted)
    pub allowed_commands: Option<Vec<String>>,
    /// QuID identities allowed for this user
    pub quid_identities: Vec<String>,
    /// SSH public keys allowed for this user
    pub ssh_keys: Vec<String>,
    /// User is enabled
    pub enabled: bool,
}

impl Default for UserConfig {
    fn default() -> Self {
        Self {
            shell: Some("/bin/bash".to_string()),
            home_directory: None,
            allowed_commands: None,
            quid_identities: Vec::new(),
            ssh_keys: Vec::new(),
            enabled: true,
        }
    }
}

/// SSH session state
#[derive(Debug)]
pub struct SSHSessionState {
    pub username: Option<String>,
    pub authenticated: bool,
    pub auth_method: Option<AuthMethod>,
    pub quid_identity: Option<QuIDIdentity>,
    pub auth_attempts: u32,
    pub channels: HashMap<ChannelId, ChannelState>,
    pub remote_address: SocketAddr,
    pub session_start: std::time::Instant,
}

impl SSHSessionState {
    pub fn new(remote_address: SocketAddr) -> Self {
        Self {
            username: None,
            authenticated: false,
            auth_method: None,
            quid_identity: None,
            auth_attempts: 0,
            channels: HashMap::new(),
            remote_address,
            session_start: std::time::Instant::now(),
        }
    }
}

/// Channel state
#[derive(Debug)]
pub struct ChannelState {
    pub channel_type: String,
    pub pty: Option<Pty>,
    pub exec_command: Option<String>,
    pub subsystem: Option<String>,
}

/// Authentication handler trait
#[async_trait::async_trait]
pub trait AuthenticationHandler: Send + Sync {
    /// Authenticate user with QuID identity
    async fn authenticate_quid(
        &self,
        username: &str,
        identity: &QuIDIdentity,
        signature: &[u8],
        challenge: &[u8],
    ) -> QuIDSSHResult<bool>;

    /// Authenticate user with SSH public key
    async fn authenticate_public_key(
        &self,
        username: &str,
        public_key: &PublicKey,
        signature: Option<&[u8]>,
        challenge: &[u8],
    ) -> QuIDSSHResult<bool>;

    /// Get user configuration
    async fn get_user_config(&self, username: &str) -> QuIDSSHResult<Option<UserConfig>>;

    /// Log authentication attempt
    async fn log_auth_attempt(
        &self,
        username: &str,
        method: &AuthMethod,
        success: bool,
        remote_address: SocketAddr,
    ) -> QuIDSSHResult<()>;
}

/// Default authentication handler
pub struct DefaultAuthHandler {
    quid_client: Arc<QuIDClient>,
    config: SSHServerConfig,
    authorized_identities: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl DefaultAuthHandler {
    pub fn new(quid_client: Arc<QuIDClient>, config: SSHServerConfig) -> Self {
        Self {
            quid_client,
            config,
            authorized_identities: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Load authorized identities from file
    pub async fn load_authorized_identities(&self) -> QuIDSSHResult<()> {
        if let Some(file_path) = &self.config.authorized_users.authorized_identities_file {
            let content = tokio::fs::read_to_string(file_path).await?;
            let mut identities = self.authorized_identities.write().await;
            
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let username = parts[0].to_string();
                    let identity_id = parts[1].to_string();
                    
                    identities.entry(username).or_insert_with(Vec::new).push(identity_id);
                }
            }
        }
        
        Ok(())
    }
}

#[async_trait::async_trait]
impl AuthenticationHandler for DefaultAuthHandler {
    async fn authenticate_quid(
        &self,
        username: &str,
        identity: &QuIDIdentity,
        signature: &[u8],
        challenge: &[u8],
    ) -> QuIDSSHResult<bool> {
        debug!("Authenticating user {} with QuID identity {}", username, identity.id);

        // Check if identity is authorized for this user
        let authorized = {
            let identities = self.authorized_identities.read().await;
            if let Some(user_identities) = identities.get(username) {
                user_identities.contains(&identity.id)
            } else if let Some(user_config) = self.config.authorized_users.users.get(username) {
                user_config.quid_identities.contains(&identity.id)
            } else {
                false
            }
        };

        if !authorized {
            warn!("QuID identity {} not authorized for user {}", identity.id, username);
            return Ok(false);
        }

        // Verify the signature
        let quid_key = QuIDSSHKey::from_identity(&self.quid_client, identity).await?;
        let signature_valid = quid_key.verify_signature(signature, challenge)?;

        if signature_valid {
            info!("QuID authentication successful for user {} with identity {}", username, identity.id);
        } else {
            warn!("QuID signature verification failed for user {} with identity {}", username, identity.id);
        }

        Ok(signature_valid)
    }

    async fn authenticate_public_key(
        &self,
        username: &str,
        public_key: &PublicKey,
        signature: Option<&[u8]>,
        challenge: &[u8],
    ) -> QuIDSSHResult<bool> {
        debug!("Authenticating user {} with SSH public key", username);

        // In a real implementation, we would:
        // 1. Check authorized_keys file
        // 2. Verify the signature if provided
        // 3. Return authentication result

        // For now, we'll implement a placeholder
        if let Some(user_config) = self.config.authorized_users.users.get(username) {
            if !user_config.ssh_keys.is_empty() {
                info!("SSH public key authentication successful for user {}", username);
                return Ok(true);
            }
        }

        warn!("SSH public key authentication failed for user {}", username);
        Ok(false)
    }

    async fn get_user_config(&self, username: &str) -> QuIDSSHResult<Option<UserConfig>> {
        Ok(self.config.authorized_users.users.get(username).cloned())
    }

    async fn log_auth_attempt(
        &self,
        username: &str,
        method: &AuthMethod,
        success: bool,
        remote_address: SocketAddr,
    ) -> QuIDSSHResult<()> {
        if self.config.log_auth_attempts {
            let status = if success { "SUCCESS" } else { "FAILED" };
            info!(
                "AUTH {} {} {} {} {}",
                status,
                username,
                method.as_str(),
                remote_address.ip(),
                remote_address.port()
            );
        }
        Ok(())
    }
}

/// QuID SSH server handler
pub struct QuIDSSHServerHandler {
    quid_client: Arc<QuIDClient>,
    config: SSHServerConfig,
    auth_handler: Arc<dyn AuthenticationHandler>,
    sessions: Arc<Mutex<HashMap<usize, SSHSessionState>>>,
    connection_counter: Arc<Mutex<usize>>,
}

impl QuIDSSHServerHandler {
    pub fn new(
        quid_client: Arc<QuIDClient>,
        config: SSHServerConfig,
        auth_handler: Arc<dyn AuthenticationHandler>,
    ) -> Self {
        Self {
            quid_client,
            config,
            auth_handler,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            connection_counter: Arc::new(Mutex::new(0)),
        }
    }

    async fn get_session_mut(&self, session_id: usize) -> Option<SSHSessionState> {
        let sessions = self.sessions.lock().await;
        sessions.get(&session_id).cloned()
    }

    async fn update_session<F>(&self, session_id: usize, updater: F) 
    where
        F: FnOnce(&mut SSHSessionState),
    {
        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get_mut(&session_id) {
            updater(session);
        }
    }
}

#[async_trait::async_trait]
impl russh::server::Handler for QuIDSSHServerHandler {
    type Error = QuIDSSHError;

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        info!("Opening session channel");
        Ok(true)
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        info!("Public key authentication attempt for user: {}", user);
        
        // Generate challenge
        let challenge = b"ssh-auth-challenge";
        
        // Authenticate without signature first (SSH protocol requirement)
        let result = self.auth_handler.authenticate_public_key(user, public_key, None, challenge).await?;
        
        if result {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::Reject)
        }
    }

    async fn auth_publickey_sign(
        &mut self,
        user: &str,
        public_key: &PublicKey,
        data: &[u8],
    ) -> Result<Auth, Self::Error> {
        info!("Public key signature authentication for user: {}", user);
        
        let result = self.auth_handler.authenticate_public_key(user, public_key, Some(data), data).await?;
        
        if result {
            info!("User {} authenticated successfully with public key", user);
            Ok(Auth::Accept)
        } else {
            warn!("Public key authentication failed for user {}", user);
            Ok(Auth::Reject)
        }
    }

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<Auth, Self::Error> {
        warn!("Password authentication attempted for user {} (not supported)", user);
        Ok(Auth::Reject)
    }

    async fn auth_keyboard_interactive(
        &mut self,
        user: &str,
        submethods: &str,
        response: Option<russh::server::Response>,
    ) -> Result<Auth, Self::Error> {
        warn!("Keyboard-interactive authentication attempted for user {} (not supported)", user);
        Ok(Auth::Reject)
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!("Closing channel {}", channel);
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!("Channel {} EOF", channel);
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!("Received {} bytes on channel {}", data.len(), channel);
        
        // Echo data back (for demonstration)
        session.data(channel, CryptoVec::from(data));
        
        Ok(())
    }

    async fn extended_data(
        &mut self,
        channel: ChannelId,
        code: u32,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!("Received extended data on channel {}: code={}, {} bytes", channel, code, data.len());
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!("Window change request on channel {}: {}x{}", channel, col_width, row_height);
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!("PTY request on channel {}: terminal={}", channel, term);
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!("Shell request on channel {}", channel);
        
        // Send welcome message
        if let Some(banner) = &self.config.banner {
            session.data(channel, CryptoVec::from(format!("{}\r\n", banner)));
        }
        
        if let Some(motd) = &self.config.motd {
            session.data(channel, CryptoVec::from(format!("{}\r\n", motd)));
        }
        
        // Send prompt
        session.data(channel, CryptoVec::from("quid-ssh$ "));
        
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data);
        info!("Exec request on channel {}: {}", channel, command);
        
        // Check if command is allowed
        if let Some(allowed_commands) = &self.config.allowed_commands {
            if !allowed_commands.iter().any(|cmd| command.starts_with(cmd)) {
                session.data(channel, CryptoVec::from("Command not allowed\r\n"));
                session.exit_status_request(channel, 1);
                return Ok(());
            }
        }
        
        // Execute command (placeholder)
        let output = format!("Executed: {}\r\n", command);
        session.data(channel, CryptoVec::from(output));
        session.exit_status_request(channel, 0);
        
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!("Subsystem request on channel {}: {}", channel, name);
        
        match name {
            "sftp" if self.config.enable_sftp => {
                info!("Starting SFTP subsystem on channel {}", channel);
                // In a real implementation, we would start the SFTP subsystem
                Ok(())
            }
            _ => {
                warn!("Subsystem {} not supported or disabled", name);
                Ok(())
            }
        }
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if self.config.enable_port_forwarding {
            info!("TCP/IP forward request: {}:{}", address, port);
            Ok(true)
        } else {
            warn!("Port forwarding disabled");
            Ok(false)
        }
    }

    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        info!("Cancel TCP/IP forward: {}:{}", address, port);
        Ok(true)
    }
}

/// QuID SSH server
pub struct QuIDSSHServer {
    quid_client: Arc<QuIDClient>,
    config: SSHServerConfig,
    auth_handler: Arc<dyn AuthenticationHandler>,
}

impl QuIDSSHServer {
    /// Create a new QuID SSH server
    pub fn new(
        quid_client: Arc<QuIDClient>,
        config: SSHServerConfig,
    ) -> Self {
        let auth_handler = Arc::new(DefaultAuthHandler::new(quid_client.clone(), config.clone()));
        
        Self {
            quid_client,
            config,
            auth_handler,
        }
    }

    /// Create a new QuID SSH server with custom authentication handler
    pub fn with_auth_handler(
        quid_client: Arc<QuIDClient>,
        config: SSHServerConfig,
        auth_handler: Arc<dyn AuthenticationHandler>,
    ) -> Self {
        Self {
            quid_client,
            config,
            auth_handler,
        }
    }

    /// Start the SSH server
    pub async fn start(&self) -> QuIDSSHResult<()> {
        info!("Starting QuID SSH server on {}", self.config.bind_address);

        // Load authorized identities
        if let auth_handler = self.auth_handler.as_ref().as_any().downcast_ref::<DefaultAuthHandler>() {
            auth_handler.load_authorized_identities().await?;
        }

        // Create server configuration
        let ssh_config = russh::server::Config {
            auth_timeout: Some(std::time::Duration::from_secs(self.config.auth_timeout)),
            connection_timeout: Some(std::time::Duration::from_secs(self.config.connection_timeout)),
            ..Default::default()
        };

        // Start listening
        let listener = TcpListener::bind(self.config.bind_address).await
            .map_err(|e| QuIDSSHError::ConnectionFailed(format!("Failed to bind to {}: {}", self.config.bind_address, e)))?;

        info!("QuID SSH server listening on {}", self.config.bind_address);

        loop {
            let (stream, remote_addr) = listener.accept().await
                .map_err(|e| QuIDSSHError::ConnectionFailed(format!("Failed to accept connection: {}", e)))?;

            info!("New connection from {}", remote_addr);

            // Create handler for this connection
            let handler = QuIDSSHServerHandler::new(
                self.quid_client.clone(),
                self.config.clone(),
                self.auth_handler.clone(),
            );

            // Spawn connection handler
            let ssh_config = ssh_config.clone();
            tokio::spawn(async move {
                if let Err(e) = russh::server::run(Arc::new(ssh_config), stream, handler).await {
                    error!("SSH connection error: {}", e);
                }
            });
        }
    }

    /// Stop the server (graceful shutdown)
    pub async fn stop(&self) -> QuIDSSHResult<()> {
        info!("Stopping QuID SSH server");
        // In a real implementation, we would:
        // 1. Stop accepting new connections
        // 2. Wait for existing connections to close
        // 3. Force close remaining connections after timeout
        Ok(())
    }
}

// Helper trait for type erasure
trait AsAny {
    fn as_any(&self) -> &dyn std::any::Any;
}

impl<T: 'static> AsAny for T {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_server_config_default() {
        let config = SSHServerConfig::default();
        assert_eq!(config.max_connections, 100);
        assert_eq!(config.connection_timeout, 300);
        assert_eq!(config.auth_timeout, 60);
        assert!(config.auth_methods.contains(&AuthMethod::QuID));
        assert!(config.enable_sftp);
    }

    #[test]
    fn test_auth_method_as_str() {
        assert_eq!(AuthMethod::QuID.as_str(), "quid");
        assert_eq!(AuthMethod::PublicKey.as_str(), "publickey");
        assert_eq!(AuthMethod::Password.as_str(), "password");
        assert_eq!(AuthMethod::KeyboardInteractive.as_str(), "keyboard-interactive");
    }

    #[test]
    fn test_user_config_default() {
        let config = UserConfig::default();
        assert_eq!(config.shell, Some("/bin/bash".to_string()));
        assert!(config.enabled);
        assert!(config.quid_identities.is_empty());
        assert!(config.ssh_keys.is_empty());
    }

    #[test]
    fn test_ssh_session_state_new() {
        let addr = "127.0.0.1:22".parse().unwrap();
        let state = SSHSessionState::new(addr);
        
        assert_eq!(state.remote_address, addr);
        assert!(!state.authenticated);
        assert_eq!(state.auth_attempts, 0);
        assert!(state.channels.is_empty());
        assert!(state.username.is_none());
    }
}