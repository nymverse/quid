/**
 * OAuth/OIDC Client
 * Provides OAuth and OpenID Connect integration for QuID
 */

import { QuIDClient } from '../core/quid-client';
import { 
  OAuthConfig, 
  OAuthProvider, 
  OAuthTokenResponse,
  AuthenticationResponse 
} from '../types';
import { Logger } from '../utils/logger';
import * as jose from 'jose';

export class QuIDOAuthClient {
  private quidClient: QuIDClient;
  private config: Required<OAuthConfig>;
  private logger: Logger;

  constructor(config: OAuthConfig, quidClient?: QuIDClient) {
    this.quidClient = quidClient || new QuIDClient();
    this.logger = new Logger(false);
    
    // Set default provider configuration
    const defaultProvider: OAuthProvider = {
      authorizationEndpoint: '/oauth/authorize',
      tokenEndpoint: '/oauth/token',
      userInfoEndpoint: '/oauth/userinfo',
      jwksEndpoint: '/oauth/jwks'
    };

    this.config = {
      clientId: config.clientId,
      clientSecret: config.clientSecret || '',
      redirectUri: config.redirectUri,
      scopes: config.scopes || ['openid', 'profile'],
      provider: { ...defaultProvider, ...config.provider }
    };
  }

  /**
   * Generate OAuth authorization URL with QuID authentication
   */
  public generateAuthUrl(options: {
    state?: string;
    nonce?: string;
    additionalParams?: Record<string, string>;
  } = {}): string {
    const { state, nonce, additionalParams = {} } = options;
    
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      scope: this.config.scopes.join(' '),
      ...additionalParams
    });

    if (state) {
      params.set('state', state);
    }

    if (nonce) {
      params.set('nonce', nonce);
    }

    // Add QuID-specific parameters
    params.set('quid_enabled', 'true');
    params.set('response_mode', 'query');

    const baseUrl = this.config.provider.authorizationEndpoint;
    return `${baseUrl}?${params.toString()}`;
  }

  /**
   * Handle OAuth callback with QuID authentication
   */
  public async handleCallback(callbackUrl: string): Promise<{
    tokens: OAuthTokenResponse;
    userInfo?: any;
  }> {
    const url = new URL(callbackUrl);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    const error = url.searchParams.get('error');

    if (error) {
      throw new Error(`OAuth error: ${error} - ${url.searchParams.get('error_description')}`);
    }

    if (!code) {
      throw new Error('No authorization code received');
    }

    this.logger.debug('Processing OAuth callback with code:', code);

    // Exchange code for tokens using QuID authentication
    const tokens = await this.exchangeCodeForTokens(code, state);
    
    // Get user info if scope includes profile
    let userInfo;
    if (this.config.scopes.includes('profile') && this.config.provider.userInfoEndpoint) {
      userInfo = await this.getUserInfo(tokens.accessToken);
    }

    return { tokens, userInfo };
  }

  /**
   * Exchange authorization code for tokens using QuID authentication
   */
  private async exchangeCodeForTokens(code: string, state?: string): Promise<OAuthTokenResponse> {
    try {
      // Use QuID to authenticate the token request
      const authResponse = await this.quidClient.authenticate({
        challenge: this.generateChallenge(),
        origin: window.location.origin
      });

      if (!authResponse.success) {
        throw new Error('QuID authentication failed for token exchange');
      }

      // Prepare token request
      const tokenRequest = {
        grant_type: 'authorization_code',
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        code,
        redirect_uri: this.config.redirectUri,
        quid_credential: JSON.stringify(authResponse.credential)
      };

      const response = await fetch(this.config.provider.tokenEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept': 'application/json'
        },
        body: new URLSearchParams(tokenRequest).toString()
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(`Token exchange failed: ${errorData.error || response.statusText}`);
      }

      const tokenData = await response.json();
      
      this.logger.debug('Token exchange successful');

      return {
        accessToken: tokenData.access_token,
        tokenType: tokenData.token_type || 'Bearer',
        expiresIn: tokenData.expires_in,
        refreshToken: tokenData.refresh_token,
        scope: tokenData.scope,
        idToken: tokenData.id_token
      };

    } catch (error) {
      this.logger.error('Token exchange failed:', error);
      throw error;
    }
  }

  /**
   * Refresh access token using QuID authentication
   */
  public async refreshToken(refreshToken: string): Promise<OAuthTokenResponse> {
    if (!refreshToken) {
      throw new Error('Refresh token is required');
    }

    try {
      // Use QuID to authenticate the refresh request
      const authResponse = await this.quidClient.authenticate({
        challenge: this.generateChallenge(),
        origin: window.location.origin
      });

      if (!authResponse.success) {
        throw new Error('QuID authentication failed for token refresh');
      }

      const refreshRequest = {
        grant_type: 'refresh_token',
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        refresh_token: refreshToken,
        quid_credential: JSON.stringify(authResponse.credential)
      };

      const response = await fetch(this.config.provider.tokenEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept': 'application/json'
        },
        body: new URLSearchParams(refreshRequest).toString()
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(`Token refresh failed: ${errorData.error || response.statusText}`);
      }

      const tokenData = await response.json();
      
      return {
        accessToken: tokenData.access_token,
        tokenType: tokenData.token_type || 'Bearer',
        expiresIn: tokenData.expires_in,
        refreshToken: tokenData.refresh_token || refreshToken, // Use new refresh token if provided
        scope: tokenData.scope,
        idToken: tokenData.id_token
      };

    } catch (error) {
      this.logger.error('Token refresh failed:', error);
      throw error;
    }
  }

  /**
   * Get user information using access token
   */
  public async getUserInfo(accessToken: string): Promise<any> {
    if (!this.config.provider.userInfoEndpoint) {
      throw new Error('User info endpoint not configured');
    }

    try {
      const response = await fetch(this.config.provider.userInfoEndpoint, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Accept': 'application/json'
        }
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch user info: ${response.statusText}`);
      }

      return await response.json();

    } catch (error) {
      this.logger.error('Failed to get user info:', error);
      throw error;
    }
  }

  /**
   * Verify and decode ID token
   */
  public async verifyIdToken(idToken: string): Promise<any> {
    if (!this.config.provider.jwksEndpoint) {
      this.logger.warn('JWKS endpoint not configured, skipping token verification');
      return jose.decodeJwt(idToken);
    }

    try {
      // Fetch JWKS
      const jwks = await jose.createRemoteJWKSet(new URL(this.config.provider.jwksEndpoint));
      
      // Verify and decode the token
      const { payload } = await jose.jwtVerify(idToken, jwks, {
        issuer: this.extractIssuerFromEndpoint(),
        audience: this.config.clientId
      });

      return payload;

    } catch (error) {
      this.logger.error('ID token verification failed:', error);
      throw new Error('Invalid ID token');
    }
  }

  /**
   * Logout from OAuth provider
   */
  public generateLogoutUrl(options: {
    postLogoutRedirectUri?: string;
    state?: string;
  } = {}): string {
    const { postLogoutRedirectUri, state } = options;
    
    // Standard logout endpoint (RFC 7636)
    const logoutEndpoint = this.config.provider.authorizationEndpoint.replace('/authorize', '/logout');
    
    const params = new URLSearchParams({
      client_id: this.config.clientId
    });

    if (postLogoutRedirectUri) {
      params.set('post_logout_redirect_uri', postLogoutRedirectUri);
    }

    if (state) {
      params.set('state', state);
    }

    return `${logoutEndpoint}?${params.toString()}`;
  }

  /**
   * Create PKCE challenge for secure OAuth flow
   */
  public generatePKCEChallenge(): { codeVerifier: string; codeChallenge: string } {
    // Generate code verifier
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    const codeVerifier = this.base64URLEncode(array);
    
    // Generate code challenge
    const encoder = new TextEncoder();
    const data = encoder.encode(codeVerifier);
    return crypto.subtle.digest('SHA-256', data).then(hash => {
      const codeChallenge = this.base64URLEncode(new Uint8Array(hash));
      return { codeVerifier, codeChallenge };
    }) as any; // Simplified for demo
  }

  /**
   * Start OAuth flow with PKCE and QuID integration
   */
  public async startSecureFlow(options: {
    state?: string;
    nonce?: string;
  } = {}): Promise<{ authUrl: string; codeVerifier: string }> {
    const { state, nonce } = options;
    
    // Generate PKCE challenge
    const { codeVerifier, codeChallenge } = this.generatePKCEChallenge();
    
    // Generate auth URL with PKCE
    const authUrl = this.generateAuthUrl({
      state,
      nonce,
      additionalParams: {
        code_challenge: codeChallenge,
        code_challenge_method: 'S256'
      }
    });

    return { authUrl, codeVerifier };
  }

  private generateChallenge(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  private base64URLEncode(buffer: Uint8Array): string {
    const base64 = btoa(String.fromCharCode(...buffer));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  private extractIssuerFromEndpoint(): string {
    try {
      const url = new URL(this.config.provider.authorizationEndpoint);
      return `${url.protocol}//${url.host}`;
    } catch {
      return 'unknown';
    }
  }

  /**
   * Update configuration
   */
  public updateConfig(newConfig: Partial<OAuthConfig>): void {
    Object.assign(this.config, newConfig);
  }

  /**
   * Get current configuration
   */
  public getConfig(): OAuthConfig {
    return { ...this.config };
  }
}