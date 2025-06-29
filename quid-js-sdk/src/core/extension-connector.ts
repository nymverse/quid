/**
 * Extension Connector
 * Handles communication with the QuID browser extension
 */

import {
  QuIDConfig,
  QuIDIdentity,
  AuthenticationRequest,
  AuthenticationResponse,
  CreateIdentityRequest
} from '../types';
import { Logger } from '../utils/logger';

export class ExtensionConnector {
  private config: QuIDConfig;
  private logger: Logger;
  public isConnected = false;
  private extensionId?: string;

  constructor(config: QuIDConfig, logger: Logger) {
    this.config = config;
    this.logger = logger;
  }

  /**
   * Attempt to connect to the QuID browser extension
   */
  public async connect(): Promise<boolean> {
    try {
      // Check if we're in a browser environment
      if (typeof window === 'undefined' || !window.chrome?.runtime) {
        this.logger.debug('Not in browser environment or Chrome APIs not available');
        return false;
      }

      // Try to detect QuID extension
      const detected = await this.detectExtension();
      if (!detected) {
        this.logger.debug('QuID extension not detected');
        return false;
      }

      // Test connection
      const status = await this.sendMessage({ type: 'GET_EXTENSION_STATUS' });
      if (status && status.isConnected !== undefined) {
        this.isConnected = true;
        this.logger.info('Successfully connected to QuID extension');
        return true;
      }

      return false;

    } catch (error) {
      this.logger.debug('Failed to connect to extension:', error);
      return false;
    }
  }

  /**
   * Disconnect from the extension
   */
  public disconnect(): void {
    this.isConnected = false;
    this.extensionId = undefined;
  }

  /**
   * Get identities from the extension
   */
  public async getIdentities(): Promise<QuIDIdentity[]> {
    if (!this.isConnected) {
      throw new Error('Extension not connected');
    }

    try {
      const response = await this.sendMessage({ type: 'GET_IDENTITIES' });
      
      if (response.success && response.identities) {
        return response.identities.map(this.mapIdentity);
      } else {
        throw new Error(response.error || 'Failed to get identities');
      }
    } catch (error) {
      this.logger.error('Failed to get identities from extension:', error);
      throw error;
    }
  }

  /**
   * Create a new identity via the extension
   */
  public async createIdentity(request: CreateIdentityRequest): Promise<QuIDIdentity> {
    if (!this.isConnected) {
      throw new Error('Extension not connected');
    }

    try {
      const response = await this.sendMessage({
        type: 'CREATE_IDENTITY',
        config: {
          name: request.name,
          securityLevel: request.securityLevel || 'Level1',
          networks: request.networks || ['web']
        }
      });

      if (response.success && response.identity) {
        return this.mapIdentity(response.identity);
      } else {
        throw new Error(response.error || 'Failed to create identity');
      }
    } catch (error) {
      this.logger.error('Failed to create identity via extension:', error);
      throw error;
    }
  }

  /**
   * Authenticate via the extension
   */
  public async authenticate(request: AuthenticationRequest): Promise<AuthenticationResponse> {
    if (!this.isConnected) {
      throw new Error('Extension not connected');
    }

    try {
      const response = await this.sendMessage({
        type: 'AUTH_REQUEST',
        challenge: request.challenge,
        allowCredentials: request.allowCredentials,
        userVerification: request.userVerification,
        timeout: request.timeout
      });

      return {
        success: response.success || false,
        error: response.error,
        credential: response.credential,
        identity: response.identity ? this.mapIdentity(response.identity) : undefined
      };

    } catch (error) {
      this.logger.error('Authentication via extension failed:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Authentication failed'
      };
    }
  }

  /**
   * Sign a challenge via the extension
   */
  public async signChallenge(identityId: string, challenge: string): Promise<string> {
    if (!this.isConnected) {
      throw new Error('Extension not connected');
    }

    try {
      const response = await this.sendMessage({
        type: 'SIGN_CHALLENGE',
        identityId,
        challenge,
        origin: window.location.origin
      });

      if (response.success && response.signature) {
        return response.signature;
      } else {
        throw new Error(response.error || 'Failed to sign challenge');
      }
    } catch (error) {
      this.logger.error('Failed to sign challenge via extension:', error);
      throw error;
    }
  }

  /**
   * Detect if QuID extension is installed
   */
  private async detectExtension(): Promise<boolean> {
    try {
      // Method 1: Check for QuID API in page
      if (window.QuID && window.QuID.isAvailable) {
        this.logger.debug('QuID API detected in page');
        return true;
      }

      // Method 2: Check for extension via custom event
      return new Promise((resolve) => {
        const timeout = setTimeout(() => resolve(false), 1000);
        
        const handler = (event: CustomEvent) => {
          if (event.detail && event.detail.available) {
            clearTimeout(timeout);
            window.removeEventListener('quid:ready', handler as EventListener);
            resolve(true);
          }
        };

        window.addEventListener('quid:ready', handler as EventListener);
        
        // Try to trigger extension detection
        window.dispatchEvent(new CustomEvent('quid:detect'));
      });

    } catch (error) {
      this.logger.debug('Extension detection failed:', error);
      return false;
    }
  }

  /**
   * Send message to extension
   */
  private async sendMessage(message: any): Promise<any> {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('Extension message timeout'));
      }, this.config.timeout || 60000);

      try {
        // Method 1: Direct extension communication (if extension ID is known)
        if (this.extensionId && window.chrome?.runtime) {
          window.chrome.runtime.sendMessage(this.extensionId, message, (response) => {
            clearTimeout(timeout);
            if (window.chrome.runtime.lastError) {
              reject(new Error(window.chrome.runtime.lastError.message));
            } else {
              resolve(response);
            }
          });
          return;
        }

        // Method 2: Use QuID API if available
        if (window.QuID) {
          this.handleQuIDAPIMessage(message, resolve, reject, timeout);
          return;
        }

        // Method 3: Custom events
        this.handleCustomEventMessage(message, resolve, reject, timeout);

      } catch (error) {
        clearTimeout(timeout);
        reject(error);
      }
    });
  }

  /**
   * Handle message via QuID API
   */
  private handleQuIDAPIMessage(message: any, resolve: Function, reject: Function, timeout: NodeJS.Timeout): void {
    try {
      switch (message.type) {
        case 'GET_EXTENSION_STATUS':
          window.QuID.isReady().then(resolve).catch(reject);
          break;
          
        case 'GET_IDENTITIES':
          window.QuID.getIdentities().then(resolve).catch(reject);
          break;
          
        case 'AUTH_REQUEST':
          window.QuID.authenticate({
            challenge: message.challenge,
            userVerification: message.userVerification,
            timeout: message.timeout,
            allowCredentials: message.allowCredentials
          }).then(resolve).catch(reject);
          break;
          
        case 'CREATE_IDENTITY':
          window.QuID.createIdentity(message.config).then(resolve).catch(reject);
          break;
          
        case 'SIGN_CHALLENGE':
          window.QuID.signChallenge(message.identityId, message.challenge)
            .then(signature => resolve({ success: true, signature }))
            .catch(reject);
          break;
          
        default:
          reject(new Error('Unknown message type'));
      }
    } catch (error) {
      clearTimeout(timeout);
      reject(error);
    }
  }

  /**
   * Handle message via custom events
   */
  private handleCustomEventMessage(message: any, resolve: Function, reject: Function, timeout: NodeJS.Timeout): void {
    const requestId = `quid-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    const handler = (event: CustomEvent) => {
      if (event.detail && event.detail.requestId === requestId) {
        clearTimeout(timeout);
        window.removeEventListener('quid:response', handler as EventListener);
        resolve(event.detail.response);
      }
    };

    window.addEventListener('quid:response', handler as EventListener);
    
    window.dispatchEvent(new CustomEvent('quid:request', {
      detail: { ...message, requestId }
    }));
  }

  /**
   * Map extension identity to SDK identity
   */
  private mapIdentity(extIdentity: any): QuIDIdentity {
    return {
      id: extIdentity.id,
      name: extIdentity.name,
      securityLevel: extIdentity.security_level || extIdentity.securityLevel || 'Level1',
      networks: extIdentity.networks || ['web'],
      isActive: extIdentity.is_active !== false,
      createdAt: new Date(extIdentity.created_at || extIdentity.createdAt || Date.now()),
      lastUsedAt: extIdentity.last_used_at || extIdentity.lastUsedAt ? 
        new Date(extIdentity.last_used_at || extIdentity.lastUsedAt) : undefined,
      publicKey: extIdentity.public_key || extIdentity.publicKey
    };
  }
}

// Extend window interface for QuID API
declare global {
  interface Window {
    QuID?: {
      isAvailable: boolean;
      authenticate: (options: any) => Promise<any>;
      getIdentities: () => Promise<any[]>;
      createIdentity: (config: any) => Promise<any>;
      signChallenge: (identityId: string, challenge: string) => Promise<string>;
      isReady: () => Promise<any>;
    };
  }
}