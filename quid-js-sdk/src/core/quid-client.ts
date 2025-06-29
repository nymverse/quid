/**
 * QuID Client
 * Core client for QuID authentication operations
 */

import {
  QuIDConfig,
  QuIDIdentity,
  AuthenticationRequest,
  AuthenticationResponse,
  CreateIdentityRequest,
  QuIDEvent,
  QuIDEventType,
  QuIDSDKError
} from '../types';
import { ExtensionConnector } from './extension-connector';
import { WebAuthnBridge } from './webauthn-bridge';
import { EventEmitter } from '../utils/event-emitter';
import { Logger } from '../utils/logger';

export class QuIDClient extends EventEmitter<QuIDEvent> {
  private config: Required<QuIDConfig>;
  private extensionConnector: ExtensionConnector;
  private webauthnBridge: WebAuthnBridge;
  private logger: Logger;
  private isReady = false;

  constructor(config: QuIDConfig = {}) {
    super();
    
    this.config = {
      baseUrl: '',
      timeout: 60000,
      userVerification: 'preferred',
      debug: false,
      extensionId: '',
      enableWebAuthnFallback: true,
      ...config
    };

    this.logger = new Logger(this.config.debug);
    this.extensionConnector = new ExtensionConnector(this.config, this.logger);
    this.webauthnBridge = new WebAuthnBridge(this, this.logger);

    this.init();
  }

  private async init(): Promise<void> {
    try {
      this.logger.debug('Initializing QuID client...');

      // Try to connect to browser extension
      const extensionConnected = await this.extensionConnector.connect();
      
      if (extensionConnected) {
        this.logger.info('Connected to QuID browser extension');
        this.emit({
          type: 'extension-connected',
          timestamp: new Date()
        });
      } else {
        this.logger.warn('QuID browser extension not available');
        
        if (this.config.enableWebAuthnFallback) {
          this.logger.info('WebAuthn fallback enabled');
        }
      }

      // Set up WebAuthn integration
      this.webauthnBridge.init();

      this.isReady = true;
      this.emit({
        type: 'ready',
        timestamp: new Date()
      });

      this.logger.info('QuID client ready');

    } catch (error) {
      this.logger.error('Failed to initialize QuID client:', error);
      this.emit({
        type: 'error',
        data: error,
        timestamp: new Date()
      });
    }
  }

  /**
   * Check if QuID is ready for use
   */
  public get ready(): boolean {
    return this.isReady;
  }

  /**
   * Check if browser extension is available
   */
  public get extensionAvailable(): boolean {
    return this.extensionConnector.isConnected;
  }

  /**
   * Get available QuID identities
   */
  public async getIdentities(): Promise<QuIDIdentity[]> {
    if (!this.isReady) {
      throw this.createError('SDK_NOT_READY', 'QuID SDK is not ready');
    }

    try {
      if (this.extensionConnector.isConnected) {
        return await this.extensionConnector.getIdentities();
      } else {
        this.logger.warn('No extension available, returning empty identity list');
        return [];
      }
    } catch (error) {
      this.logger.error('Failed to get identities:', error);
      throw this.createError('GET_IDENTITIES_FAILED', 'Failed to retrieve identities', error);
    }
  }

  /**
   * Create a new QuID identity
   */
  public async createIdentity(request: CreateIdentityRequest): Promise<QuIDIdentity> {
    if (!this.isReady) {
      throw this.createError('SDK_NOT_READY', 'QuID SDK is not ready');
    }

    if (!this.extensionConnector.isConnected) {
      throw this.createError('EXTENSION_NOT_AVAILABLE', 'QuID browser extension is required for identity creation');
    }

    try {
      this.logger.debug('Creating new identity:', request);
      
      const identity = await this.extensionConnector.createIdentity(request);
      
      this.emit({
        type: 'identity-created',
        data: identity,
        timestamp: new Date()
      });

      this.logger.info('Identity created successfully:', identity.id);
      return identity;

    } catch (error) {
      this.logger.error('Failed to create identity:', error);
      throw this.createError('CREATE_IDENTITY_FAILED', 'Failed to create identity', error);
    }
  }

  /**
   * Authenticate using QuID
   */
  public async authenticate(request: Partial<AuthenticationRequest> = {}): Promise<AuthenticationResponse> {
    if (!this.isReady) {
      throw this.createError('SDK_NOT_READY', 'QuID SDK is not ready');
    }

    const authRequest: AuthenticationRequest = {
      challenge: request.challenge || this.generateChallenge(),
      origin: request.origin || window.location.origin,
      userVerification: request.userVerification || this.config.userVerification,
      timeout: request.timeout || this.config.timeout,
      allowCredentials: request.allowCredentials,
      rpId: request.rpId
    };

    this.emit({
      type: 'authentication-started',
      data: authRequest,
      timestamp: new Date()
    });

    try {
      this.logger.debug('Starting authentication:', authRequest);

      let response: AuthenticationResponse;

      if (this.extensionConnector.isConnected) {
        // Use QuID extension
        response = await this.extensionConnector.authenticate(authRequest);
      } else if (this.config.enableWebAuthnFallback && navigator.credentials) {
        // Fallback to WebAuthn
        this.logger.info('Using WebAuthn fallback');
        response = await this.webauthnBridge.authenticate(authRequest);
      } else {
        throw this.createError('NO_AUTH_METHOD', 'No authentication method available');
      }

      if (response.success) {
        this.emit({
          type: 'authentication-completed',
          data: response,
          timestamp: new Date()
        });
        this.logger.info('Authentication successful');
      } else {
        this.emit({
          type: 'authentication-failed',
          data: response,
          timestamp: new Date()
        });
        this.logger.warn('Authentication failed:', response.error);
      }

      return response;

    } catch (error) {
      this.logger.error('Authentication error:', error);
      
      const errorResponse: AuthenticationResponse = {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown authentication error'
      };

      this.emit({
        type: 'authentication-failed',
        data: errorResponse,
        timestamp: new Date()
      });

      return errorResponse;
    }
  }

  /**
   * Sign a challenge with a specific identity
   */
  public async signChallenge(identityId: string, challenge: string): Promise<string> {
    if (!this.isReady) {
      throw this.createError('SDK_NOT_READY', 'QuID SDK is not ready');
    }

    if (!this.extensionConnector.isConnected) {
      throw this.createError('EXTENSION_NOT_AVAILABLE', 'QuID browser extension is required for signing');
    }

    try {
      this.logger.debug('Signing challenge:', { identityId, challenge });
      
      const signature = await this.extensionConnector.signChallenge(identityId, challenge);
      
      this.logger.info('Challenge signed successfully');
      return signature;

    } catch (error) {
      this.logger.error('Failed to sign challenge:', error);
      throw this.createError('SIGN_CHALLENGE_FAILED', 'Failed to sign challenge', error);
    }
  }

  /**
   * Check connection status
   */
  public async getStatus(): Promise<{
    ready: boolean;
    extensionAvailable: boolean;
    identityCount: number;
    version: string;
  }> {
    const identities = this.extensionAvailable ? await this.getIdentities() : [];
    
    return {
      ready: this.isReady,
      extensionAvailable: this.extensionAvailable,
      identityCount: identities.length,
      version: '1.0.0'
    };
  }

  /**
   * Update configuration
   */
  public updateConfig(newConfig: Partial<QuIDConfig>): void {
    Object.assign(this.config, newConfig);
    this.logger.setDebug(this.config.debug);
    this.logger.debug('Configuration updated:', newConfig);
  }

  /**
   * Disconnect and cleanup
   */
  public disconnect(): void {
    this.logger.debug('Disconnecting QuID client');
    
    this.extensionConnector.disconnect();
    this.webauthnBridge.cleanup();
    this.isReady = false;
    
    this.emit({
      type: 'extension-disconnected',
      timestamp: new Date()
    });
  }

  private generateChallenge(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  private createError(code: string, message: string, cause?: any): QuIDSDKError {
    const error = new Error(message) as QuIDSDKError;
    error.name = 'QuIDSDKError';
    error.code = code;
    error.details = cause;
    return error;
  }
}