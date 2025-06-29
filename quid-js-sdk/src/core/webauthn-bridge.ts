/**
 * WebAuthn Bridge
 * Provides fallback WebAuthn functionality when QuID extension is not available
 */

import {
  AuthenticationRequest,
  AuthenticationResponse,
  WebAuthnCredentialRequestOptions,
  QuIDCredential
} from '../types';
import { Logger } from '../utils/logger';

export class WebAuthnBridge {
  private logger: Logger;
  private client: any; // Reference to QuIDClient

  constructor(client: any, logger: Logger) {
    this.client = client;
    this.logger = logger;
  }

  /**
   * Initialize WebAuthn bridge
   */
  public init(): void {
    if (!this.isWebAuthnSupported()) {
      this.logger.warn('WebAuthn is not supported in this browser');
      return;
    }

    this.logger.debug('WebAuthn bridge initialized');
  }

  /**
   * Check if WebAuthn is supported
   */
  public isWebAuthnSupported(): boolean {
    return !!(navigator.credentials && navigator.credentials.create && navigator.credentials.get);
  }

  /**
   * Authenticate using WebAuthn as fallback
   */
  public async authenticate(request: AuthenticationRequest): Promise<AuthenticationResponse> {
    if (!this.isWebAuthnSupported()) {
      return {
        success: false,
        error: 'WebAuthn is not supported in this browser'
      };
    }

    try {
      this.logger.debug('Starting WebAuthn fallback authentication');

      const options: WebAuthnCredentialRequestOptions = {
        publicKey: {
          challenge: this.stringToArrayBuffer(request.challenge),
          timeout: request.timeout,
          rpId: request.rpId || this.extractDomain(request.origin),
          allowCredentials: request.allowCredentials || [],
          userVerification: request.userVerification || 'preferred'
        }
      };

      const credential = await navigator.credentials.get(options) as PublicKeyCredential | null;

      if (!credential) {
        return {
          success: false,
          error: 'No credential returned from WebAuthn'
        };
      }

      const response = credential.response as AuthenticatorAssertionResponse;
      
      const quidCredential: QuIDCredential = {
        id: credential.id,
        rawId: this.arrayBufferToString(credential.rawId),
        type: 'public-key',
        response: {
          authenticatorData: this.arrayBufferToString(response.authenticatorData),
          clientDataJSON: this.arrayBufferToString(response.clientDataJSON),
          signature: this.arrayBufferToString(response.signature),
          userHandle: response.userHandle ? this.arrayBufferToString(response.userHandle) : undefined
        }
      };

      this.logger.info('WebAuthn fallback authentication successful');

      return {
        success: true,
        credential: quidCredential
      };

    } catch (error) {
      this.logger.error('WebAuthn fallback authentication failed:', error);
      
      return {
        success: false,
        error: this.getWebAuthnErrorMessage(error)
      };
    }
  }

  /**
   * Create a WebAuthn credential (registration)
   */
  public async createCredential(options: {
    challenge: string;
    userId: string;
    userName: string;
    userDisplayName: string;
    rpName: string;
    rpId?: string;
    timeout?: number;
  }): Promise<AuthenticationResponse> {
    if (!this.isWebAuthnSupported()) {
      return {
        success: false,
        error: 'WebAuthn is not supported in this browser'
      };
    }

    try {
      this.logger.debug('Creating WebAuthn credential');

      const createOptions: CredentialCreationOptions = {
        publicKey: {
          challenge: this.stringToArrayBuffer(options.challenge),
          rp: {
            name: options.rpName,
            id: options.rpId || this.extractDomain(window.location.origin)
          },
          user: {
            id: this.stringToArrayBuffer(options.userId),
            name: options.userName,
            displayName: options.userDisplayName
          },
          pubKeyCredParams: [
            { alg: -7, type: 'public-key' }, // ES256
            { alg: -257, type: 'public-key' } // RS256
          ],
          timeout: options.timeout || 60000,
          authenticatorSelection: {
            authenticatorAttachment: 'platform',
            userVerification: 'preferred',
            requireResidentKey: false
          },
          attestation: 'direct'
        }
      };

      const credential = await navigator.credentials.create(createOptions) as PublicKeyCredential | null;

      if (!credential) {
        return {
          success: false,
          error: 'No credential created'
        };
      }

      const response = credential.response as AuthenticatorAttestationResponse;
      
      const quidCredential: QuIDCredential = {
        id: credential.id,
        rawId: this.arrayBufferToString(credential.rawId),
        type: 'public-key',
        response: {
          authenticatorData: this.arrayBufferToString(response.authenticatorData),
          clientDataJSON: this.arrayBufferToString(response.clientDataJSON),
          signature: '', // Not applicable for creation
          userHandle: undefined
        }
      };

      this.logger.info('WebAuthn credential created successfully');

      return {
        success: true,
        credential: quidCredential
      };

    } catch (error) {
      this.logger.error('WebAuthn credential creation failed:', error);
      
      return {
        success: false,
        error: this.getWebAuthnErrorMessage(error)
      };
    }
  }

  /**
   * Check if a credential exists for the current origin
   */
  public async isCredentialAvailable(): Promise<boolean> {
    if (!this.isWebAuthnSupported()) {
      return false;
    }

    try {
      // Try a simple get call with no allowCredentials to see if platform authenticator is available
      const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
      return available;
    } catch (error) {
      this.logger.debug('Could not check credential availability:', error);
      return false;
    }
  }

  /**
   * Cleanup WebAuthn bridge
   */
  public cleanup(): void {
    // Nothing to cleanup for WebAuthn
    this.logger.debug('WebAuthn bridge cleaned up');
  }

  /**
   * Convert string to ArrayBuffer
   */
  private stringToArrayBuffer(str: string): ArrayBuffer {
    // If it's already a hex string, convert from hex
    if (/^[0-9a-fA-F]+$/.test(str)) {
      const bytes = new Uint8Array(str.length / 2);
      for (let i = 0; i < str.length; i += 2) {
        bytes[i / 2] = parseInt(str.substr(i, 2), 16);
      }
      return bytes.buffer;
    }
    
    // Otherwise, convert from UTF-8
    const encoder = new TextEncoder();
    return encoder.encode(str).buffer;
  }

  /**
   * Convert ArrayBuffer to string
   */
  private arrayBufferToString(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Extract domain from origin
   */
  private extractDomain(origin: string): string {
    try {
      const url = new URL(origin);
      return url.hostname;
    } catch (error) {
      this.logger.warn('Could not extract domain from origin:', origin);
      return 'localhost';
    }
  }

  /**
   * Get user-friendly error message from WebAuthn error
   */
  private getWebAuthnErrorMessage(error: any): string {
    if (!error) return 'Unknown WebAuthn error';

    const errorName = error.name || '';
    const errorMessage = error.message || '';

    switch (errorName) {
      case 'NotAllowedError':
        return 'Authentication was cancelled or not allowed';
      case 'SecurityError':
        return 'Security error during authentication';
      case 'NotSupportedError':
        return 'WebAuthn is not supported on this device';
      case 'InvalidStateError':
        return 'Invalid state for WebAuthn operation';
      case 'ConstraintError':
        return 'WebAuthn constraints could not be satisfied';
      case 'UnknownError':
        return 'An unknown error occurred during authentication';
      default:
        return errorMessage || 'WebAuthn authentication failed';
    }
  }
}