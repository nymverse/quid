/**
 * QuID Browser Extension Injected Script
 * Provides the QuID API to web pages and intercepts WebAuthn calls
 */

(function() {
  'use strict';
  
  // Prevent multiple injections
  if (window.QuID) {
    return;
  }
  
  console.log('🔐 QuID API injected into page');
  
  /**
   * QuID API class that websites can use for authentication
   */
  class QuID {
    constructor() {
      this.version = '1.0.0';
      this.isAvailable = true;
      this.pendingRequests = new Map();
      
      this.setupEventListeners();
      this.interceptWebAuthn();
    }
    
    setupEventListeners() {
      // Listen for responses from the content script
      window.addEventListener('quid:auth-response', (event) => {
        this.handleAuthResponse(event.detail);
      });
      
      window.addEventListener('quid:auth-error', (event) => {
        this.handleAuthError(event.detail);
      });
      
      window.addEventListener('quid:identities-response', (event) => {
        this.handleIdentitiesResponse(event.detail);
      });
      
      window.addEventListener('quid:sign-response', (event) => {
        this.handleSignResponse(event.detail);
      });
    }
    
    /**
     * Authenticate user with QuID
     * @param {Object} options - Authentication options
     * @returns {Promise} - Authentication result
     */
    async authenticate(options = {}) {
      const requestId = this.generateRequestId();
      
      return new Promise((resolve, reject) => {
        // Store promise callbacks
        this.pendingRequests.set(requestId, { resolve, reject });
        
        // Send authentication request
        window.dispatchEvent(new CustomEvent('quid:auth-request', {
          detail: {
            requestId,
            challenge: options.challenge || this.generateChallenge(),
            userVerification: options.userVerification || 'preferred',
            timeout: options.timeout || 60000,
            allowCredentials: options.allowCredentials
          }
        }));
        
        // Set timeout
        setTimeout(() => {
          if (this.pendingRequests.has(requestId)) {
            this.pendingRequests.delete(requestId);
            reject(new Error('Authentication request timed out'));
          }
        }, options.timeout || 60000);
      });
    }
    
    /**
     * Get list of available identities
     * @returns {Promise} - List of identities
     */
    async getIdentities() {
      const requestId = this.generateRequestId();
      
      return new Promise((resolve, reject) => {
        this.pendingRequests.set(requestId, { resolve, reject });
        
        window.dispatchEvent(new CustomEvent('quid:get-identities', {
          detail: { requestId }
        }));
        
        setTimeout(() => {
          if (this.pendingRequests.has(requestId)) {
            this.pendingRequests.delete(requestId);
            reject(new Error('Get identities request timed out'));
          }
        }, 10000);
      });
    }
    
    /**
     * Sign a challenge with a specific identity
     * @param {string} identityId - Identity to use for signing
     * @param {string} challenge - Challenge to sign
     * @returns {Promise} - Signature result
     */
    async signChallenge(identityId, challenge) {
      const requestId = this.generateRequestId();
      
      return new Promise((resolve, reject) => {
        this.pendingRequests.set(requestId, { resolve, reject });
        
        window.dispatchEvent(new CustomEvent('quid:sign-challenge', {
          detail: {
            requestId,
            identityId,
            challenge
          }
        }));
        
        setTimeout(() => {
          if (this.pendingRequests.has(requestId)) {
            this.pendingRequests.delete(requestId);
            reject(new Error('Sign challenge request timed out'));
          }
        }, 30000);
      });
    }
    
    /**
     * Check if QuID is available and working
     * @returns {Promise} - Status check result
     */
    async isReady() {
      try {
        const identities = await this.getIdentities();
        return {
          available: true,
          hasIdentities: identities.length > 0,
          version: this.version
        };
      } catch (error) {
        return {
          available: false,
          error: error.message,
          version: this.version
        };
      }
    }
    
    /**
     * Create a new QuID identity
     * @param {Object} config - Identity configuration
     * @returns {Promise} - Created identity
     */
    async createIdentity(config = {}) {
      const requestId = this.generateRequestId();
      
      return new Promise((resolve, reject) => {
        this.pendingRequests.set(requestId, { resolve, reject });
        
        window.dispatchEvent(new CustomEvent('quid:create-identity', {
          detail: {
            requestId,
            config: {
              name: config.name || 'Web Identity',
              securityLevel: config.securityLevel || 'Level1',
              networks: config.networks || ['web']
            }
          }
        }));
        
        setTimeout(() => {
          if (this.pendingRequests.has(requestId)) {
            this.pendingRequests.delete(requestId);
            reject(new Error('Create identity request timed out'));
          }
        }, 30000);
      });
    }
    
    interceptWebAuthn() {
      // Intercept and replace navigator.credentials calls with QuID
      if (!navigator.credentials) {
        return;
      }
      
      const originalCreate = navigator.credentials.create;
      const originalGet = navigator.credentials.get;
      
      navigator.credentials.create = async (options) => {
        console.log('🔒 WebAuthn create() intercepted, using QuID instead');
        
        if (options.publicKey) {
          try {
            const result = await this.authenticate({
              challenge: this.arrayBufferToHex(options.publicKey.challenge),
              userVerification: options.publicKey.userVerification,
              timeout: options.publicKey.timeout
            });
            
            return this.convertToWebAuthnCredential(result);
          } catch (error) {
            // Fallback to original WebAuthn if QuID fails
            console.warn('QuID authentication failed, falling back to WebAuthn:', error);
            return originalCreate.call(navigator.credentials, options);
          }
        }
        
        return originalCreate.call(navigator.credentials, options);
      };
      
      navigator.credentials.get = async (options) => {
        console.log('🔒 WebAuthn get() intercepted, using QuID instead');
        
        if (options.publicKey) {
          try {
            const result = await this.authenticate({
              challenge: this.arrayBufferToHex(options.publicKey.challenge),
              allowCredentials: options.publicKey.allowCredentials,
              userVerification: options.publicKey.userVerification,
              timeout: options.publicKey.timeout
            });
            
            return this.convertToWebAuthnCredential(result);
          } catch (error) {
            // Fallback to original WebAuthn if QuID fails
            console.warn('QuID authentication failed, falling back to WebAuthn:', error);
            return originalGet.call(navigator.credentials, options);
          }
        }
        
        return originalGet.call(navigator.credentials, options);
      };
      
      console.log('✅ WebAuthn intercepted and enhanced with QuID');
    }
    
    convertToWebAuthnCredential(quidResult) {
      // Convert QuID authentication result to WebAuthn credential format
      if (!quidResult.success || !quidResult.credential) {
        throw new Error(quidResult.error || 'Authentication failed');
      }
      
      const credential = quidResult.credential;
      
      return {
        id: credential.id,
        rawId: this.hexToArrayBuffer(credential.id),
        response: {
          authenticatorData: this.hexToArrayBuffer(credential.response.authenticatorData),
          clientDataJSON: this.hexToArrayBuffer(credential.response.clientDataJSON),
          signature: this.hexToArrayBuffer(credential.response.signature),
          userHandle: credential.response.userHandle ? 
                      this.hexToArrayBuffer(credential.response.userHandle) : null
        },
        type: 'public-key'
      };
    }
    
    handleAuthResponse(response) {
      const request = this.findPendingRequest(response);
      if (request) {
        request.resolve(response);
      }
    }
    
    handleAuthError(error) {
      const request = this.findPendingRequest(error);
      if (request) {
        request.reject(new Error(error.error || 'Authentication failed'));
      }
    }
    
    handleIdentitiesResponse(response) {
      const request = this.findPendingRequest(response);
      if (request) {
        if (response.success) {
          request.resolve(response.identities || []);
        } else {
          request.reject(new Error(response.error || 'Failed to get identities'));
        }
      }
    }
    
    handleSignResponse(response) {
      const request = this.findPendingRequest(response);
      if (request) {
        if (response.success) {
          request.resolve(response.signature);
        } else {
          request.reject(new Error(response.error || 'Failed to sign challenge'));
        }
      }
    }
    
    findPendingRequest(response) {
      // For now, resolve the first pending request
      // In a real implementation, we'd match by requestId
      const requests = Array.from(this.pendingRequests.values());
      if (requests.length > 0) {
        const request = requests[0];
        this.pendingRequests.clear(); // Clear all for simplicity
        return request;
      }
      return null;
    }
    
    generateRequestId() {
      return `quid-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    }
    
    generateChallenge() {
      const array = new Uint8Array(32);
      crypto.getRandomValues(array);
      return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }
    
    arrayBufferToHex(buffer) {
      return Array.from(new Uint8Array(buffer))
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
    }
    
    hexToArrayBuffer(hex) {
      const bytes = new Uint8Array(hex.length / 2);
      for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
      }
      return bytes.buffer;
    }
  }
  
  // Make QuID available globally
  window.QuID = new QuID();
  
  // Also provide as a module for websites that use module systems
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = QuID;
  }
  
  // Dispatch ready event
  window.dispatchEvent(new CustomEvent('quid:injected', {
    detail: {
      version: window.QuID.version,
      available: true
    }
  }));
  
  // Add QuID button styling to page
  const style = document.createElement('style');
  style.textContent = `
    .quid-button {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
    }
    
    .quid-button:hover {
      transform: translateY(-1px) !important;
    }
    
    .quid-button:active {
      transform: translateY(0) !important;
    }
    
    .quid-enhanced {
      position: relative;
    }
    
    .quid-enhanced::after {
      content: "🔐";
      position: absolute;
      right: 8px;
      top: 50%;
      transform: translateY(-50%);
      font-size: 12px;
    }
  `;
  document.head.appendChild(style);
  
  console.log('✅ QuID API ready for use');
  
})();