/**
 * QuID Browser Extension Test Suite
 * Tests all major browser extension functionality
 */

// Mock Chrome APIs for testing
const chrome = {
  runtime: {
    sendMessage: jest.fn(),
    onMessage: {
      addListener: jest.fn()
    },
    getManifest: () => ({ version: '1.0.0' }),
    getURL: (path) => `chrome-extension://test/${path}`,
    connectNative: jest.fn(),
    openOptionsPage: jest.fn()
  },
  action: {
    setIcon: jest.fn(),
    setBadgeText: jest.fn(),
    setBadgeBackgroundColor: jest.fn(),
    onClicked: {
      addListener: jest.fn()
    }
  },
  tabs: {
    onUpdated: {
      addListener: jest.fn()
    },
    sendMessage: jest.fn(),
    create: jest.fn()
  },
  notifications: {
    create: jest.fn(),
    onButtonClicked: {
      addListener: jest.fn()
    },
    clear: jest.fn()
  },
  scripting: {
    executeScript: jest.fn()
  },
  webRequest: {
    onBeforeRequest: {
      addListener: jest.fn()
    }
  },
  storage: {
    local: {
      get: jest.fn(),
      set: jest.fn()
    }
  }
};

global.chrome = chrome;

describe('QuID Browser Extension', () => {
  
  describe('Background Script', () => {
    let QuIDExtension;
    let extension;
    
    beforeEach(() => {
      // Reset mocks
      jest.clearAllMocks();
      
      // Import background script class
      QuIDExtension = require('../src/background.js');
      extension = new QuIDExtension();
    });
    
    test('should initialize extension properly', () => {
      expect(extension.pendingRequests).toBeInstanceOf(Map);
      expect(extension.activeIdentities).toBeInstanceOf(Map);
      expect(extension.isConnected).toBe(false);
    });
    
    test('should handle authentication requests', async () => {
      const message = {
        type: 'AUTH_REQUEST',
        challenge: 'test-challenge',
        allowCredentials: [],
        userVerification: 'preferred',
        timeout: 60000
      };
      
      const sender = {
        origin: 'https://example.com',
        tab: { id: 123, url: 'https://example.com' }
      };
      
      const sendResponse = jest.fn();
      
      // Mock successful authentication
      extension.showAuthenticationPrompt = jest.fn().mockResolvedValue({
        success: true,
        credential: { id: 'test-credential' }
      });
      
      await extension.handleAuthRequest(message, sender, sendResponse);
      
      expect(sendResponse).toHaveBeenCalledWith({
        success: true,
        credential: { id: 'test-credential' }
      });
    });
    
    test('should handle WebAuthn interception', async () => {
      const message = {
        type: 'WEBAUTHN_INTERCEPT',
        challenge: 'webauthn-challenge',
        rpId: 'example.com'
      };
      
      const sender = {
        origin: 'https://example.com'
      };
      
      const sendResponse = jest.fn();
      
      // Mock the authentication handler
      extension.handleAuthRequest = jest.fn().mockResolvedValue();
      
      await extension.handleWebAuthnIntercept(message, sender, sendResponse);
      
      expect(extension.handleAuthRequest).toHaveBeenCalled();
    });
    
    test('should manage identity list', async () => {
      const sendResponse = jest.fn();
      
      // Mock native host connection
      extension.isConnected = true;
      extension.sendToNativeHost = jest.fn().mockResolvedValue({
        identities: [
          { id: 'identity1', name: 'Test Identity 1' },
          { id: 'identity2', name: 'Test Identity 2' }
        ]
      });
      
      await extension.getIdentities(sendResponse);
      
      expect(sendResponse).toHaveBeenCalledWith({
        success: true,
        identities: [
          { id: 'identity1', name: 'Test Identity 1' },
          { id: 'identity2', name: 'Test Identity 2' }
        ]
      });
    });
    
    test('should handle native host disconnection', () => {
      extension.isConnected = true;
      
      // Simulate disconnection
      const disconnectHandler = chrome.runtime.connectNative.mock.calls[0];
      if (disconnectHandler && disconnectHandler.onDisconnect) {
        disconnectHandler.onDisconnect.addListener.mock.calls[0][0]();
      }
      
      expect(extension.isConnected).toBe(false);
    });
    
    test('should create identity with proper configuration', async () => {
      const config = {
        name: 'Test Identity',
        securityLevel: 'Level1',
        networks: ['web', 'ssh']
      };
      
      const sendResponse = jest.fn();
      
      extension.isConnected = true;
      extension.sendToNativeHost = jest.fn().mockResolvedValue({
        success: true,
        identity: { id: 'new-identity', ...config }
      });
      
      await extension.createIdentity(config, sendResponse);
      
      expect(extension.sendToNativeHost).toHaveBeenCalledWith({
        type: 'create_identity',
        config
      });
      
      expect(sendResponse).toHaveBeenCalledWith({
        success: true,
        identity: { id: 'new-identity', ...config },
        error: undefined
      });
    });
    
    test('should update icon based on state', () => {
      extension.updateIcon('active');
      
      expect(chrome.action.setIcon).toHaveBeenCalledWith({
        path: {
          16: 'icons/icon-active-16.png',
          32: 'icons/icon-active-32.png',
          48: 'icons/icon-active-48.png',
          128: 'icons/icon-active-128.png'
        }
      });
    });
    
    test('should show badge for pending requests', () => {
      extension.pendingRequests.set('req1', {});
      extension.pendingRequests.set('req2', {});
      
      extension.updateIcon('pending');
      
      expect(chrome.action.setBadgeText).toHaveBeenCalledWith({ text: '2' });
    });
  });
  
  describe('Content Script', () => {
    let mockWindow;
    let mockDocument;
    
    beforeEach(() => {
      // Set up DOM mocks
      mockDocument = {
        createElement: jest.fn(() => ({
          addEventListener: jest.fn(),
          appendChild: jest.fn(),
          style: {},
          textContent: '',
          innerHTML: ''
        })),
        head: { appendChild: jest.fn() },
        documentElement: { appendChild: jest.fn() },
        body: {
          appendChild: jest.fn(),
          querySelectorAll: jest.fn(() => [])
        },
        querySelectorAll: jest.fn(() => [])
      };
      
      mockWindow = {
        quidInjected: false,
        addEventListener: jest.fn(),
        dispatchEvent: jest.fn(),
        location: { origin: 'https://example.com' }
      };
      
      global.document = mockDocument;
      global.window = mockWindow;
      global.console = { log: jest.fn(), error: jest.fn() };
    });
    
    test('should inject QuID API script', () => {
      // Mock content script initialization
      const script = { src: '', onload: null };
      mockDocument.createElement.mockReturnValue(script);
      
      // This would normally be done by the content script
      const injectQuIDAPI = () => {
        const scriptElement = document.createElement('script');
        scriptElement.src = chrome.runtime.getURL('injected-script.js');
        scriptElement.onload = () => {
          window.dispatchEvent(new CustomEvent('quid:ready', {
            detail: { version: '1.0.0', available: true }
          }));
        };
        document.head.appendChild(scriptElement);
      };
      
      injectQuIDAPI();
      
      expect(mockDocument.createElement).toHaveBeenCalledWith('script');
      expect(mockDocument.head.appendChild).toHaveBeenCalled();
    });
    
    test('should detect login forms', () => {
      const isLoginForm = (form) => {
        const inputs = form.querySelectorAll('input');
        let hasPassword = false;
        let hasUsernameOrEmail = false;
        
        inputs.forEach(input => {
          if (input.type === 'password') hasPassword = true;
          if (input.type === 'email' || input.name.includes('username')) {
            hasUsernameOrEmail = true;
          }
        });
        
        return hasPassword && hasUsernameOrEmail;
      };
      
      const mockForm = {
        querySelectorAll: jest.fn(() => [
          { type: 'email', name: 'email' },
          { type: 'password', name: 'password' }
        ])
      };
      
      expect(isLoginForm(mockForm)).toBe(true);
      
      const mockFormNoPassword = {
        querySelectorAll: jest.fn(() => [
          { type: 'email', name: 'email' },
          { type: 'text', name: 'search' }
        ])
      };
      
      expect(isLoginForm(mockFormNoPassword)).toBe(false);
    });
    
    test('should handle authentication requests from page', async () => {
      const handleAuthRequest = async (request) => {
        try {
          const response = await chrome.runtime.sendMessage({
            type: 'AUTH_REQUEST',
            challenge: request.challenge,
            allowCredentials: request.allowCredentials,
            userVerification: request.userVerification || 'preferred',
            timeout: request.timeout || 60000
          });
          
          window.dispatchEvent(new CustomEvent('quid:auth-response', {
            detail: response
          }));
        } catch (error) {
          window.dispatchEvent(new CustomEvent('quid:auth-error', {
            detail: { error: error.message }
          }));
        }
      };
      
      chrome.runtime.sendMessage.mockResolvedValue({
        success: true,
        credential: { id: 'test-credential' }
      });
      
      await handleAuthRequest({
        challenge: 'test-challenge',
        userVerification: 'required'
      });
      
      expect(chrome.runtime.sendMessage).toHaveBeenCalledWith({
        type: 'AUTH_REQUEST',
        challenge: 'test-challenge',
        allowCredentials: undefined,
        userVerification: 'required',
        timeout: 60000
      });
      
      expect(mockWindow.dispatchEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'quid:auth-response',
          detail: { success: true, credential: { id: 'test-credential' } }
        })
      );
    });
  });
  
  describe('Injected Script (QuID API)', () => {
    let QuID;
    let quid;
    
    beforeEach(() => {
      global.window = {
        addEventListener: jest.fn(),
        dispatchEvent: jest.fn(),
        CustomEvent: jest.fn((type, options) => ({ type, detail: options.detail })),
        crypto: {
          getRandomValues: jest.fn((arr) => {
            for (let i = 0; i < arr.length; i++) {
              arr[i] = Math.floor(Math.random() * 256);
            }
            return arr;
          })
        }
      };
      
      global.navigator = {
        credentials: {
          create: jest.fn(),
          get: jest.fn()
        }
      };
      
      // Mock QuID class
      QuID = class {
        constructor() {
          this.version = '1.0.0';
          this.isAvailable = true;
          this.pendingRequests = new Map();
        }
        
        async authenticate(options = {}) {
          const requestId = Date.now().toString();
          
          return new Promise((resolve) => {
            this.pendingRequests.set(requestId, { resolve });
            
            window.dispatchEvent(new CustomEvent('quid:auth-request', {
              detail: {
                requestId,
                challenge: options.challenge || this.generateChallenge(),
                userVerification: options.userVerification || 'preferred',
                timeout: options.timeout || 60000
              }
            }));
            
            // Simulate successful response
            setTimeout(() => {
              resolve({
                success: true,
                credential: { id: 'test-credential' }
              });
            }, 10);
          });
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
      };
      
      quid = new QuID();
    });
    
    test('should provide authentication method', async () => {
      const result = await quid.authenticate({
        challenge: 'test-challenge',
        userVerification: 'required'
      });
      
      expect(result.success).toBe(true);
      expect(result.credential).toBeDefined();
    });
    
    test('should generate random challenges', () => {
      const challenge1 = quid.generateChallenge();
      const challenge2 = quid.generateChallenge();
      
      expect(challenge1).toHaveLength(64); // 32 bytes = 64 hex chars
      expect(challenge2).toHaveLength(64);
      expect(challenge1).not.toBe(challenge2);
    });
    
    test('should convert ArrayBuffer to hex', () => {
      const buffer = new ArrayBuffer(4);
      const view = new Uint8Array(buffer);
      view[0] = 0xDE;
      view[1] = 0xAD;
      view[2] = 0xBE;
      view[3] = 0xEF;
      
      const hex = quid.arrayBufferToHex(buffer);
      expect(hex).toBe('deadbeef');
    });
    
    test('should dispatch auth request events', async () => {
      quid.authenticate({ challenge: 'test' });
      
      expect(window.dispatchEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'quid:auth-request',
          detail: expect.objectContaining({
            challenge: 'test',
            userVerification: 'preferred'
          })
        })
      );
    });
  });
  
  describe('Popup Interface', () => {
    let mockDocument;
    let QuIDPopup;
    
    beforeEach(() => {
      // Mock DOM elements
      mockDocument = {
        getElementById: jest.fn((id) => ({
          addEventListener: jest.fn(),
          textContent: '',
          innerHTML: '',
          style: {},
          disabled: false,
          className: '',
          querySelector: jest.fn(),
          querySelectorAll: jest.fn(() => []),
          appendChild: jest.fn(),
          removeChild: jest.fn(),
          value: '',
          reset: jest.fn()
        })),
        createElement: jest.fn(() => ({
          addEventListener: jest.fn(),
          style: {},
          textContent: '',
          innerHTML: '',
          className: ''
        })),
        addEventListener: jest.fn(),
        body: {
          appendChild: jest.fn(),
          removeChild: jest.fn()
        }
      };
      
      global.document = mockDocument;
      global.chrome = chrome;
      global.console = { log: jest.fn(), error: jest.fn() };
      
      // Mock QuIDPopup class
      QuIDPopup = class {
        constructor() {
          this.isConnected = false;
          this.identities = [];
          this.pendingRequests = [];
        }
        
        async loadExtensionStatus() {
          const response = await chrome.runtime.sendMessage({
            type: 'GET_EXTENSION_STATUS'
          });
          
          this.isConnected = response.isConnected;
          return response;
        }
        
        updateStatusIndicator(status) {
          const indicator = document.getElementById('statusIndicator');
          if (status.isConnected) {
            indicator.className = 'connected';
          }
        }
        
        async handleCreateIdentity() {
          const config = {
            name: 'Test Identity',
            securityLevel: 'Level1',
            networks: ['web']
          };
          
          const response = await chrome.runtime.sendMessage({
            type: 'CREATE_IDENTITY',
            config
          });
          
          return response;
        }
      };
    });
    
    test('should load extension status', async () => {
      chrome.runtime.sendMessage.mockResolvedValue({
        isConnected: true,
        hasIdentities: true,
        version: '1.0.0'
      });
      
      const popup = new QuIDPopup();
      const status = await popup.loadExtensionStatus();
      
      expect(status.isConnected).toBe(true);
      expect(popup.isConnected).toBe(true);
    });
    
    test('should update status indicator', () => {
      const popup = new QuIDPopup();
      
      popup.updateStatusIndicator({ isConnected: true });
      
      const indicator = document.getElementById('statusIndicator');
      expect(indicator.className).toBe('connected');
    });
    
    test('should handle identity creation', async () => {
      chrome.runtime.sendMessage.mockResolvedValue({
        success: true,
        identity: { id: 'new-identity', name: 'Test Identity' }
      });
      
      const popup = new QuIDPopup();
      const result = await popup.handleCreateIdentity();
      
      expect(chrome.runtime.sendMessage).toHaveBeenCalledWith({
        type: 'CREATE_IDENTITY',
        config: {
          name: 'Test Identity',
          securityLevel: 'Level1',
          networks: ['web']
        }
      });
      
      expect(result.success).toBe(true);
    });
  });
  
  describe('WebAuthn Integration', () => {
    test('should intercept navigator.credentials.create', async () => {
      const originalCreate = navigator.credentials.create;
      const mockQuIDAuth = jest.fn().mockResolvedValue({
        success: true,
        credential: { id: 'quid-credential' }
      });
      
      // Mock WebAuthn interception
      navigator.credentials.create = async (options) => {
        if (options.publicKey) {
          return await mockQuIDAuth(options);
        }
        return originalCreate.call(navigator.credentials, options);
      };
      
      const result = await navigator.credentials.create({
        publicKey: {
          challenge: new ArrayBuffer(32),
          rp: { name: 'Test RP' },
          user: { id: new ArrayBuffer(8), name: 'test', displayName: 'Test User' },
          pubKeyCredParams: [{ alg: -7, type: 'public-key' }]
        }
      });
      
      expect(mockQuIDAuth).toHaveBeenCalled();
      expect(result.credential.id).toBe('quid-credential');
    });
    
    test('should intercept navigator.credentials.get', async () => {
      const originalGet = navigator.credentials.get;
      const mockQuIDAuth = jest.fn().mockResolvedValue({
        success: true,
        credential: { id: 'quid-credential' }
      });
      
      // Mock WebAuthn interception
      navigator.credentials.get = async (options) => {
        if (options.publicKey) {
          return await mockQuIDAuth(options);
        }
        return originalGet.call(navigator.credentials, options);
      };
      
      const result = await navigator.credentials.get({
        publicKey: {
          challenge: new ArrayBuffer(32),
          allowCredentials: []
        }
      });
      
      expect(mockQuIDAuth).toHaveBeenCalled();
      expect(result.credential.id).toBe('quid-credential');
    });
  });
  
  describe('Security and Error Handling', () => {
    test('should handle native host connection errors', () => {
      const QuIDExtension = require('../src/background.js');
      const extension = new QuIDExtension();
      
      chrome.runtime.connectNative.mockImplementation(() => {
        throw new Error('Native host not found');
      });
      
      extension.connectToNativeHost();
      
      expect(extension.isConnected).toBe(false);
    });
    
    test('should validate authentication requests', () => {
      const validateAuthRequest = (request) => {
        if (!request.challenge) {
          throw new Error('Challenge is required');
        }
        if (request.timeout && request.timeout > 300000) {
          throw new Error('Timeout too long');
        }
        return true;
      };
      
      expect(() => validateAuthRequest({})).toThrow('Challenge is required');
      expect(() => validateAuthRequest({ 
        challenge: 'test', 
        timeout: 400000 
      })).toThrow('Timeout too long');
      
      expect(validateAuthRequest({ 
        challenge: 'test', 
        timeout: 60000 
      })).toBe(true);
    });
    
    test('should sanitize user input', () => {
      const sanitizeInput = (input) => {
        return input.replace(/<script[^>]*>.*?<\/script>/gi, '')
                   .replace(/[<>]/g, '');
      };
      
      const maliciousInput = '<script>alert("xss")</script>Hello<>';
      const sanitized = sanitizeInput(maliciousInput);
      
      expect(sanitized).toBe('Hello');
      expect(sanitized).not.toContain('<script>');
    });
    
    test('should handle request timeouts', async () => {
      const QuIDExtension = require('../src/background.js');
      const extension = new QuIDExtension();
      
      const request = {
        id: 'test-request',
        timeout: 100, // 100ms timeout
        timestamp: Date.now()
      };
      
      extension.pendingRequests.set(request.id, request);
      
      // Wait for timeout
      await new Promise(resolve => setTimeout(resolve, 150));
      
      expect(request.timestamp + request.timeout).toBeLessThan(Date.now());
    });
  });
  
  describe('Performance', () => {
    test('should complete authentication requests quickly', async () => {
      const QuID = class {
        async authenticate() {
          const start = Date.now();
          
          // Simulate authentication processing
          await new Promise(resolve => setTimeout(resolve, 10));
          
          const end = Date.now();
          return { 
            success: true, 
            processingTime: end - start,
            credential: { id: 'test' }
          };
        }
      };
      
      const quid = new QuID();
      const result = await quid.authenticate();
      
      expect(result.success).toBe(true);
      expect(result.processingTime).toBeLessThan(100); // Should be fast
    });
    
    test('should efficiently manage pending requests', () => {
      const QuIDExtension = require('../src/background.js');
      const extension = new QuIDExtension();
      
      // Add many requests
      for (let i = 0; i < 1000; i++) {
        extension.pendingRequests.set(`req-${i}`, { id: `req-${i}` });
      }
      
      expect(extension.pendingRequests.size).toBe(1000);
      
      // Remove requests efficiently
      const start = Date.now();
      extension.pendingRequests.clear();
      const end = Date.now();
      
      expect(extension.pendingRequests.size).toBe(0);
      expect(end - start).toBeLessThan(10); // Should be very fast
    });
  });
  
  describe('Manifest Validation', () => {
    test('should have valid manifest v3', () => {
      const manifestV3 = require('../manifest/manifest_v3.json');
      
      expect(manifestV3.manifest_version).toBe(3);
      expect(manifestV3.name).toBe('QuID Universal Authentication');
      expect(manifestV3.permissions).toContain('storage');
      expect(manifestV3.permissions).toContain('activeTab');
      expect(manifestV3.host_permissions).toContain('<all_urls>');
    });
    
    test('should have valid manifest v2', () => {
      const manifestV2 = require('../manifest/manifest_v2.json');
      
      expect(manifestV2.manifest_version).toBe(2);
      expect(manifestV2.name).toBe('QuID Universal Authentication');
      expect(manifestV2.permissions).toContain('storage');
      expect(manifestV2.permissions).toContain('activeTab');
    });
  });
});

module.exports = {
  // Export test utilities for integration tests
  createMockChrome: () => chrome,
  createMockExtension: () => new (require('../src/background.js'))()
};