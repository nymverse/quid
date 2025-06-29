/**
 * QuID Browser Extension Background Script
 * Handles authentication requests, WebAuthn integration, and native messaging
 */

// Import security policy
importScripts('security-policy.js');

// Extension state management
class QuIDExtension {
  constructor() {
    this.pendingRequests = new Map();
    this.activeIdentities = new Map();
    this.nativePort = null;
    this.isConnected = false;
    this.securityPolicy = new SecurityPolicy();
    
    this.init();
  }
  
  async init() {
    console.log('🔐 QuID Extension initialized');
    
    // Set up message listeners
    this.setupMessageListeners();
    
    // Connect to native host
    this.connectToNativeHost();
    
    // Set up WebRequest listeners for authentication interception
    this.setupWebRequestListeners();
    
    // Initialize icon and state
    this.updateIcon('inactive');
    
    // Set up periodic cleanup
    setInterval(() => {
      this.securityPolicy.cleanup();
    }, 300000); // Clean up every 5 minutes
    
    // Log extension startup
    this.securityPolicy.logSecurityEvent('EXTENSION_STARTED');
  }
  
  setupMessageListeners() {
    // Listen for messages from content scripts
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      this.handleMessage(message, sender, sendResponse);
      return true; // Keep message channel open for async response
    });
    
    // Listen for tab updates to inject QuID support
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      if (changeInfo.status === 'complete' && tab.url) {
        this.injectQuIDSupport(tabId, tab.url);
      }
    });
    
    // Listen for extension icon clicks
    chrome.action?.onClicked.addListener((tab) => {
      this.handleIconClick(tab);
    });
  }
  
  async handleMessage(message, sender, sendResponse) {
    try {
      switch (message.type) {
        case 'AUTH_REQUEST':
          await this.handleAuthRequest(message, sender, sendResponse);
          break;
          
        case 'WEBAUTHN_INTERCEPT':
          await this.handleWebAuthnIntercept(message, sender, sendResponse);
          break;
          
        case 'GET_IDENTITIES':
          await this.getIdentities(sendResponse);
          break;
          
        case 'CREATE_IDENTITY':
          await this.createIdentity(message.config, sendResponse);
          break;
          
        case 'SIGN_CHALLENGE':
          await this.signChallenge(message, sendResponse);
          break;
          
        case 'GET_EXTENSION_STATUS':
          sendResponse({
            isConnected: this.isConnected,
            hasIdentities: this.activeIdentities.size > 0,
            version: chrome.runtime.getManifest().version
          });
          break;
          
        case 'GET_SECURITY_LOG':
          sendResponse({
            success: true,
            log: this.securityPolicy.getSecurityLog(message.filters)
          });
          break;
          
        case 'UPDATE_SECURITY_POLICIES':
          await this.securityPolicy.updatePolicies(message.policies);
          sendResponse({ success: true });
          break;
          
        case 'GET_SECURITY_POLICIES':
          sendResponse({
            success: true,
            policies: this.securityPolicy.getPolicies()
          });
          break;
          
        default:
          console.warn('Unknown message type:', message.type);
          sendResponse({ error: 'Unknown message type' });
      }
    } catch (error) {
      console.error('Error handling message:', error);
      sendResponse({ error: error.message });
    }
  }
  
  async handleAuthRequest(message, sender, sendResponse) {
    const request = {
      id: this.generateRequestId(),
      origin: sender.origin || sender.tab?.url,
      tabId: sender.tab?.id,
      challenge: message.challenge,
      allowCredentials: message.allowCredentials,
      userVerification: message.userVerification,
      timeout: message.timeout || 60000,
      timestamp: Date.now()
    };
    
    console.log('📨 Authentication request received:', request);
    
    // Validate request against security policies
    const validation = this.securityPolicy.validateAuthRequest(request);
    if (!validation.allowed) {
      console.warn('❌ Authentication request blocked:', validation.reason);
      sendResponse({
        success: false,
        error: validation.reason
      });
      return;
    }
    
    // Use sanitized request
    const sanitizedRequest = validation.sanitizedRequest;
    sanitizedRequest.id = request.id;
    sanitizedRequest.tabId = request.tabId;
    
    // Store pending request
    this.pendingRequests.set(sanitizedRequest.id, sanitizedRequest);
    
    // Update icon to show pending authentication
    this.updateIcon('pending');
    
    // Show user prompt for authentication
    const result = await this.showAuthenticationPrompt(sanitizedRequest);
    
    // Clean up
    this.pendingRequests.delete(sanitizedRequest.id);
    this.updateIcon(this.pendingRequests.size > 0 ? 'pending' : 'active');
    
    sendResponse(result);
  }
  
  async handleWebAuthnIntercept(message, sender, sendResponse) {
    console.log('🔒 WebAuthn request intercepted:', message);
    
    // Validate WebAuthn interception
    const webauthnValidation = this.securityPolicy.validateWebAuthnInterception({
      origin: sender.origin,
      challenge: message.challenge,
      rpId: message.rpId
    });
    
    if (!webauthnValidation.allowed) {
      console.warn('❌ WebAuthn interception blocked:', webauthnValidation.reason);
      sendResponse({
        success: false,
        error: webauthnValidation.reason
      });
      return;
    }
    
    // Convert WebAuthn request to QuID authentication
    const quidRequest = {
      type: 'AUTH_REQUEST',
      challenge: message.challenge,
      allowCredentials: message.allowCredentials,
      userVerification: message.userVerification,
      timeout: message.timeout,
      rpId: message.rpId,
      origin: sender.origin
    };
    
    // Handle as QuID authentication
    await this.handleAuthRequest(quidRequest, sender, sendResponse);
  }
  
  async showAuthenticationPrompt(request) {
    return new Promise((resolve) => {
      // Create notification or popup for user interaction
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon-48.png',
        title: 'QuID Authentication Request',
        message: `${request.origin} is requesting authentication`,
        buttons: [
          { title: 'Approve' },
          { title: 'Deny' }
        ]
      }, (notificationId) => {
        // Handle notification response
        chrome.notifications.onButtonClicked.addListener((id, buttonIndex) => {
          if (id === notificationId) {
            chrome.notifications.clear(id);
            
            if (buttonIndex === 0) {
              // Approved - proceed with authentication
              this.processAuthentication(request).then(resolve);
            } else {
              // Denied
              resolve({
                success: false,
                error: 'User denied authentication request'
              });
            }
          }
        });
        
        // Auto-deny after timeout
        setTimeout(() => {
          chrome.notifications.clear(notificationId);
          resolve({
            success: false,
            error: 'Authentication request timed out'
          });
        }, request.timeout);
      });
    });
  }
  
  async processAuthentication(request) {
    try {
      // Send authentication request to native host
      if (!this.isConnected) {
        throw new Error('Native host not connected');
      }
      
      const nativeRequest = {
        type: 'authenticate',
        origin: request.origin,
        challenge: request.challenge,
        userVerification: request.userVerification
      };
      
      const response = await this.sendToNativeHost(nativeRequest);
      
      if (response.success) {
        console.log('✅ Authentication successful');
        return {
          success: true,
          credential: {
            id: response.credentialId,
            rawId: response.credentialId,
            response: {
              authenticatorData: response.authenticatorData,
              clientDataJSON: response.clientDataJSON,
              signature: response.signature,
              userHandle: response.userHandle
            },
            type: 'public-key'
          }
        };
      } else {
        throw new Error(response.error || 'Authentication failed');
      }
    } catch (error) {
      console.error('❌ Authentication failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }
  
  connectToNativeHost() {
    try {
      this.nativePort = chrome.runtime.connectNative('com.quid.native_host');
      
      this.nativePort.onMessage.addListener((message) => {
        console.log('📥 Native message received:', message);
        this.handleNativeMessage(message);
      });
      
      this.nativePort.onDisconnect.addListener(() => {
        console.log('🔌 Native host disconnected');
        this.isConnected = false;
        this.updateIcon('inactive');
        
        // Attempt to reconnect after delay
        setTimeout(() => {
          this.connectToNativeHost();
        }, 5000);
      });
      
      // Send ping to test connection
      this.nativePort.postMessage({ type: 'ping' });
      this.isConnected = true;
      this.updateIcon('active');
      
      console.log('🔗 Connected to native host');
    } catch (error) {
      console.error('❌ Failed to connect to native host:', error);
      this.isConnected = false;
      this.updateIcon('inactive');
    }
  }
  
  async sendToNativeHost(message) {
    return new Promise((resolve, reject) => {
      if (!this.isConnected || !this.nativePort) {
        reject(new Error('Native host not connected'));
        return;
      }
      
      // Validate message against security policy
      if (!this.securityPolicy.validateNativeHostMessage(message)) {
        reject(new Error('Invalid native host message'));
        return;
      }
      
      const requestId = this.generateRequestId();
      message.requestId = requestId;
      
      const timeout = setTimeout(() => {
        reject(new Error('Native host request timeout'));
      }, 30000);
      
      const listener = (response) => {
        if (response.requestId === requestId) {
          clearTimeout(timeout);
          this.nativePort.onMessage.removeListener(listener);
          resolve(response);
        }
      };
      
      this.nativePort.onMessage.addListener(listener);
      this.nativePort.postMessage(message);
    });
  }
  
  handleNativeMessage(message) {
    switch (message.type) {
      case 'pong':
        console.log('🏓 Native host connection confirmed');
        break;
        
      case 'identity_list':
        this.updateIdentityList(message.identities);
        break;
        
      case 'auth_result':
        this.handleAuthResult(message);
        break;
        
      default:
        console.log('📨 Unknown native message:', message);
    }
  }
  
  setupWebRequestListeners() {
    // Intercept WebAuthn credential creation requests
    chrome.webRequest.onBeforeRequest.addListener(
      (details) => {
        // Check if this is a WebAuthn request that should be handled by QuID
        if (this.shouldInterceptWebAuthn(details)) {
          console.log('🚫 Intercepting WebAuthn request for QuID handling');
          
          // Inject QuID authentication instead
          chrome.tabs.sendMessage(details.tabId, {
            type: 'REPLACE_WEBAUTHN',
            requestDetails: details
          });
        }
      },
      { urls: ['<all_urls>'] },
      ['requestBody']
    );
  }
  
  shouldInterceptWebAuthn(details) {
    // Logic to determine if we should intercept this WebAuthn request
    // For now, intercept all navigator.credentials.create/get calls
    return details.url.includes('webauthn') || 
           details.requestBody?.includes('credentials');
  }
  
  async injectQuIDSupport(tabId, url) {
    try {
      // Check security policy for content script injection
      if (!this.securityPolicy.shouldInjectContentScript(url)) {
        console.log(`🚫 Content script injection blocked for: ${url}`);
        return;
      }
      
      // Inject QuID support script into the page
      await chrome.scripting.executeScript({
        target: { tabId },
        files: ['injected-script.js']
      });
      
      console.log(`✅ QuID support injected into tab ${tabId}: ${url}`);
    } catch (error) {
      // Ignore errors for special pages (chrome://, about:, etc.)
      if (!url.startsWith('chrome://') && !url.startsWith('about:')) {
        console.warn('Failed to inject QuID support:', error);
      }
    }
  }
  
  updateIcon(state) {
    const iconPaths = {
      active: 'icons/icon-active-',
      pending: 'icons/icon-pending-',
      inactive: 'icons/icon-inactive-'
    };
    
    const basePath = iconPaths[state] || iconPaths.inactive;
    
    chrome.action.setIcon({
      path: {
        16: `${basePath}16.png`,
        32: `${basePath}32.png`,
        48: `${basePath}48.png`,
        128: `${basePath}128.png`
      }
    });
    
    // Update badge text
    const badgeText = this.pendingRequests.size > 0 ? 
                      this.pendingRequests.size.toString() : '';
    chrome.action.setBadgeText({ text: badgeText });
    chrome.action.setBadgeBackgroundColor({ color: '#FF4444' });
  }
  
  handleIconClick(tab) {
    // Open QuID popup or manage identities
    chrome.tabs.create({
      url: chrome.runtime.getURL('options/options.html')
    });
  }
  
  generateRequestId() {
    return `quid-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }
  
  async getIdentities(sendResponse) {
    try {
      if (!this.isConnected) {
        throw new Error('Native host not connected');
      }
      
      const response = await this.sendToNativeHost({ type: 'list_identities' });
      sendResponse({
        success: true,
        identities: response.identities || []
      });
    } catch (error) {
      sendResponse({
        success: false,
        error: error.message
      });
    }
  }
  
  async createIdentity(config, sendResponse) {
    try {
      if (!this.isConnected) {
        throw new Error('Native host not connected');
      }
      
      const response = await this.sendToNativeHost({
        type: 'create_identity',
        config
      });
      
      sendResponse({
        success: response.success,
        identity: response.identity,
        error: response.error
      });
    } catch (error) {
      sendResponse({
        success: false,
        error: error.message
      });
    }
  }
  
  async signChallenge(message, sendResponse) {
    try {
      if (!this.isConnected) {
        throw new Error('Native host not connected');
      }
      
      const response = await this.sendToNativeHost({
        type: 'sign_challenge',
        identityId: message.identityId,
        challenge: message.challenge,
        origin: message.origin
      });
      
      sendResponse({
        success: response.success,
        signature: response.signature,
        error: response.error
      });
    } catch (error) {
      sendResponse({
        success: false,
        error: error.message
      });
    }
  }
  
  updateIdentityList(identities) {
    this.activeIdentities.clear();
    identities.forEach(identity => {
      this.activeIdentities.set(identity.id, identity);
    });
    
    console.log(`🆔 Updated identity list: ${identities.length} identities`);
  }
}

// Initialize extension
const quidExtension = new QuIDExtension();

// Export for testing
if (typeof module !== 'undefined' && module.exports) {
  module.exports = QuIDExtension;
}