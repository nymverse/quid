/**
 * QuID Browser Extension Content Script
 * Injects QuID authentication capabilities into web pages
 */

(function() {
  'use strict';
  
  // Prevent multiple injections
  if (window.quidInjected) {
    return;
  }
  window.quidInjected = true;
  
  console.log('🔐 QuID content script loaded');
  
  class QuIDContentScript {
    constructor() {
      this.init();
    }
    
    init() {
      // Inject QuID API into the page
      this.injectQuIDAPI();
      
      // Set up WebAuthn interception
      this.setupWebAuthnInterception();
      
      // Listen for messages from background script
      this.setupMessageListeners();
      
      // Monitor for login forms
      this.monitorLoginForms();
    }
    
    injectQuIDAPI() {
      // Create and inject the QuID API script
      const script = document.createElement('script');
      script.src = chrome.runtime.getURL('injected-script.js');
      script.onload = () => {
        console.log('✅ QuID API injected');
        
        // Notify the page that QuID is available
        window.dispatchEvent(new CustomEvent('quid:ready', {
          detail: {
            version: chrome.runtime.getManifest().version,
            available: true
          }
        }));
      };
      
      (document.head || document.documentElement).appendChild(script);
    }
    
    setupWebAuthnInterception() {
      // Listen for WebAuthn calls to redirect to QuID
      window.addEventListener('quid:webauthn-intercept', async (event) => {
        const { detail } = event;
        console.log('🔒 WebAuthn intercepted:', detail);
        
        try {
          const response = await chrome.runtime.sendMessage({
            type: 'WEBAUTHN_INTERCEPT',
            challenge: detail.challenge,
            allowCredentials: detail.allowCredentials,
            userVerification: detail.userVerification,
            timeout: detail.timeout,
            rpId: detail.rpId
          });
          
          // Send response back to page
          window.dispatchEvent(new CustomEvent('quid:webauthn-response', {
            detail: response
          }));
        } catch (error) {
          console.error('❌ WebAuthn interception failed:', error);
          window.dispatchEvent(new CustomEvent('quid:webauthn-error', {
            detail: { error: error.message }
          }));
        }
      });
    }
    
    setupMessageListeners() {
      // Listen for messages from background script
      chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        this.handleBackgroundMessage(message, sendResponse);
        return true;
      });
      
      // Listen for QuID authentication requests from the page
      window.addEventListener('quid:auth-request', async (event) => {
        const { detail } = event;
        await this.handleAuthRequest(detail);
      });
      
      // Listen for identity management requests
      window.addEventListener('quid:get-identities', async (event) => {
        await this.handleGetIdentities(event.detail);
      });
      
      // Listen for signing requests
      window.addEventListener('quid:sign-challenge', async (event) => {
        await this.handleSignChallenge(event.detail);
      });
    }
    
    async handleBackgroundMessage(message, sendResponse) {
      switch (message.type) {
        case 'REPLACE_WEBAUTHN':
          this.replaceWebAuthnWithQuID(message.requestDetails);
          break;
          
        case 'AUTH_RESULT':
          this.notifyPageOfAuthResult(message.result);
          break;
          
        default:
          console.log('📨 Unknown background message:', message);
      }
    }
    
    async handleAuthRequest(request) {
      try {
        console.log('🔐 Authentication request from page:', request);
        
        const response = await chrome.runtime.sendMessage({
          type: 'AUTH_REQUEST',
          challenge: request.challenge,
          allowCredentials: request.allowCredentials,
          userVerification: request.userVerification || 'preferred',
          timeout: request.timeout || 60000
        });
        
        // Notify page of result
        window.dispatchEvent(new CustomEvent('quid:auth-response', {
          detail: response
        }));
      } catch (error) {
        console.error('❌ Authentication request failed:', error);
        window.dispatchEvent(new CustomEvent('quid:auth-error', {
          detail: { error: error.message }
        }));
      }
    }
    
    async handleGetIdentities(request) {
      try {
        const response = await chrome.runtime.sendMessage({
          type: 'GET_IDENTITIES'
        });
        
        window.dispatchEvent(new CustomEvent('quid:identities-response', {
          detail: response
        }));
      } catch (error) {
        console.error('❌ Get identities failed:', error);
        window.dispatchEvent(new CustomEvent('quid:identities-error', {
          detail: { error: error.message }
        }));
      }
    }
    
    async handleSignChallenge(request) {
      try {
        const response = await chrome.runtime.sendMessage({
          type: 'SIGN_CHALLENGE',
          identityId: request.identityId,
          challenge: request.challenge,
          origin: window.location.origin
        });
        
        window.dispatchEvent(new CustomEvent('quid:sign-response', {
          detail: response
        }));
      } catch (error) {
        console.error('❌ Sign challenge failed:', error);
        window.dispatchEvent(new CustomEvent('quid:sign-error', {
          detail: { error: error.message }
        }));
      }
    }
    
    monitorLoginForms() {
      // Monitor for login forms and offer QuID authentication
      const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === Node.ELEMENT_NODE) {
              this.processElement(node);
            }
          });
        });
      });
      
      observer.observe(document.body, {
        childList: true,
        subtree: true
      });
      
      // Process existing elements
      this.processElement(document.body);
    }
    
    processElement(element) {
      // Look for login forms
      const forms = element.querySelectorAll('form');
      forms.forEach(form => {
        if (this.isLoginForm(form)) {
          this.enhanceLoginForm(form);
        }
      });
      
      // Look for WebAuthn buttons
      const webauthnButtons = element.querySelectorAll('[data-webauthn], .webauthn-button, #webauthn-signin');
      webauthnButtons.forEach(button => {
        this.enhanceWebAuthnButton(button);
      });
    }
    
    isLoginForm(form) {
      // Detect if this is a login form
      const inputs = form.querySelectorAll('input');
      let hasPassword = false;
      let hasUsernameOrEmail = false;
      
      inputs.forEach(input => {
        const type = input.type.toLowerCase();
        const name = input.name.toLowerCase();
        const id = input.id.toLowerCase();
        
        if (type === 'password') {
          hasPassword = true;
        }
        
        if (type === 'email' || 
            name.includes('email') || name.includes('username') || name.includes('user') ||
            id.includes('email') || id.includes('username') || id.includes('user')) {
          hasUsernameOrEmail = true;
        }
      });
      
      return hasPassword && hasUsernameOrEmail;
    }
    
    enhanceLoginForm(form) {
      // Check if already enhanced
      if (form.querySelector('.quid-button')) {
        return;
      }
      
      console.log('🔍 Enhancing login form with QuID');
      
      // Create QuID login button
      const quidButton = document.createElement('button');
      quidButton.type = 'button';
      quidButton.className = 'quid-button';
      quidButton.textContent = '🔐 Sign in with QuID';
      quidButton.style.cssText = `
        display: block;
        width: 100%;
        padding: 12px;
        margin: 10px 0;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        border-radius: 6px;
        font-size: 14px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.3s ease;
        box-shadow: 0 2px 4px rgba(102, 126, 234, 0.3);
      `;
      
      // Add hover effects
      quidButton.addEventListener('mouseenter', () => {
        quidButton.style.transform = 'translateY(-1px)';
        quidButton.style.boxShadow = '0 4px 8px rgba(102, 126, 234, 0.4)';
      });
      
      quidButton.addEventListener('mouseleave', () => {
        quidButton.style.transform = 'translateY(0)';
        quidButton.style.boxShadow = '0 2px 4px rgba(102, 126, 234, 0.3)';
      });
      
      // Add click handler
      quidButton.addEventListener('click', async (e) => {
        e.preventDefault();
        await this.handleQuIDLogin(form);
      });
      
      // Insert button into form
      const submitButton = form.querySelector('input[type="submit"], button[type="submit"]');
      if (submitButton) {
        submitButton.parentNode.insertBefore(quidButton, submitButton);
      } else {
        form.appendChild(quidButton);
      }
    }
    
    enhanceWebAuthnButton(button) {
      // Replace or enhance existing WebAuthn buttons
      if (button.dataset.quidEnhanced) {
        return;
      }
      
      button.dataset.quidEnhanced = 'true';
      
      // Add QuID branding
      const originalText = button.textContent;
      button.textContent = `🔐 ${originalText} (QuID Enhanced)`;
      
      // Intercept click to use QuID instead of native WebAuthn
      button.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        
        // Trigger QuID authentication
        window.dispatchEvent(new CustomEvent('quid:auth-request', {
          detail: {
            challenge: this.generateChallenge(),
            userVerification: 'preferred',
            timeout: 60000
          }
        }));
      }, true);
    }
    
    async handleQuIDLogin(form) {
      try {
        console.log('🔐 QuID login initiated');
        
        // Show loading state
        const quidButton = form.querySelector('.quid-button');
        const originalText = quidButton.textContent;
        quidButton.textContent = '🔄 Authenticating...';
        quidButton.disabled = true;
        
        // Request QuID authentication
        window.dispatchEvent(new CustomEvent('quid:auth-request', {
          detail: {
            challenge: this.generateChallenge(),
            userVerification: 'required',
            timeout: 60000,
            origin: window.location.origin
          }
        }));
        
        // Listen for response
        const handleResponse = (event) => {
          const { detail } = event;
          
          if (detail.success) {
            console.log('✅ QuID authentication successful');
            this.completeLogin(form, detail.credential);
          } else {
            console.error('❌ QuID authentication failed:', detail.error);
            this.showError(quidButton, detail.error);
          }
          
          // Restore button state
          quidButton.textContent = originalText;
          quidButton.disabled = false;
          
          // Clean up listener
          window.removeEventListener('quid:auth-response', handleResponse);
          window.removeEventListener('quid:auth-error', handleResponse);
        };
        
        window.addEventListener('quid:auth-response', handleResponse);
        window.addEventListener('quid:auth-error', handleResponse);
        
      } catch (error) {
        console.error('❌ QuID login failed:', error);
      }
    }
    
    completeLogin(form, credential) {
      // Auto-fill form or submit with QuID credential
      console.log('✅ Completing login with QuID credential');
      
      // Create hidden field with QuID credential
      const credentialField = document.createElement('input');
      credentialField.type = 'hidden';
      credentialField.name = 'quid_credential';
      credentialField.value = JSON.stringify(credential);
      form.appendChild(credentialField);
      
      // Try to submit the form
      if (form.requestSubmit) {
        form.requestSubmit();
      } else {
        form.submit();
      }
    }
    
    showError(button, error) {
      const originalText = button.textContent;
      button.textContent = `❌ ${error}`;
      button.style.background = '#ff4444';
      
      setTimeout(() => {
        button.textContent = originalText;
        button.style.background = 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)';
      }, 3000);
    }
    
    generateChallenge() {
      // Generate random challenge for authentication
      const array = new Uint8Array(32);
      crypto.getRandomValues(array);
      return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }
    
    replaceWebAuthnWithQuID(requestDetails) {
      // Replace native WebAuthn calls with QuID authentication
      console.log('🔄 Replacing WebAuthn with QuID:', requestDetails);
      
      // This would typically involve monkey-patching navigator.credentials
      // For demonstration, we'll show how this would work
      window.dispatchEvent(new CustomEvent('quid:webauthn-replaced', {
        detail: requestDetails
      }));
    }
    
    notifyPageOfAuthResult(result) {
      // Notify page scripts of authentication result
      window.dispatchEvent(new CustomEvent('quid:auth-completed', {
        detail: result
      }));
    }
  }
  
  // Initialize content script
  const quidContent = new QuIDContentScript();
  
})();