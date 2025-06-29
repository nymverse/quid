/**
 * QuID Browser Extension Security Policy Enforcement
 * Implements security policies for authentication and access control
 */

class SecurityPolicy {
  constructor() {
    this.policies = {
      // Origin-based policies
      allowedOrigins: new Set(),
      blockedOrigins: new Set(),
      
      // Security requirements
      requireHttps: true,
      allowLocalhost: false,
      allowTestOrigins: false,
      
      // Authentication policies
      maxRequestsPerMinute: 10,
      requestTimeout: 60000,
      requireUserVerification: 'preferred',
      
      // Privacy policies
      clearDataOnExit: false,
      logSecurityEvents: true,
      
      // Development settings
      debugLogging: false
    };
    
    this.requestHistory = new Map(); // origin -> [timestamps]
    this.securityLog = [];
    
    this.loadPolicies();
  }
  
  async loadPolicies() {
    try {
      const stored = await chrome.storage.local.get('securityPolicies');
      if (stored.securityPolicies) {
        Object.assign(this.policies, stored.securityPolicies);
      }
    } catch (error) {
      console.error('Failed to load security policies:', error);
    }
  }
  
  async savePolicies() {
    try {
      await chrome.storage.local.set({
        securityPolicies: this.policies
      });
    } catch (error) {
      console.error('Failed to save security policies:', error);
    }
  }
  
  /**
   * Validate an authentication request against security policies
   * @param {Object} request - The authentication request
   * @returns {Object} - Validation result
   */
  validateAuthRequest(request) {
    const origin = request.origin;
    const timestamp = Date.now();
    
    // Check origin validity
    const originCheck = this.validateOrigin(origin);
    if (!originCheck.allowed) {
      this.logSecurityEvent('ORIGIN_BLOCKED', {
        origin,
        reason: originCheck.reason
      });
      return {
        allowed: false,
        reason: `Origin blocked: ${originCheck.reason}`
      };
    }
    
    // Check rate limiting
    const rateLimitCheck = this.checkRateLimit(origin, timestamp);
    if (!rateLimitCheck.allowed) {
      this.logSecurityEvent('RATE_LIMIT_EXCEEDED', {
        origin,
        requestCount: rateLimitCheck.count
      });
      return {
        allowed: false,
        reason: 'Rate limit exceeded'
      };
    }
    
    // Validate request parameters
    const paramCheck = this.validateRequestParameters(request);
    if (!paramCheck.valid) {
      this.logSecurityEvent('INVALID_REQUEST', {
        origin,
        errors: paramCheck.errors
      });
      return {
        allowed: false,
        reason: `Invalid request: ${paramCheck.errors.join(', ')}`
      };
    }
    
    this.logSecurityEvent('AUTH_REQUEST_VALIDATED', { origin });
    
    return {
      allowed: true,
      sanitizedRequest: this.sanitizeRequest(request)
    };
  }
  
  validateOrigin(origin) {
    if (!origin) {
      return { allowed: false, reason: 'No origin provided' };
    }
    
    // Check blocked list
    if (this.policies.blockedOrigins.has(origin)) {
      return { allowed: false, reason: 'Origin explicitly blocked' };
    }
    
    try {
      const url = new URL(origin);
      
      // Check protocol security
      if (this.policies.requireHttps && url.protocol !== 'https:') {
        // Allow localhost for development if configured
        const isLocalhost = url.hostname === 'localhost' || 
                           url.hostname === '127.0.0.1' || 
                           url.hostname.endsWith('.localhost');
        
        if (!isLocalhost || !this.policies.allowLocalhost) {
          return { allowed: false, reason: 'HTTPS required' };
        }
      }
      
      // Check test origins
      if (this.isTestOrigin(url) && !this.policies.allowTestOrigins) {
        return { allowed: false, reason: 'Test origins not allowed' };
      }
      
      // Check allowed list (if not empty, only allow listed origins)
      if (this.policies.allowedOrigins.size > 0 && 
          !this.policies.allowedOrigins.has(origin)) {
        return { allowed: false, reason: 'Origin not in allowed list' };
      }
      
      return { allowed: true };
      
    } catch (error) {
      return { allowed: false, reason: 'Invalid origin format' };
    }
  }
  
  isTestOrigin(url) {
    const testPatterns = [
      /^localhost$/,
      /^127\.0\.0\.1$/,
      /\.test$/,
      /\.localhost$/,
      /^192\.168\./,
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[01])\./
    ];
    
    return testPatterns.some(pattern => pattern.test(url.hostname));
  }
  
  checkRateLimit(origin, timestamp) {
    if (!this.requestHistory.has(origin)) {
      this.requestHistory.set(origin, []);
    }
    
    const requests = this.requestHistory.get(origin);
    const oneMinuteAgo = timestamp - 60000;
    
    // Remove old requests
    const recentRequests = requests.filter(time => time > oneMinuteAgo);
    this.requestHistory.set(origin, recentRequests);
    
    // Check limit
    if (recentRequests.length >= this.policies.maxRequestsPerMinute) {
      return { 
        allowed: false, 
        count: recentRequests.length 
      };
    }
    
    // Add current request
    recentRequests.push(timestamp);
    
    return { allowed: true };
  }
  
  validateRequestParameters(request) {
    const errors = [];
    
    // Validate challenge
    if (!request.challenge) {
      errors.push('Challenge is required');
    } else if (typeof request.challenge !== 'string') {
      errors.push('Challenge must be a string');
    } else if (request.challenge.length < 16) {
      errors.push('Challenge is too short');
    }
    
    // Validate timeout
    if (request.timeout !== undefined) {
      if (typeof request.timeout !== 'number') {
        errors.push('Timeout must be a number');
      } else if (request.timeout < 1000 || request.timeout > 300000) {
        errors.push('Timeout must be between 1-300 seconds');
      }
    }
    
    // Validate user verification
    if (request.userVerification !== undefined) {
      const validValues = ['required', 'preferred', 'discouraged'];
      if (!validValues.includes(request.userVerification)) {
        errors.push('Invalid userVerification value');
      }
    }
    
    return {
      valid: errors.length === 0,
      errors
    };
  }
  
  sanitizeRequest(request) {
    return {
      origin: request.origin,
      challenge: this.sanitizeString(request.challenge),
      userVerification: request.userVerification || this.policies.requireUserVerification,
      timeout: Math.min(request.timeout || this.policies.requestTimeout, 300000),
      allowCredentials: Array.isArray(request.allowCredentials) ? 
        request.allowCredentials.slice(0, 10) : [], // Limit array size
      timestamp: Date.now()
    };
  }
  
  sanitizeString(str) {
    if (typeof str !== 'string') return '';
    
    // Remove potentially dangerous characters
    return str.replace(/[<>'"&]/g, '').trim();
  }
  
  /**
   * Check if user verification is required for this request
   * @param {Object} request - The authentication request
   * @returns {string} - Required verification level
   */
  getRequiredUserVerification(request) {
    const origin = request.origin;
    
    // High-security domains always require verification
    const highSecurityDomains = [
      'bank',
      'financial',
      'government',
      'medical',
      'healthcare'
    ];
    
    if (highSecurityDomains.some(domain => origin.includes(domain))) {
      return 'required';
    }
    
    return request.userVerification || this.policies.requireUserVerification;
  }
  
  /**
   * Validate WebAuthn interception
   * @param {Object} webauthnRequest - WebAuthn request details
   * @returns {Object} - Validation result
   */
  validateWebAuthnInterception(webauthnRequest) {
    const origin = webauthnRequest.origin;
    
    // Check if WebAuthn interception is allowed for this origin
    if (!this.validateOrigin(origin).allowed) {
      return {
        allowed: false,
        reason: 'Origin not allowed for WebAuthn interception'
      };
    }
    
    // Check if the WebAuthn request looks legitimate
    if (!webauthnRequest.challenge || !webauthnRequest.rpId) {
      return {
        allowed: false,
        reason: 'Invalid WebAuthn request structure'
      };
    }
    
    this.logSecurityEvent('WEBAUTHN_INTERCEPTED', { origin });
    
    return { allowed: true };
  }
  
  /**
   * Check content script injection policy
   * @param {string} url - The URL to inject into
   * @returns {boolean} - Whether injection is allowed
   */
  shouldInjectContentScript(url) {
    try {
      const urlObj = new URL(url);
      
      // Never inject into special pages
      if (urlObj.protocol === 'chrome:' || 
          urlObj.protocol === 'chrome-extension:' ||
          urlObj.protocol === 'moz-extension:' ||
          urlObj.protocol === 'about:') {
        return false;
      }
      
      // Check origin validation
      return this.validateOrigin(urlObj.origin).allowed;
      
    } catch (error) {
      return false;
    }
  }
  
  /**
   * Validate native host communication
   * @param {Object} message - Message to/from native host
   * @returns {boolean} - Whether communication is allowed
   */
  validateNativeHostMessage(message) {
    if (!message || typeof message !== 'object') {
      return false;
    }
    
    // Check message structure
    if (!message.type || typeof message.type !== 'string') {
      return false;
    }
    
    // Validate allowed message types
    const allowedTypes = [
      'ping',
      'pong',
      'authenticate',
      'list_identities',
      'create_identity',
      'sign_challenge',
      'get_version'
    ];
    
    if (!allowedTypes.includes(message.type)) {
      this.logSecurityEvent('INVALID_NATIVE_MESSAGE', {
        type: message.type
      });
      return false;
    }
    
    return true;
  }
  
  logSecurityEvent(event, details = {}) {
    if (!this.policies.logSecurityEvents) {
      return;
    }
    
    const logEntry = {
      timestamp: Date.now(),
      event,
      details,
      level: this.getEventLevel(event)
    };
    
    this.securityLog.push(logEntry);
    
    // Keep only last 1000 entries
    if (this.securityLog.length > 1000) {
      this.securityLog = this.securityLog.slice(-1000);
    }
    
    // Log to console in debug mode
    if (this.policies.debugLogging) {
      console.log(`[QuID Security] ${event}:`, details);
    }
    
    // Store log persistently
    this.persistSecurityLog();
  }
  
  getEventLevel(event) {
    const warningEvents = [
      'RATE_LIMIT_EXCEEDED',
      'INVALID_REQUEST',
      'WEBAUTHN_INTERCEPT_FAILED'
    ];
    
    const errorEvents = [
      'ORIGIN_BLOCKED',
      'INVALID_NATIVE_MESSAGE',
      'SECURITY_VIOLATION'
    ];
    
    if (errorEvents.includes(event)) return 'ERROR';
    if (warningEvents.includes(event)) return 'WARNING';
    return 'INFO';
  }
  
  async persistSecurityLog() {
    try {
      // Only store recent events to avoid storage bloat
      const recentEvents = this.securityLog.slice(-100);
      await chrome.storage.local.set({
        securityLog: recentEvents
      });
    } catch (error) {
      console.error('Failed to persist security log:', error);
    }
  }
  
  /**
   * Get security log entries
   * @param {Object} filters - Optional filters
   * @returns {Array} - Filtered log entries
   */
  getSecurityLog(filters = {}) {
    let logs = [...this.securityLog];
    
    if (filters.level) {
      logs = logs.filter(entry => entry.level === filters.level);
    }
    
    if (filters.event) {
      logs = logs.filter(entry => entry.event === filters.event);
    }
    
    if (filters.since) {
      logs = logs.filter(entry => entry.timestamp >= filters.since);
    }
    
    return logs.sort((a, b) => b.timestamp - a.timestamp);
  }
  
  /**
   * Clear security log
   */
  clearSecurityLog() {
    this.securityLog = [];
    this.persistSecurityLog();
  }
  
  /**
   * Update security policies
   * @param {Object} newPolicies - Updated policy values
   */
  async updatePolicies(newPolicies) {
    Object.assign(this.policies, newPolicies);
    await this.savePolicies();
    
    this.logSecurityEvent('POLICIES_UPDATED', {
      changes: Object.keys(newPolicies)
    });
  }
  
  /**
   * Get current security policies
   * @returns {Object} - Current policies
   */
  getPolicies() {
    return { ...this.policies };
  }
  
  /**
   * Cleanup expired data
   */
  cleanup() {
    const now = Date.now();
    const oneHourAgo = now - 3600000;
    
    // Clean request history
    for (const [origin, requests] of this.requestHistory.entries()) {
      const recentRequests = requests.filter(time => time > oneHourAgo);
      if (recentRequests.length === 0) {
        this.requestHistory.delete(origin);
      } else {
        this.requestHistory.set(origin, recentRequests);
      }
    }
    
    // Clean old security logs
    this.securityLog = this.securityLog.filter(entry => 
      entry.timestamp > oneHourAgo);
  }
}

// Export for use in background script
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SecurityPolicy;
} else {
  window.SecurityPolicy = SecurityPolicy;
}