/*!
 * QuID JavaScript SDK v1.0.0
 * https://docs.quid.dev/sdk/javascript
 * 
 * Copyright 2025 QuID Team
 * Licensed under MIT
 */
'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var jose = require('jose');
var jsxRuntime = require('react/jsx-runtime');
var react = require('react');

function _interopNamespaceDefault(e) {
    var n = Object.create(null);
    if (e) {
        Object.keys(e).forEach(function (k) {
            if (k !== 'default') {
                var d = Object.getOwnPropertyDescriptor(e, k);
                Object.defineProperty(n, k, d.get ? d : {
                    enumerable: true,
                    get: function () { return e[k]; }
                });
            }
        });
    }
    n.default = e;
    return Object.freeze(n);
}

var jose__namespace = /*#__PURE__*/_interopNamespaceDefault(jose);

/**
 * Extension Connector
 * Handles communication with the QuID browser extension
 */
class ExtensionConnector {
    constructor(config, logger) {
        this.isConnected = false;
        this.config = config;
        this.logger = logger;
    }
    /**
     * Attempt to connect to the QuID browser extension
     */
    async connect() {
        var _a;
        try {
            // Check if we're in a browser environment
            if (typeof window === 'undefined' || !((_a = window.chrome) === null || _a === void 0 ? void 0 : _a.runtime)) {
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
        }
        catch (error) {
            this.logger.debug('Failed to connect to extension:', error);
            return false;
        }
    }
    /**
     * Disconnect from the extension
     */
    disconnect() {
        this.isConnected = false;
        this.extensionId = undefined;
    }
    /**
     * Get identities from the extension
     */
    async getIdentities() {
        if (!this.isConnected) {
            throw new Error('Extension not connected');
        }
        try {
            const response = await this.sendMessage({ type: 'GET_IDENTITIES' });
            if (response.success && response.identities) {
                return response.identities.map(this.mapIdentity);
            }
            else {
                throw new Error(response.error || 'Failed to get identities');
            }
        }
        catch (error) {
            this.logger.error('Failed to get identities from extension:', error);
            throw error;
        }
    }
    /**
     * Create a new identity via the extension
     */
    async createIdentity(request) {
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
            }
            else {
                throw new Error(response.error || 'Failed to create identity');
            }
        }
        catch (error) {
            this.logger.error('Failed to create identity via extension:', error);
            throw error;
        }
    }
    /**
     * Authenticate via the extension
     */
    async authenticate(request) {
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
        }
        catch (error) {
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
    async signChallenge(identityId, challenge) {
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
            }
            else {
                throw new Error(response.error || 'Failed to sign challenge');
            }
        }
        catch (error) {
            this.logger.error('Failed to sign challenge via extension:', error);
            throw error;
        }
    }
    /**
     * Detect if QuID extension is installed
     */
    async detectExtension() {
        try {
            // Method 1: Check for QuID API in page
            if (window.QuID && window.QuID.isAvailable) {
                this.logger.debug('QuID API detected in page');
                return true;
            }
            // Method 2: Check for extension via custom event
            return new Promise((resolve) => {
                const timeout = setTimeout(() => resolve(false), 1000);
                const handler = (event) => {
                    if (event.detail && event.detail.available) {
                        clearTimeout(timeout);
                        window.removeEventListener('quid:ready', handler);
                        resolve(true);
                    }
                };
                window.addEventListener('quid:ready', handler);
                // Try to trigger extension detection
                window.dispatchEvent(new CustomEvent('quid:detect'));
            });
        }
        catch (error) {
            this.logger.debug('Extension detection failed:', error);
            return false;
        }
    }
    /**
     * Send message to extension
     */
    async sendMessage(message) {
        return new Promise((resolve, reject) => {
            var _a;
            const timeout = setTimeout(() => {
                reject(new Error('Extension message timeout'));
            }, this.config.timeout || 60000);
            try {
                // Method 1: Direct extension communication (if extension ID is known)
                if (this.extensionId && ((_a = window.chrome) === null || _a === void 0 ? void 0 : _a.runtime)) {
                    window.chrome.runtime.sendMessage(this.extensionId, message, (response) => {
                        clearTimeout(timeout);
                        if (window.chrome.runtime.lastError) {
                            reject(new Error(window.chrome.runtime.lastError.message));
                        }
                        else {
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
            }
            catch (error) {
                clearTimeout(timeout);
                reject(error);
            }
        });
    }
    /**
     * Handle message via QuID API
     */
    handleQuIDAPIMessage(message, resolve, reject, timeout) {
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
        }
        catch (error) {
            clearTimeout(timeout);
            reject(error);
        }
    }
    /**
     * Handle message via custom events
     */
    handleCustomEventMessage(message, resolve, reject, timeout) {
        const requestId = `quid-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        const handler = (event) => {
            if (event.detail && event.detail.requestId === requestId) {
                clearTimeout(timeout);
                window.removeEventListener('quid:response', handler);
                resolve(event.detail.response);
            }
        };
        window.addEventListener('quid:response', handler);
        window.dispatchEvent(new CustomEvent('quid:request', {
            detail: { ...message, requestId }
        }));
    }
    /**
     * Map extension identity to SDK identity
     */
    mapIdentity(extIdentity) {
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

/**
 * WebAuthn Bridge
 * Provides fallback WebAuthn functionality when QuID extension is not available
 */
class WebAuthnBridge {
    constructor(client, logger) {
        this.client = client;
        this.logger = logger;
    }
    /**
     * Initialize WebAuthn bridge
     */
    init() {
        if (!this.isWebAuthnSupported()) {
            this.logger.warn('WebAuthn is not supported in this browser');
            return;
        }
        this.logger.debug('WebAuthn bridge initialized');
    }
    /**
     * Check if WebAuthn is supported
     */
    isWebAuthnSupported() {
        return !!(navigator.credentials && navigator.credentials.create && navigator.credentials.get);
    }
    /**
     * Authenticate using WebAuthn as fallback
     */
    async authenticate(request) {
        if (!this.isWebAuthnSupported()) {
            return {
                success: false,
                error: 'WebAuthn is not supported in this browser'
            };
        }
        try {
            this.logger.debug('Starting WebAuthn fallback authentication');
            const options = {
                publicKey: {
                    challenge: this.stringToArrayBuffer(request.challenge),
                    timeout: request.timeout,
                    rpId: request.rpId || this.extractDomain(request.origin),
                    allowCredentials: request.allowCredentials || [],
                    userVerification: request.userVerification || 'preferred'
                }
            };
            const credential = await navigator.credentials.get(options);
            if (!credential) {
                return {
                    success: false,
                    error: 'No credential returned from WebAuthn'
                };
            }
            const response = credential.response;
            const quidCredential = {
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
        }
        catch (error) {
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
    async createCredential(options) {
        if (!this.isWebAuthnSupported()) {
            return {
                success: false,
                error: 'WebAuthn is not supported in this browser'
            };
        }
        try {
            this.logger.debug('Creating WebAuthn credential');
            const createOptions = {
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
            const credential = await navigator.credentials.create(createOptions);
            if (!credential) {
                return {
                    success: false,
                    error: 'No credential created'
                };
            }
            const response = credential.response;
            const quidCredential = {
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
        }
        catch (error) {
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
    async isCredentialAvailable() {
        if (!this.isWebAuthnSupported()) {
            return false;
        }
        try {
            // Try a simple get call with no allowCredentials to see if platform authenticator is available
            const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
            return available;
        }
        catch (error) {
            this.logger.debug('Could not check credential availability:', error);
            return false;
        }
    }
    /**
     * Cleanup WebAuthn bridge
     */
    cleanup() {
        // Nothing to cleanup for WebAuthn
        this.logger.debug('WebAuthn bridge cleaned up');
    }
    /**
     * Convert string to ArrayBuffer
     */
    stringToArrayBuffer(str) {
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
    arrayBufferToString(buffer) {
        const bytes = new Uint8Array(buffer);
        return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
    }
    /**
     * Extract domain from origin
     */
    extractDomain(origin) {
        try {
            const url = new URL(origin);
            return url.hostname;
        }
        catch (error) {
            this.logger.warn('Could not extract domain from origin:', origin);
            return 'localhost';
        }
    }
    /**
     * Get user-friendly error message from WebAuthn error
     */
    getWebAuthnErrorMessage(error) {
        if (!error)
            return 'Unknown WebAuthn error';
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

/**
 * Event Emitter
 * Simple type-safe event emitter for QuID SDK
 */
class EventEmitter {
    constructor() {
        this.listeners = [];
    }
    /**
     * Add an event listener
     */
    on(listener) {
        this.listeners.push(listener);
        // Return unsubscribe function
        return () => {
            const index = this.listeners.indexOf(listener);
            if (index > -1) {
                this.listeners.splice(index, 1);
            }
        };
    }
    /**
     * Add a one-time event listener
     */
    once(listener) {
        const onceListener = (event) => {
            listener(event);
            unsubscribe();
        };
        const unsubscribe = this.on(onceListener);
        return unsubscribe;
    }
    /**
     * Emit an event to all listeners
     */
    emit(event) {
        // Create a copy of listeners to avoid issues if listeners are modified during iteration
        const currentListeners = [...this.listeners];
        for (const listener of currentListeners) {
            try {
                listener(event);
            }
            catch (error) {
                console.error('Error in event listener:', error);
            }
        }
    }
    /**
     * Remove all listeners
     */
    removeAllListeners() {
        this.listeners = [];
    }
    /**
     * Get the number of listeners
     */
    get listenerCount() {
        return this.listeners.length;
    }
}

/**
 * Logger
 * Simple logging utility for QuID SDK
 */
class Logger {
    constructor(debug = false) {
        this.prefix = '[QuID SDK]';
        this.debug = debug;
    }
    /**
     * Set debug mode
     */
    setDebug(debug) {
        this.debug = debug;
    }
    /**
     * Log debug message (only in debug mode)
     */
    debug(message, ...args) {
        if (this.debug) {
            console.debug(this.prefix, message, ...args);
        }
    }
    /**
     * Log info message
     */
    info(message, ...args) {
        if (this.debug) {
            console.info(this.prefix, message, ...args);
        }
    }
    /**
     * Log warning message
     */
    warn(message, ...args) {
        console.warn(this.prefix, message, ...args);
    }
    /**
     * Log error message
     */
    error(message, ...args) {
        console.error(this.prefix, message, ...args);
    }
}

/**
 * QuID Client
 * Core client for QuID authentication operations
 */
let QuIDClient$2 = class QuIDClient extends EventEmitter {
    constructor(config = {}) {
        super();
        this.isReady = false;
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
    async init() {
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
            }
            else {
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
        }
        catch (error) {
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
    get ready() {
        return this.isReady;
    }
    /**
     * Check if browser extension is available
     */
    get extensionAvailable() {
        return this.extensionConnector.isConnected;
    }
    /**
     * Get available QuID identities
     */
    async getIdentities() {
        if (!this.isReady) {
            throw this.createError('SDK_NOT_READY', 'QuID SDK is not ready');
        }
        try {
            if (this.extensionConnector.isConnected) {
                return await this.extensionConnector.getIdentities();
            }
            else {
                this.logger.warn('No extension available, returning empty identity list');
                return [];
            }
        }
        catch (error) {
            this.logger.error('Failed to get identities:', error);
            throw this.createError('GET_IDENTITIES_FAILED', 'Failed to retrieve identities', error);
        }
    }
    /**
     * Create a new QuID identity
     */
    async createIdentity(request) {
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
        }
        catch (error) {
            this.logger.error('Failed to create identity:', error);
            throw this.createError('CREATE_IDENTITY_FAILED', 'Failed to create identity', error);
        }
    }
    /**
     * Authenticate using QuID
     */
    async authenticate(request = {}) {
        if (!this.isReady) {
            throw this.createError('SDK_NOT_READY', 'QuID SDK is not ready');
        }
        const authRequest = {
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
            let response;
            if (this.extensionConnector.isConnected) {
                // Use QuID extension
                response = await this.extensionConnector.authenticate(authRequest);
            }
            else if (this.config.enableWebAuthnFallback && navigator.credentials) {
                // Fallback to WebAuthn
                this.logger.info('Using WebAuthn fallback');
                response = await this.webauthnBridge.authenticate(authRequest);
            }
            else {
                throw this.createError('NO_AUTH_METHOD', 'No authentication method available');
            }
            if (response.success) {
                this.emit({
                    type: 'authentication-completed',
                    data: response,
                    timestamp: new Date()
                });
                this.logger.info('Authentication successful');
            }
            else {
                this.emit({
                    type: 'authentication-failed',
                    data: response,
                    timestamp: new Date()
                });
                this.logger.warn('Authentication failed:', response.error);
            }
            return response;
        }
        catch (error) {
            this.logger.error('Authentication error:', error);
            const errorResponse = {
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
    async signChallenge(identityId, challenge) {
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
        }
        catch (error) {
            this.logger.error('Failed to sign challenge:', error);
            throw this.createError('SIGN_CHALLENGE_FAILED', 'Failed to sign challenge', error);
        }
    }
    /**
     * Check connection status
     */
    async getStatus() {
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
    updateConfig(newConfig) {
        Object.assign(this.config, newConfig);
        this.logger.setDebug(this.config.debug);
        this.logger.debug('Configuration updated:', newConfig);
    }
    /**
     * Disconnect and cleanup
     */
    disconnect() {
        this.logger.debug('Disconnecting QuID client');
        this.extensionConnector.disconnect();
        this.webauthnBridge.cleanup();
        this.isReady = false;
        this.emit({
            type: 'extension-disconnected',
            timestamp: new Date()
        });
    }
    generateChallenge() {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }
    createError(code, message, cause) {
        const error = new Error(message);
        error.name = 'QuIDSDKError';
        error.code = code;
        error.details = cause;
        return error;
    }
};

/**
 * OAuth/OIDC Client
 * Provides OAuth and OpenID Connect integration for QuID
 */
class QuIDOAuthClient {
    constructor(config, quidClient) {
        this.quidClient = quidClient || new QuIDClient$2();
        this.logger = new Logger(false);
        // Set default provider configuration
        const defaultProvider = {
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
    generateAuthUrl(options = {}) {
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
    async handleCallback(callbackUrl) {
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
    async exchangeCodeForTokens(code, state) {
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
        }
        catch (error) {
            this.logger.error('Token exchange failed:', error);
            throw error;
        }
    }
    /**
     * Refresh access token using QuID authentication
     */
    async refreshToken(refreshToken) {
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
        }
        catch (error) {
            this.logger.error('Token refresh failed:', error);
            throw error;
        }
    }
    /**
     * Get user information using access token
     */
    async getUserInfo(accessToken) {
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
        }
        catch (error) {
            this.logger.error('Failed to get user info:', error);
            throw error;
        }
    }
    /**
     * Verify and decode ID token
     */
    async verifyIdToken(idToken) {
        if (!this.config.provider.jwksEndpoint) {
            this.logger.warn('JWKS endpoint not configured, skipping token verification');
            return jose__namespace.decodeJwt(idToken);
        }
        try {
            // Fetch JWKS
            const jwks = await jose__namespace.createRemoteJWKSet(new URL(this.config.provider.jwksEndpoint));
            // Verify and decode the token
            const { payload } = await jose__namespace.jwtVerify(idToken, jwks, {
                issuer: this.extractIssuerFromEndpoint(),
                audience: this.config.clientId
            });
            return payload;
        }
        catch (error) {
            this.logger.error('ID token verification failed:', error);
            throw new Error('Invalid ID token');
        }
    }
    /**
     * Logout from OAuth provider
     */
    generateLogoutUrl(options = {}) {
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
    generatePKCEChallenge() {
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
        }); // Simplified for demo
    }
    /**
     * Start OAuth flow with PKCE and QuID integration
     */
    async startSecureFlow(options = {}) {
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
    generateChallenge() {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }
    base64URLEncode(buffer) {
        const base64 = btoa(String.fromCharCode(...buffer));
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }
    extractIssuerFromEndpoint() {
        try {
            const url = new URL(this.config.provider.authorizationEndpoint);
            return `${url.protocol}//${url.host}`;
        }
        catch (_a) {
            return 'unknown';
        }
    }
    /**
     * Update configuration
     */
    updateConfig(newConfig) {
        Object.assign(this.config, newConfig);
    }
    /**
     * Get current configuration
     */
    getConfig() {
        return { ...this.config };
    }
}

/**
 * Sign in with QuID Button
 * Vanilla JavaScript component for QuID authentication
 */
let QuIDSigninButton$1 = class QuIDSigninButton {
    constructor(container, options = {}) {
        this.isLoading = false;
        // Get container element
        if (typeof container === 'string') {
            const element = document.querySelector(container);
            if (!element) {
                throw new Error(`Container element not found: ${container}`);
            }
            this.container = element;
        }
        else {
            this.container = container;
        }
        // Set default options
        this.options = {
            challenge: options.challenge || '',
            userVerification: options.userVerification || 'preferred',
            timeout: options.timeout || 60000,
            onSuccess: options.onSuccess || (() => { }),
            onError: options.onError || (() => { }),
            style: options.style || {},
            buttonText: options.buttonText || 'Sign in with QuID',
            showBranding: options.showBranding !== false
        };
        // Initialize QuID client
        this.client = new QuIDClient$2();
        // Create the button
        this.createButton();
        this.setupEventListeners();
    }
    /**
     * Create the signin button element
     */
    createButton() {
        this.button = document.createElement('button');
        this.button.type = 'button';
        this.button.className = 'quid-signin-button';
        // Apply styles
        this.applyStyles();
        // Set content
        this.updateButtonContent();
        // Add to container
        this.container.appendChild(this.button);
    }
    /**
     * Apply styles to the button
     */
    applyStyles() {
        const defaultStyle = {
            width: '100%',
            height: '44px',
            backgroundColor: '#667eea',
            color: '#ffffff',
            borderRadius: '6px',
            fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
            fontSize: '16px',
            padding: '0 16px',
            margin: '8px 0'
        };
        const style = { ...defaultStyle, ...this.options.style };
        // Apply styles
        Object.assign(this.button.style, {
            width: style.width,
            height: style.height,
            backgroundColor: style.backgroundColor,
            color: style.color,
            borderRadius: style.borderRadius,
            fontFamily: style.fontFamily,
            fontSize: style.fontSize,
            padding: style.padding,
            margin: style.margin,
            border: 'none',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '8px',
            transition: 'all 0.2s ease',
            textDecoration: 'none',
            fontWeight: '500',
            lineHeight: '1',
            outline: 'none',
            position: 'relative',
            overflow: 'hidden'
        });
        // Add custom class if provided
        if (style.className) {
            this.button.className += ` ${style.className}`;
        }
        // Add hover effects
        this.button.addEventListener('mouseenter', () => {
            if (!this.isLoading) {
                this.button.style.transform = 'translateY(-1px)';
                this.button.style.boxShadow = '0 4px 12px rgba(102, 126, 234, 0.3)';
            }
        });
        this.button.addEventListener('mouseleave', () => {
            if (!this.isLoading) {
                this.button.style.transform = 'translateY(0)';
                this.button.style.boxShadow = 'none';
            }
        });
    }
    /**
     * Update button content
     */
    updateButtonContent() {
        if (this.isLoading) {
            this.button.innerHTML = `
        <div class="quid-spinner" style="
          width: 16px;
          height: 16px;
          border: 2px solid transparent;
          border-top: 2px solid currentColor;
          border-radius: 50%;
          animation: quid-spin 1s linear infinite;
        "></div>
        <span>Authenticating...</span>
      `;
        }
        else {
            const icon = this.options.showBranding ?
                '<span style="font-size: 18px;">🔐</span>' : '';
            this.button.innerHTML = `
        ${icon}
        <span>${this.options.buttonText}</span>
      `;
        }
        // Add spinner animation CSS if not already added
        if (!document.querySelector('#quid-spinner-styles')) {
            const style = document.createElement('style');
            style.id = 'quid-spinner-styles';
            style.textContent = `
        @keyframes quid-spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      `;
            document.head.appendChild(style);
        }
    }
    /**
     * Set up event listeners
     */
    setupEventListeners() {
        this.button.addEventListener('click', this.handleClick.bind(this));
        // Listen for QuID client events
        this.client.on((event) => {
            if (event.type === 'ready' && !this.client.extensionAvailable) {
                this.showWarning();
            }
        });
    }
    /**
     * Handle button click
     */
    async handleClick() {
        if (this.isLoading) {
            return;
        }
        try {
            this.setLoading(true);
            // Generate challenge if not provided
            const challenge = this.options.challenge || this.generateChallenge();
            // Authenticate
            const response = await this.client.authenticate({
                challenge,
                userVerification: this.options.userVerification,
                timeout: this.options.timeout,
                origin: window.location.origin
            });
            if (response.success) {
                this.options.onSuccess(response);
            }
            else {
                this.options.onError(new Error(response.error || 'Authentication failed'));
            }
        }
        catch (error) {
            this.options.onError(error instanceof Error ? error : new Error('Authentication failed'));
        }
        finally {
            this.setLoading(false);
        }
    }
    /**
     * Set loading state
     */
    setLoading(loading) {
        this.isLoading = loading;
        this.button.disabled = loading;
        this.updateButtonContent();
        if (loading) {
            this.button.style.transform = 'translateY(0)';
            this.button.style.boxShadow = 'none';
            this.button.style.cursor = 'wait';
        }
        else {
            this.button.style.cursor = 'pointer';
        }
    }
    /**
     * Show warning when extension is not available
     */
    showWarning() {
        var _a;
        const warningElement = document.createElement('div');
        warningElement.className = 'quid-warning';
        warningElement.style.cssText = `
      background: #fff3cd;
      border: 1px solid #ffeaa7;
      color: #856404;
      padding: 8px 12px;
      border-radius: 4px;
      font-size: 12px;
      margin-top: 4px;
      font-family: ${((_a = this.options.style) === null || _a === void 0 ? void 0 : _a.fontFamily) || 'inherit'};
    `;
        warningElement.innerHTML = `
      ⚠️ QuID browser extension not detected. 
      <a href="https://quid.dev/download" target="_blank" style="color: inherit; text-decoration: underline;">
        Install extension
      </a> for full functionality.
    `;
        this.container.appendChild(warningElement);
        // Auto-hide after 10 seconds
        setTimeout(() => {
            if (warningElement.parentElement) {
                warningElement.parentElement.removeChild(warningElement);
            }
        }, 10000);
    }
    /**
     * Generate random challenge
     */
    generateChallenge() {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }
    /**
     * Update options
     */
    updateOptions(newOptions) {
        Object.assign(this.options, newOptions);
        this.applyStyles();
        this.updateButtonContent();
    }
    /**
     * Destroy the component
     */
    destroy() {
        if (this.button && this.button.parentElement) {
            this.button.parentElement.removeChild(this.button);
        }
        this.client.disconnect();
    }
    /**
     * Get the underlying QuID client
     */
    getClient() {
        return this.client;
    }
};
/**
 * Factory function to create signin button
 */
function createSigninButton(container, options) {
    return new QuIDSigninButton$1(container, options);
}

/**
 * QuID Signin Button React Component
 */
const QuIDSigninButton = ({ challenge, userVerification = 'preferred', timeout = 60000, onSuccess, onError, style = {}, buttonText = 'Sign in with QuID', showBranding = true, className = '', disabled = false, children, ...props }) => {
    const clientRef = react.useRef(null);
    const [isLoading, setIsLoading] = react.useState(false);
    const [isReady, setIsReady] = react.useState(false);
    const [extensionAvailable, setExtensionAvailable] = react.useState(false);
    const [showWarning, setShowWarning] = react.useState(false);
    // Initialize QuID client
    react.useEffect(() => {
        clientRef.current = new QuIDClient$2();
        const unsubscribe = clientRef.current.on((event) => {
            switch (event.type) {
                case 'ready':
                    setIsReady(true);
                    break;
                case 'extension-connected':
                    setExtensionAvailable(true);
                    break;
                case 'extension-disconnected':
                    setExtensionAvailable(false);
                    setShowWarning(true);
                    break;
            }
        });
        return () => {
            unsubscribe();
            if (clientRef.current) {
                clientRef.current.disconnect();
            }
        };
    }, []);
    // Check extension availability after ready
    react.useEffect(() => {
        if (isReady && clientRef.current) {
            const available = clientRef.current.extensionAvailable;
            setExtensionAvailable(available);
            if (!available) {
                setShowWarning(true);
                // Auto-hide warning after 10 seconds
                setTimeout(() => setShowWarning(false), 10000);
            }
        }
    }, [isReady]);
    const handleClick = react.useCallback(async () => {
        if (!clientRef.current || isLoading || disabled) {
            return;
        }
        try {
            setIsLoading(true);
            // Generate challenge if not provided
            const authChallenge = challenge || generateChallenge();
            // Authenticate
            const response = await clientRef.current.authenticate({
                challenge: authChallenge,
                userVerification,
                timeout,
                origin: window.location.origin
            });
            if (response.success) {
                onSuccess === null || onSuccess === void 0 ? void 0 : onSuccess(response);
            }
            else {
                onError === null || onError === void 0 ? void 0 : onError(new Error(response.error || 'Authentication failed'));
            }
        }
        catch (error) {
            onError === null || onError === void 0 ? void 0 : onError(error instanceof Error ? error : new Error('Authentication failed'));
        }
        finally {
            setIsLoading(false);
        }
    }, [challenge, userVerification, timeout, onSuccess, onError, isLoading, disabled]);
    const generateChallenge = () => {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    };
    const defaultStyle = {
        width: '100%',
        height: '44px',
        backgroundColor: '#667eea',
        color: '#ffffff',
        borderRadius: '6px',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
        fontSize: '16px',
        padding: '0 16px',
        margin: '8px 0',
        border: 'none',
        cursor: isLoading || disabled ? 'not-allowed' : 'pointer',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '8px',
        transition: 'all 0.2s ease',
        textDecoration: 'none',
        fontWeight: '500',
        lineHeight: '1',
        outline: 'none',
        position: 'relative',
        overflow: 'hidden',
        opacity: disabled ? 0.6 : 1,
        ...style
    };
    const buttonContent = children || (jsxRuntime.jsxs(jsxRuntime.Fragment, { children: [showBranding && jsxRuntime.jsx("span", { style: { fontSize: '18px' }, children: "\uD83D\uDD10" }), jsxRuntime.jsx("span", { children: isLoading ? 'Authenticating...' : buttonText }), isLoading && (jsxRuntime.jsx("div", { style: {
                    width: '16px',
                    height: '16px',
                    border: '2px solid transparent',
                    borderTop: '2px solid currentColor',
                    borderRadius: '50%',
                    animation: 'spin 1s linear infinite'
                } }))] }));
    return (jsxRuntime.jsxs("div", { children: [jsxRuntime.jsx("button", { type: "button", onClick: handleClick, disabled: disabled || isLoading || !isReady, className: `quid-signin-button ${className}`, style: defaultStyle, ...props, children: buttonContent }), showWarning && (jsxRuntime.jsxs("div", { style: {
                    background: '#fff3cd',
                    border: '1px solid #ffeaa7',
                    color: '#856404',
                    padding: '8px 12px',
                    borderRadius: '4px',
                    fontSize: '12px',
                    marginTop: '4px',
                    fontFamily: defaultStyle.fontFamily
                }, children: ["\u26A0\uFE0F QuID browser extension not detected.", ' ', jsxRuntime.jsx("a", { href: "https://quid.dev/download", target: "_blank", rel: "noopener noreferrer", style: { color: 'inherit', textDecoration: 'underline' }, children: "Install extension" }), ' ', "for full functionality."] })), jsxRuntime.jsx("style", { jsx: true, children: `
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      ` })] }));
};

/**
 * useQuID React Hook
 * React hook for QuID authentication
 */
/**
 * useQuID Hook
 */
function useQuID(options = {}) {
    const { autoInit = true, ...config } = options;
    const clientRef = react.useRef(null);
    const [isReady, setIsReady] = react.useState(false);
    const [extensionAvailable, setExtensionAvailable] = react.useState(false);
    const [isLoading, setIsLoading] = react.useState(false);
    const [error, setError] = react.useState(null);
    const [identities, setIdentities] = react.useState([]);
    // Initialize client
    react.useEffect(() => {
        if (!autoInit)
            return;
        const initClient = async () => {
            try {
                setIsLoading(true);
                setError(null);
                clientRef.current = new QuIDClient$2(config);
                // Set up event listeners
                const unsubscribe = clientRef.current.on((event) => {
                    var _a;
                    switch (event.type) {
                        case 'ready':
                            setIsReady(true);
                            setExtensionAvailable(((_a = clientRef.current) === null || _a === void 0 ? void 0 : _a.extensionAvailable) || false);
                            break;
                        case 'extension-connected':
                            setExtensionAvailable(true);
                            break;
                        case 'extension-disconnected':
                            setExtensionAvailable(false);
                            break;
                        case 'error':
                            setError(event.data);
                            break;
                    }
                });
                // Cleanup function
                return unsubscribe;
            }
            catch (err) {
                setError(err instanceof Error ? err : new Error('Failed to initialize QuID'));
            }
            finally {
                setIsLoading(false);
            }
        };
        const cleanup = initClient();
        return () => {
            cleanup.then(unsubscribe => unsubscribe === null || unsubscribe === void 0 ? void 0 : unsubscribe());
            if (clientRef.current) {
                clientRef.current.disconnect();
                clientRef.current = null;
            }
        };
    }, [autoInit, config]);
    // Load identities when ready
    react.useEffect(() => {
        if (isReady && extensionAvailable) {
            refreshIdentities();
        }
    }, [isReady, extensionAvailable]);
    const authenticate = react.useCallback(async (request = {}) => {
        if (!clientRef.current) {
            throw new Error('QuID client not initialized');
        }
        setIsLoading(true);
        setError(null);
        try {
            const response = await clientRef.current.authenticate(request);
            return response;
        }
        catch (err) {
            const error = err instanceof Error ? err : new Error('Authentication failed');
            setError(error);
            return {
                success: false,
                error: error.message
            };
        }
        finally {
            setIsLoading(false);
        }
    }, []);
    const createIdentity = react.useCallback(async (request) => {
        if (!clientRef.current) {
            throw new Error('QuID client not initialized');
        }
        setIsLoading(true);
        setError(null);
        try {
            const identity = await clientRef.current.createIdentity(request);
            // Refresh identities list
            await refreshIdentities();
            return identity;
        }
        catch (err) {
            const error = err instanceof Error ? err : new Error('Failed to create identity');
            setError(error);
            throw error;
        }
        finally {
            setIsLoading(false);
        }
    }, []);
    const refreshIdentities = react.useCallback(async () => {
        if (!clientRef.current || !extensionAvailable) {
            setIdentities([]);
            return;
        }
        try {
            const identityList = await clientRef.current.getIdentities();
            setIdentities(identityList);
        }
        catch (err) {
            console.warn('Failed to refresh identities:', err);
            setIdentities([]);
        }
    }, [extensionAvailable]);
    const getStatus = react.useCallback(async () => {
        if (!clientRef.current) {
            return {
                ready: false,
                extensionAvailable: false,
                identityCount: 0,
                version: '1.0.0'
            };
        }
        return await clientRef.current.getStatus();
    }, []);
    const clearError = react.useCallback(() => {
        setError(null);
    }, []);
    return {
        client: clientRef.current,
        isReady,
        extensionAvailable,
        isLoading,
        error,
        identities,
        authenticate,
        createIdentity,
        refreshIdentities,
        getStatus,
        clearError
    };
}

/**
 * QuID JavaScript SDK
 * Universal quantum-resistant authentication for web applications
 */
// Core exports
// Default export
var QuIDClient$1 = QuIDClient;

exports.EventEmitter = EventEmitter;
exports.ExtensionConnector = ExtensionConnector;
exports.Logger = Logger;
exports.QuIDClient = QuIDClient$2;
exports.QuIDOAuthClient = QuIDOAuthClient;
exports.QuIDSigninButton = QuIDSigninButton$1;
exports.QuIDSigninButtonReact = QuIDSigninButton;
exports.QuIDSigninButtonReactDefault = QuIDSigninButton;
exports.WebAuthnBridge = WebAuthnBridge;
exports.createSigninButton = createSigninButton;
exports.default = QuIDClient$1;
exports.useQuID = useQuID;
exports.useQuIDDefault = useQuID;
//# sourceMappingURL=index.js.map
