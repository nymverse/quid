/*!
 * QuID JavaScript SDK v1.0.0
 * https://docs.quid.dev/sdk/javascript
 * 
 * Copyright 2025 QuID Team
 * Licensed under MIT
 */
(function (global, factory) {
    typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports, require('react/jsx-runtime'), require('react')) :
    typeof define === 'function' && define.amd ? define(['exports', 'react/jsx-runtime', 'react'], factory) :
    (global = typeof globalThis !== 'undefined' ? globalThis : global || self, factory(global.QuIDSDK = {}, global.jsxRuntime, global.React));
})(this, (function (exports, jsxRuntime, react) { 'use strict';

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

    var crypto$1 = crypto;
    const isCryptoKey = (key) => key instanceof CryptoKey;

    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    function concat(...buffers) {
        const size = buffers.reduce((acc, { length }) => acc + length, 0);
        const buf = new Uint8Array(size);
        let i = 0;
        for (const buffer of buffers) {
            buf.set(buffer, i);
            i += buffer.length;
        }
        return buf;
    }

    const decodeBase64 = (encoded) => {
        const binary = atob(encoded);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    };
    const decode$1 = (input) => {
        let encoded = input;
        if (encoded instanceof Uint8Array) {
            encoded = decoder.decode(encoded);
        }
        encoded = encoded.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '');
        try {
            return decodeBase64(encoded);
        }
        catch {
            throw new TypeError('The input to be decoded is not correctly encoded.');
        }
    };

    class JOSEError extends Error {
        constructor(message, options) {
            super(message, options);
            this.code = 'ERR_JOSE_GENERIC';
            this.name = this.constructor.name;
            Error.captureStackTrace?.(this, this.constructor);
        }
    }
    JOSEError.code = 'ERR_JOSE_GENERIC';
    class JWTClaimValidationFailed extends JOSEError {
        constructor(message, payload, claim = 'unspecified', reason = 'unspecified') {
            super(message, { cause: { claim, reason, payload } });
            this.code = 'ERR_JWT_CLAIM_VALIDATION_FAILED';
            this.claim = claim;
            this.reason = reason;
            this.payload = payload;
        }
    }
    JWTClaimValidationFailed.code = 'ERR_JWT_CLAIM_VALIDATION_FAILED';
    class JWTExpired extends JOSEError {
        constructor(message, payload, claim = 'unspecified', reason = 'unspecified') {
            super(message, { cause: { claim, reason, payload } });
            this.code = 'ERR_JWT_EXPIRED';
            this.claim = claim;
            this.reason = reason;
            this.payload = payload;
        }
    }
    JWTExpired.code = 'ERR_JWT_EXPIRED';
    class JOSEAlgNotAllowed extends JOSEError {
        constructor() {
            super(...arguments);
            this.code = 'ERR_JOSE_ALG_NOT_ALLOWED';
        }
    }
    JOSEAlgNotAllowed.code = 'ERR_JOSE_ALG_NOT_ALLOWED';
    class JOSENotSupported extends JOSEError {
        constructor() {
            super(...arguments);
            this.code = 'ERR_JOSE_NOT_SUPPORTED';
        }
    }
    JOSENotSupported.code = 'ERR_JOSE_NOT_SUPPORTED';
    class JWEDecryptionFailed extends JOSEError {
        constructor(message = 'decryption operation failed', options) {
            super(message, options);
            this.code = 'ERR_JWE_DECRYPTION_FAILED';
        }
    }
    JWEDecryptionFailed.code = 'ERR_JWE_DECRYPTION_FAILED';
    class JWEInvalid extends JOSEError {
        constructor() {
            super(...arguments);
            this.code = 'ERR_JWE_INVALID';
        }
    }
    JWEInvalid.code = 'ERR_JWE_INVALID';
    class JWSInvalid extends JOSEError {
        constructor() {
            super(...arguments);
            this.code = 'ERR_JWS_INVALID';
        }
    }
    JWSInvalid.code = 'ERR_JWS_INVALID';
    class JWTInvalid extends JOSEError {
        constructor() {
            super(...arguments);
            this.code = 'ERR_JWT_INVALID';
        }
    }
    JWTInvalid.code = 'ERR_JWT_INVALID';
    class JWKInvalid extends JOSEError {
        constructor() {
            super(...arguments);
            this.code = 'ERR_JWK_INVALID';
        }
    }
    JWKInvalid.code = 'ERR_JWK_INVALID';
    class JWKSInvalid extends JOSEError {
        constructor() {
            super(...arguments);
            this.code = 'ERR_JWKS_INVALID';
        }
    }
    JWKSInvalid.code = 'ERR_JWKS_INVALID';
    class JWKSNoMatchingKey extends JOSEError {
        constructor(message = 'no applicable key found in the JSON Web Key Set', options) {
            super(message, options);
            this.code = 'ERR_JWKS_NO_MATCHING_KEY';
        }
    }
    JWKSNoMatchingKey.code = 'ERR_JWKS_NO_MATCHING_KEY';
    class JWKSMultipleMatchingKeys extends JOSEError {
        constructor(message = 'multiple matching keys found in the JSON Web Key Set', options) {
            super(message, options);
            this.code = 'ERR_JWKS_MULTIPLE_MATCHING_KEYS';
        }
    }
    JWKSMultipleMatchingKeys.code = 'ERR_JWKS_MULTIPLE_MATCHING_KEYS';
    class JWKSTimeout extends JOSEError {
        constructor(message = 'request timed out', options) {
            super(message, options);
            this.code = 'ERR_JWKS_TIMEOUT';
        }
    }
    JWKSTimeout.code = 'ERR_JWKS_TIMEOUT';
    class JWSSignatureVerificationFailed extends JOSEError {
        constructor(message = 'signature verification failed', options) {
            super(message, options);
            this.code = 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED';
        }
    }
    JWSSignatureVerificationFailed.code = 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED';

    function unusable(name, prop = 'algorithm.name') {
        return new TypeError(`CryptoKey does not support this operation, its ${prop} must be ${name}`);
    }
    function isAlgorithm(algorithm, name) {
        return algorithm.name === name;
    }
    function getHashLength(hash) {
        return parseInt(hash.name.slice(4), 10);
    }
    function getNamedCurve(alg) {
        switch (alg) {
            case 'ES256':
                return 'P-256';
            case 'ES384':
                return 'P-384';
            case 'ES512':
                return 'P-521';
            default:
                throw new Error('unreachable');
        }
    }
    function checkUsage(key, usages) {
        if (usages.length && !usages.some((expected) => key.usages.includes(expected))) {
            let msg = 'CryptoKey does not support this operation, its usages must include ';
            if (usages.length > 2) {
                const last = usages.pop();
                msg += `one of ${usages.join(', ')}, or ${last}.`;
            }
            else if (usages.length === 2) {
                msg += `one of ${usages[0]} or ${usages[1]}.`;
            }
            else {
                msg += `${usages[0]}.`;
            }
            throw new TypeError(msg);
        }
    }
    function checkSigCryptoKey(key, alg, ...usages) {
        switch (alg) {
            case 'HS256':
            case 'HS384':
            case 'HS512': {
                if (!isAlgorithm(key.algorithm, 'HMAC'))
                    throw unusable('HMAC');
                const expected = parseInt(alg.slice(2), 10);
                const actual = getHashLength(key.algorithm.hash);
                if (actual !== expected)
                    throw unusable(`SHA-${expected}`, 'algorithm.hash');
                break;
            }
            case 'RS256':
            case 'RS384':
            case 'RS512': {
                if (!isAlgorithm(key.algorithm, 'RSASSA-PKCS1-v1_5'))
                    throw unusable('RSASSA-PKCS1-v1_5');
                const expected = parseInt(alg.slice(2), 10);
                const actual = getHashLength(key.algorithm.hash);
                if (actual !== expected)
                    throw unusable(`SHA-${expected}`, 'algorithm.hash');
                break;
            }
            case 'PS256':
            case 'PS384':
            case 'PS512': {
                if (!isAlgorithm(key.algorithm, 'RSA-PSS'))
                    throw unusable('RSA-PSS');
                const expected = parseInt(alg.slice(2), 10);
                const actual = getHashLength(key.algorithm.hash);
                if (actual !== expected)
                    throw unusable(`SHA-${expected}`, 'algorithm.hash');
                break;
            }
            case 'EdDSA': {
                if (key.algorithm.name !== 'Ed25519' && key.algorithm.name !== 'Ed448') {
                    throw unusable('Ed25519 or Ed448');
                }
                break;
            }
            case 'Ed25519': {
                if (!isAlgorithm(key.algorithm, 'Ed25519'))
                    throw unusable('Ed25519');
                break;
            }
            case 'ES256':
            case 'ES384':
            case 'ES512': {
                if (!isAlgorithm(key.algorithm, 'ECDSA'))
                    throw unusable('ECDSA');
                const expected = getNamedCurve(alg);
                const actual = key.algorithm.namedCurve;
                if (actual !== expected)
                    throw unusable(expected, 'algorithm.namedCurve');
                break;
            }
            default:
                throw new TypeError('CryptoKey does not support this operation');
        }
        checkUsage(key, usages);
    }

    function message(msg, actual, ...types) {
        types = types.filter(Boolean);
        if (types.length > 2) {
            const last = types.pop();
            msg += `one of type ${types.join(', ')}, or ${last}.`;
        }
        else if (types.length === 2) {
            msg += `one of type ${types[0]} or ${types[1]}.`;
        }
        else {
            msg += `of type ${types[0]}.`;
        }
        if (actual == null) {
            msg += ` Received ${actual}`;
        }
        else if (typeof actual === 'function' && actual.name) {
            msg += ` Received function ${actual.name}`;
        }
        else if (typeof actual === 'object' && actual != null) {
            if (actual.constructor?.name) {
                msg += ` Received an instance of ${actual.constructor.name}`;
            }
        }
        return msg;
    }
    var invalidKeyInput = (actual, ...types) => {
        return message('Key must be ', actual, ...types);
    };
    function withAlg(alg, actual, ...types) {
        return message(`Key for the ${alg} algorithm must be `, actual, ...types);
    }

    var isKeyLike = (key) => {
        if (isCryptoKey(key)) {
            return true;
        }
        return key?.[Symbol.toStringTag] === 'KeyObject';
    };
    const types = ['CryptoKey'];

    const isDisjoint = (...headers) => {
        const sources = headers.filter(Boolean);
        if (sources.length === 0 || sources.length === 1) {
            return true;
        }
        let acc;
        for (const header of sources) {
            const parameters = Object.keys(header);
            if (!acc || acc.size === 0) {
                acc = new Set(parameters);
                continue;
            }
            for (const parameter of parameters) {
                if (acc.has(parameter)) {
                    return false;
                }
                acc.add(parameter);
            }
        }
        return true;
    };

    function isObjectLike(value) {
        return typeof value === 'object' && value !== null;
    }
    function isObject(input) {
        if (!isObjectLike(input) || Object.prototype.toString.call(input) !== '[object Object]') {
            return false;
        }
        if (Object.getPrototypeOf(input) === null) {
            return true;
        }
        let proto = input;
        while (Object.getPrototypeOf(proto) !== null) {
            proto = Object.getPrototypeOf(proto);
        }
        return Object.getPrototypeOf(input) === proto;
    }

    var checkKeyLength = (alg, key) => {
        if (alg.startsWith('RS') || alg.startsWith('PS')) {
            const { modulusLength } = key.algorithm;
            if (typeof modulusLength !== 'number' || modulusLength < 2048) {
                throw new TypeError(`${alg} requires key modulusLength to be 2048 bits or larger`);
            }
        }
    };

    function isJWK(key) {
        return isObject(key) && typeof key.kty === 'string';
    }
    function isPrivateJWK(key) {
        return key.kty !== 'oct' && typeof key.d === 'string';
    }
    function isPublicJWK(key) {
        return key.kty !== 'oct' && typeof key.d === 'undefined';
    }
    function isSecretJWK(key) {
        return isJWK(key) && key.kty === 'oct' && typeof key.k === 'string';
    }

    function subtleMapping(jwk) {
        let algorithm;
        let keyUsages;
        switch (jwk.kty) {
            case 'RSA': {
                switch (jwk.alg) {
                    case 'PS256':
                    case 'PS384':
                    case 'PS512':
                        algorithm = { name: 'RSA-PSS', hash: `SHA-${jwk.alg.slice(-3)}` };
                        keyUsages = jwk.d ? ['sign'] : ['verify'];
                        break;
                    case 'RS256':
                    case 'RS384':
                    case 'RS512':
                        algorithm = { name: 'RSASSA-PKCS1-v1_5', hash: `SHA-${jwk.alg.slice(-3)}` };
                        keyUsages = jwk.d ? ['sign'] : ['verify'];
                        break;
                    case 'RSA-OAEP':
                    case 'RSA-OAEP-256':
                    case 'RSA-OAEP-384':
                    case 'RSA-OAEP-512':
                        algorithm = {
                            name: 'RSA-OAEP',
                            hash: `SHA-${parseInt(jwk.alg.slice(-3), 10) || 1}`,
                        };
                        keyUsages = jwk.d ? ['decrypt', 'unwrapKey'] : ['encrypt', 'wrapKey'];
                        break;
                    default:
                        throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
                }
                break;
            }
            case 'EC': {
                switch (jwk.alg) {
                    case 'ES256':
                        algorithm = { name: 'ECDSA', namedCurve: 'P-256' };
                        keyUsages = jwk.d ? ['sign'] : ['verify'];
                        break;
                    case 'ES384':
                        algorithm = { name: 'ECDSA', namedCurve: 'P-384' };
                        keyUsages = jwk.d ? ['sign'] : ['verify'];
                        break;
                    case 'ES512':
                        algorithm = { name: 'ECDSA', namedCurve: 'P-521' };
                        keyUsages = jwk.d ? ['sign'] : ['verify'];
                        break;
                    case 'ECDH-ES':
                    case 'ECDH-ES+A128KW':
                    case 'ECDH-ES+A192KW':
                    case 'ECDH-ES+A256KW':
                        algorithm = { name: 'ECDH', namedCurve: jwk.crv };
                        keyUsages = jwk.d ? ['deriveBits'] : [];
                        break;
                    default:
                        throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
                }
                break;
            }
            case 'OKP': {
                switch (jwk.alg) {
                    case 'Ed25519':
                        algorithm = { name: 'Ed25519' };
                        keyUsages = jwk.d ? ['sign'] : ['verify'];
                        break;
                    case 'EdDSA':
                        algorithm = { name: jwk.crv };
                        keyUsages = jwk.d ? ['sign'] : ['verify'];
                        break;
                    case 'ECDH-ES':
                    case 'ECDH-ES+A128KW':
                    case 'ECDH-ES+A192KW':
                    case 'ECDH-ES+A256KW':
                        algorithm = { name: jwk.crv };
                        keyUsages = jwk.d ? ['deriveBits'] : [];
                        break;
                    default:
                        throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
                }
                break;
            }
            default:
                throw new JOSENotSupported('Invalid or unsupported JWK "kty" (Key Type) Parameter value');
        }
        return { algorithm, keyUsages };
    }
    const parse = async (jwk) => {
        if (!jwk.alg) {
            throw new TypeError('"alg" argument is required when "jwk.alg" is not present');
        }
        const { algorithm, keyUsages } = subtleMapping(jwk);
        const rest = [
            algorithm,
            jwk.ext ?? false,
            jwk.key_ops ?? keyUsages,
        ];
        const keyData = { ...jwk };
        delete keyData.alg;
        delete keyData.use;
        return crypto$1.subtle.importKey('jwk', keyData, ...rest);
    };

    const exportKeyValue = (k) => decode$1(k);
    let privCache;
    let pubCache;
    const isKeyObject = (key) => {
        return key?.[Symbol.toStringTag] === 'KeyObject';
    };
    const importAndCache = async (cache, key, jwk, alg, freeze = false) => {
        let cached = cache.get(key);
        if (cached?.[alg]) {
            return cached[alg];
        }
        const cryptoKey = await parse({ ...jwk, alg });
        if (freeze)
            Object.freeze(key);
        if (!cached) {
            cache.set(key, { [alg]: cryptoKey });
        }
        else {
            cached[alg] = cryptoKey;
        }
        return cryptoKey;
    };
    const normalizePublicKey = (key, alg) => {
        if (isKeyObject(key)) {
            let jwk = key.export({ format: 'jwk' });
            delete jwk.d;
            delete jwk.dp;
            delete jwk.dq;
            delete jwk.p;
            delete jwk.q;
            delete jwk.qi;
            if (jwk.k) {
                return exportKeyValue(jwk.k);
            }
            pubCache || (pubCache = new WeakMap());
            return importAndCache(pubCache, key, jwk, alg);
        }
        if (isJWK(key)) {
            if (key.k)
                return decode$1(key.k);
            pubCache || (pubCache = new WeakMap());
            const cryptoKey = importAndCache(pubCache, key, key, alg, true);
            return cryptoKey;
        }
        return key;
    };
    const normalizePrivateKey = (key, alg) => {
        if (isKeyObject(key)) {
            let jwk = key.export({ format: 'jwk' });
            if (jwk.k) {
                return exportKeyValue(jwk.k);
            }
            privCache || (privCache = new WeakMap());
            return importAndCache(privCache, key, jwk, alg);
        }
        if (isJWK(key)) {
            if (key.k)
                return decode$1(key.k);
            privCache || (privCache = new WeakMap());
            const cryptoKey = importAndCache(privCache, key, key, alg, true);
            return cryptoKey;
        }
        return key;
    };
    var normalize = { normalizePublicKey, normalizePrivateKey };

    async function importJWK(jwk, alg) {
        if (!isObject(jwk)) {
            throw new TypeError('JWK must be an object');
        }
        alg || (alg = jwk.alg);
        switch (jwk.kty) {
            case 'oct':
                if (typeof jwk.k !== 'string' || !jwk.k) {
                    throw new TypeError('missing "k" (Key Value) Parameter value');
                }
                return decode$1(jwk.k);
            case 'RSA':
                if ('oth' in jwk && jwk.oth !== undefined) {
                    throw new JOSENotSupported('RSA JWK "oth" (Other Primes Info) Parameter value is not supported');
                }
            case 'EC':
            case 'OKP':
                return parse({ ...jwk, alg });
            default:
                throw new JOSENotSupported('Unsupported "kty" (Key Type) Parameter value');
        }
    }

    const tag = (key) => key?.[Symbol.toStringTag];
    const jwkMatchesOp = (alg, key, usage) => {
        if (key.use !== undefined && key.use !== 'sig') {
            throw new TypeError('Invalid key for this operation, when present its use must be sig');
        }
        if (key.key_ops !== undefined && key.key_ops.includes?.(usage) !== true) {
            throw new TypeError(`Invalid key for this operation, when present its key_ops must include ${usage}`);
        }
        if (key.alg !== undefined && key.alg !== alg) {
            throw new TypeError(`Invalid key for this operation, when present its alg must be ${alg}`);
        }
        return true;
    };
    const symmetricTypeCheck = (alg, key, usage, allowJwk) => {
        if (key instanceof Uint8Array)
            return;
        if (allowJwk && isJWK(key)) {
            if (isSecretJWK(key) && jwkMatchesOp(alg, key, usage))
                return;
            throw new TypeError(`JSON Web Key for symmetric algorithms must have JWK "kty" (Key Type) equal to "oct" and the JWK "k" (Key Value) present`);
        }
        if (!isKeyLike(key)) {
            throw new TypeError(withAlg(alg, key, ...types, 'Uint8Array', allowJwk ? 'JSON Web Key' : null));
        }
        if (key.type !== 'secret') {
            throw new TypeError(`${tag(key)} instances for symmetric algorithms must be of type "secret"`);
        }
    };
    const asymmetricTypeCheck = (alg, key, usage, allowJwk) => {
        if (allowJwk && isJWK(key)) {
            switch (usage) {
                case 'sign':
                    if (isPrivateJWK(key) && jwkMatchesOp(alg, key, usage))
                        return;
                    throw new TypeError(`JSON Web Key for this operation be a private JWK`);
                case 'verify':
                    if (isPublicJWK(key) && jwkMatchesOp(alg, key, usage))
                        return;
                    throw new TypeError(`JSON Web Key for this operation be a public JWK`);
            }
        }
        if (!isKeyLike(key)) {
            throw new TypeError(withAlg(alg, key, ...types, allowJwk ? 'JSON Web Key' : null));
        }
        if (key.type === 'secret') {
            throw new TypeError(`${tag(key)} instances for asymmetric algorithms must not be of type "secret"`);
        }
        if (usage === 'sign' && key.type === 'public') {
            throw new TypeError(`${tag(key)} instances for asymmetric algorithm signing must be of type "private"`);
        }
        if (usage === 'decrypt' && key.type === 'public') {
            throw new TypeError(`${tag(key)} instances for asymmetric algorithm decryption must be of type "private"`);
        }
        if (key.algorithm && usage === 'verify' && key.type === 'private') {
            throw new TypeError(`${tag(key)} instances for asymmetric algorithm verifying must be of type "public"`);
        }
        if (key.algorithm && usage === 'encrypt' && key.type === 'private') {
            throw new TypeError(`${tag(key)} instances for asymmetric algorithm encryption must be of type "public"`);
        }
    };
    function checkKeyType(allowJwk, alg, key, usage) {
        const symmetric = alg.startsWith('HS') ||
            alg === 'dir' ||
            alg.startsWith('PBES2') ||
            /^A\d{3}(?:GCM)?KW$/.test(alg);
        if (symmetric) {
            symmetricTypeCheck(alg, key, usage, allowJwk);
        }
        else {
            asymmetricTypeCheck(alg, key, usage, allowJwk);
        }
    }
    checkKeyType.bind(undefined, false);
    const checkKeyTypeWithJwk = checkKeyType.bind(undefined, true);

    function validateCrit(Err, recognizedDefault, recognizedOption, protectedHeader, joseHeader) {
        if (joseHeader.crit !== undefined && protectedHeader?.crit === undefined) {
            throw new Err('"crit" (Critical) Header Parameter MUST be integrity protected');
        }
        if (!protectedHeader || protectedHeader.crit === undefined) {
            return new Set();
        }
        if (!Array.isArray(protectedHeader.crit) ||
            protectedHeader.crit.length === 0 ||
            protectedHeader.crit.some((input) => typeof input !== 'string' || input.length === 0)) {
            throw new Err('"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present');
        }
        let recognized;
        if (recognizedOption !== undefined) {
            recognized = new Map([...Object.entries(recognizedOption), ...recognizedDefault.entries()]);
        }
        else {
            recognized = recognizedDefault;
        }
        for (const parameter of protectedHeader.crit) {
            if (!recognized.has(parameter)) {
                throw new JOSENotSupported(`Extension Header Parameter "${parameter}" is not recognized`);
            }
            if (joseHeader[parameter] === undefined) {
                throw new Err(`Extension Header Parameter "${parameter}" is missing`);
            }
            if (recognized.get(parameter) && protectedHeader[parameter] === undefined) {
                throw new Err(`Extension Header Parameter "${parameter}" MUST be integrity protected`);
            }
        }
        return new Set(protectedHeader.crit);
    }

    const validateAlgorithms = (option, algorithms) => {
        if (algorithms !== undefined &&
            (!Array.isArray(algorithms) || algorithms.some((s) => typeof s !== 'string'))) {
            throw new TypeError(`"${option}" option must be an array of strings`);
        }
        if (!algorithms) {
            return undefined;
        }
        return new Set(algorithms);
    };

    function subtleDsa(alg, algorithm) {
        const hash = `SHA-${alg.slice(-3)}`;
        switch (alg) {
            case 'HS256':
            case 'HS384':
            case 'HS512':
                return { hash, name: 'HMAC' };
            case 'PS256':
            case 'PS384':
            case 'PS512':
                return { hash, name: 'RSA-PSS', saltLength: alg.slice(-3) >> 3 };
            case 'RS256':
            case 'RS384':
            case 'RS512':
                return { hash, name: 'RSASSA-PKCS1-v1_5' };
            case 'ES256':
            case 'ES384':
            case 'ES512':
                return { hash, name: 'ECDSA', namedCurve: algorithm.namedCurve };
            case 'Ed25519':
                return { name: 'Ed25519' };
            case 'EdDSA':
                return { name: algorithm.name };
            default:
                throw new JOSENotSupported(`alg ${alg} is not supported either by JOSE or your javascript runtime`);
        }
    }

    async function getCryptoKey(alg, key, usage) {
        {
            key = await normalize.normalizePublicKey(key, alg);
        }
        if (isCryptoKey(key)) {
            checkSigCryptoKey(key, alg, usage);
            return key;
        }
        if (key instanceof Uint8Array) {
            if (!alg.startsWith('HS')) {
                throw new TypeError(invalidKeyInput(key, ...types));
            }
            return crypto$1.subtle.importKey('raw', key, { hash: `SHA-${alg.slice(-3)}`, name: 'HMAC' }, false, [usage]);
        }
        throw new TypeError(invalidKeyInput(key, ...types, 'Uint8Array', 'JSON Web Key'));
    }

    const verify = async (alg, key, signature, data) => {
        const cryptoKey = await getCryptoKey(alg, key, 'verify');
        checkKeyLength(alg, cryptoKey);
        const algorithm = subtleDsa(alg, cryptoKey.algorithm);
        try {
            return await crypto$1.subtle.verify(algorithm, cryptoKey, signature, data);
        }
        catch {
            return false;
        }
    };

    async function flattenedVerify(jws, key, options) {
        if (!isObject(jws)) {
            throw new JWSInvalid('Flattened JWS must be an object');
        }
        if (jws.protected === undefined && jws.header === undefined) {
            throw new JWSInvalid('Flattened JWS must have either of the "protected" or "header" members');
        }
        if (jws.protected !== undefined && typeof jws.protected !== 'string') {
            throw new JWSInvalid('JWS Protected Header incorrect type');
        }
        if (jws.payload === undefined) {
            throw new JWSInvalid('JWS Payload missing');
        }
        if (typeof jws.signature !== 'string') {
            throw new JWSInvalid('JWS Signature missing or incorrect type');
        }
        if (jws.header !== undefined && !isObject(jws.header)) {
            throw new JWSInvalid('JWS Unprotected Header incorrect type');
        }
        let parsedProt = {};
        if (jws.protected) {
            try {
                const protectedHeader = decode$1(jws.protected);
                parsedProt = JSON.parse(decoder.decode(protectedHeader));
            }
            catch {
                throw new JWSInvalid('JWS Protected Header is invalid');
            }
        }
        if (!isDisjoint(parsedProt, jws.header)) {
            throw new JWSInvalid('JWS Protected and JWS Unprotected Header Parameter names must be disjoint');
        }
        const joseHeader = {
            ...parsedProt,
            ...jws.header,
        };
        const extensions = validateCrit(JWSInvalid, new Map([['b64', true]]), options?.crit, parsedProt, joseHeader);
        let b64 = true;
        if (extensions.has('b64')) {
            b64 = parsedProt.b64;
            if (typeof b64 !== 'boolean') {
                throw new JWSInvalid('The "b64" (base64url-encode payload) Header Parameter must be a boolean');
            }
        }
        const { alg } = joseHeader;
        if (typeof alg !== 'string' || !alg) {
            throw new JWSInvalid('JWS "alg" (Algorithm) Header Parameter missing or invalid');
        }
        const algorithms = options && validateAlgorithms('algorithms', options.algorithms);
        if (algorithms && !algorithms.has(alg)) {
            throw new JOSEAlgNotAllowed('"alg" (Algorithm) Header Parameter value not allowed');
        }
        if (b64) {
            if (typeof jws.payload !== 'string') {
                throw new JWSInvalid('JWS Payload must be a string');
            }
        }
        else if (typeof jws.payload !== 'string' && !(jws.payload instanceof Uint8Array)) {
            throw new JWSInvalid('JWS Payload must be a string or an Uint8Array instance');
        }
        let resolvedKey = false;
        if (typeof key === 'function') {
            key = await key(parsedProt, jws);
            resolvedKey = true;
            checkKeyTypeWithJwk(alg, key, 'verify');
            if (isJWK(key)) {
                key = await importJWK(key, alg);
            }
        }
        else {
            checkKeyTypeWithJwk(alg, key, 'verify');
        }
        const data = concat(encoder.encode(jws.protected ?? ''), encoder.encode('.'), typeof jws.payload === 'string' ? encoder.encode(jws.payload) : jws.payload);
        let signature;
        try {
            signature = decode$1(jws.signature);
        }
        catch {
            throw new JWSInvalid('Failed to base64url decode the signature');
        }
        const verified = await verify(alg, key, signature, data);
        if (!verified) {
            throw new JWSSignatureVerificationFailed();
        }
        let payload;
        if (b64) {
            try {
                payload = decode$1(jws.payload);
            }
            catch {
                throw new JWSInvalid('Failed to base64url decode the payload');
            }
        }
        else if (typeof jws.payload === 'string') {
            payload = encoder.encode(jws.payload);
        }
        else {
            payload = jws.payload;
        }
        const result = { payload };
        if (jws.protected !== undefined) {
            result.protectedHeader = parsedProt;
        }
        if (jws.header !== undefined) {
            result.unprotectedHeader = jws.header;
        }
        if (resolvedKey) {
            return { ...result, key };
        }
        return result;
    }

    async function compactVerify(jws, key, options) {
        if (jws instanceof Uint8Array) {
            jws = decoder.decode(jws);
        }
        if (typeof jws !== 'string') {
            throw new JWSInvalid('Compact JWS must be a string or Uint8Array');
        }
        const { 0: protectedHeader, 1: payload, 2: signature, length } = jws.split('.');
        if (length !== 3) {
            throw new JWSInvalid('Invalid Compact JWS');
        }
        const verified = await flattenedVerify({ payload, protected: protectedHeader, signature }, key, options);
        const result = { payload: verified.payload, protectedHeader: verified.protectedHeader };
        if (typeof key === 'function') {
            return { ...result, key: verified.key };
        }
        return result;
    }

    var epoch = (date) => Math.floor(date.getTime() / 1000);

    const minute = 60;
    const hour = minute * 60;
    const day = hour * 24;
    const week = day * 7;
    const year = day * 365.25;
    const REGEX = /^(\+|\-)? ?(\d+|\d+\.\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)(?: (ago|from now))?$/i;
    var secs = (str) => {
        const matched = REGEX.exec(str);
        if (!matched || (matched[4] && matched[1])) {
            throw new TypeError('Invalid time period format');
        }
        const value = parseFloat(matched[2]);
        const unit = matched[3].toLowerCase();
        let numericDate;
        switch (unit) {
            case 'sec':
            case 'secs':
            case 'second':
            case 'seconds':
            case 's':
                numericDate = Math.round(value);
                break;
            case 'minute':
            case 'minutes':
            case 'min':
            case 'mins':
            case 'm':
                numericDate = Math.round(value * minute);
                break;
            case 'hour':
            case 'hours':
            case 'hr':
            case 'hrs':
            case 'h':
                numericDate = Math.round(value * hour);
                break;
            case 'day':
            case 'days':
            case 'd':
                numericDate = Math.round(value * day);
                break;
            case 'week':
            case 'weeks':
            case 'w':
                numericDate = Math.round(value * week);
                break;
            default:
                numericDate = Math.round(value * year);
                break;
        }
        if (matched[1] === '-' || matched[4] === 'ago') {
            return -numericDate;
        }
        return numericDate;
    };

    const normalizeTyp = (value) => value.toLowerCase().replace(/^application\//, '');
    const checkAudiencePresence = (audPayload, audOption) => {
        if (typeof audPayload === 'string') {
            return audOption.includes(audPayload);
        }
        if (Array.isArray(audPayload)) {
            return audOption.some(Set.prototype.has.bind(new Set(audPayload)));
        }
        return false;
    };
    var jwtPayload = (protectedHeader, encodedPayload, options = {}) => {
        let payload;
        try {
            payload = JSON.parse(decoder.decode(encodedPayload));
        }
        catch {
        }
        if (!isObject(payload)) {
            throw new JWTInvalid('JWT Claims Set must be a top-level JSON object');
        }
        const { typ } = options;
        if (typ &&
            (typeof protectedHeader.typ !== 'string' ||
                normalizeTyp(protectedHeader.typ) !== normalizeTyp(typ))) {
            throw new JWTClaimValidationFailed('unexpected "typ" JWT header value', payload, 'typ', 'check_failed');
        }
        const { requiredClaims = [], issuer, subject, audience, maxTokenAge } = options;
        const presenceCheck = [...requiredClaims];
        if (maxTokenAge !== undefined)
            presenceCheck.push('iat');
        if (audience !== undefined)
            presenceCheck.push('aud');
        if (subject !== undefined)
            presenceCheck.push('sub');
        if (issuer !== undefined)
            presenceCheck.push('iss');
        for (const claim of new Set(presenceCheck.reverse())) {
            if (!(claim in payload)) {
                throw new JWTClaimValidationFailed(`missing required "${claim}" claim`, payload, claim, 'missing');
            }
        }
        if (issuer &&
            !(Array.isArray(issuer) ? issuer : [issuer]).includes(payload.iss)) {
            throw new JWTClaimValidationFailed('unexpected "iss" claim value', payload, 'iss', 'check_failed');
        }
        if (subject && payload.sub !== subject) {
            throw new JWTClaimValidationFailed('unexpected "sub" claim value', payload, 'sub', 'check_failed');
        }
        if (audience &&
            !checkAudiencePresence(payload.aud, typeof audience === 'string' ? [audience] : audience)) {
            throw new JWTClaimValidationFailed('unexpected "aud" claim value', payload, 'aud', 'check_failed');
        }
        let tolerance;
        switch (typeof options.clockTolerance) {
            case 'string':
                tolerance = secs(options.clockTolerance);
                break;
            case 'number':
                tolerance = options.clockTolerance;
                break;
            case 'undefined':
                tolerance = 0;
                break;
            default:
                throw new TypeError('Invalid clockTolerance option type');
        }
        const { currentDate } = options;
        const now = epoch(currentDate || new Date());
        if ((payload.iat !== undefined || maxTokenAge) && typeof payload.iat !== 'number') {
            throw new JWTClaimValidationFailed('"iat" claim must be a number', payload, 'iat', 'invalid');
        }
        if (payload.nbf !== undefined) {
            if (typeof payload.nbf !== 'number') {
                throw new JWTClaimValidationFailed('"nbf" claim must be a number', payload, 'nbf', 'invalid');
            }
            if (payload.nbf > now + tolerance) {
                throw new JWTClaimValidationFailed('"nbf" claim timestamp check failed', payload, 'nbf', 'check_failed');
            }
        }
        if (payload.exp !== undefined) {
            if (typeof payload.exp !== 'number') {
                throw new JWTClaimValidationFailed('"exp" claim must be a number', payload, 'exp', 'invalid');
            }
            if (payload.exp <= now - tolerance) {
                throw new JWTExpired('"exp" claim timestamp check failed', payload, 'exp', 'check_failed');
            }
        }
        if (maxTokenAge) {
            const age = now - payload.iat;
            const max = typeof maxTokenAge === 'number' ? maxTokenAge : secs(maxTokenAge);
            if (age - tolerance > max) {
                throw new JWTExpired('"iat" claim timestamp check failed (too far in the past)', payload, 'iat', 'check_failed');
            }
            if (age < 0 - tolerance) {
                throw new JWTClaimValidationFailed('"iat" claim timestamp check failed (it should be in the past)', payload, 'iat', 'check_failed');
            }
        }
        return payload;
    };

    async function jwtVerify(jwt, key, options) {
        const verified = await compactVerify(jwt, key, options);
        if (verified.protectedHeader.crit?.includes('b64') && verified.protectedHeader.b64 === false) {
            throw new JWTInvalid('JWTs MUST NOT use unencoded payload');
        }
        const payload = jwtPayload(verified.protectedHeader, verified.payload, options);
        const result = { payload, protectedHeader: verified.protectedHeader };
        if (typeof key === 'function') {
            return { ...result, key: verified.key };
        }
        return result;
    }

    function getKtyFromAlg(alg) {
        switch (typeof alg === 'string' && alg.slice(0, 2)) {
            case 'RS':
            case 'PS':
                return 'RSA';
            case 'ES':
                return 'EC';
            case 'Ed':
                return 'OKP';
            default:
                throw new JOSENotSupported('Unsupported "alg" value for a JSON Web Key Set');
        }
    }
    function isJWKSLike(jwks) {
        return (jwks &&
            typeof jwks === 'object' &&
            Array.isArray(jwks.keys) &&
            jwks.keys.every(isJWKLike));
    }
    function isJWKLike(key) {
        return isObject(key);
    }
    function clone(obj) {
        if (typeof structuredClone === 'function') {
            return structuredClone(obj);
        }
        return JSON.parse(JSON.stringify(obj));
    }
    class LocalJWKSet {
        constructor(jwks) {
            this._cached = new WeakMap();
            if (!isJWKSLike(jwks)) {
                throw new JWKSInvalid('JSON Web Key Set malformed');
            }
            this._jwks = clone(jwks);
        }
        async getKey(protectedHeader, token) {
            const { alg, kid } = { ...protectedHeader, ...token?.header };
            const kty = getKtyFromAlg(alg);
            const candidates = this._jwks.keys.filter((jwk) => {
                let candidate = kty === jwk.kty;
                if (candidate && typeof kid === 'string') {
                    candidate = kid === jwk.kid;
                }
                if (candidate && typeof jwk.alg === 'string') {
                    candidate = alg === jwk.alg;
                }
                if (candidate && typeof jwk.use === 'string') {
                    candidate = jwk.use === 'sig';
                }
                if (candidate && Array.isArray(jwk.key_ops)) {
                    candidate = jwk.key_ops.includes('verify');
                }
                if (candidate) {
                    switch (alg) {
                        case 'ES256':
                            candidate = jwk.crv === 'P-256';
                            break;
                        case 'ES256K':
                            candidate = jwk.crv === 'secp256k1';
                            break;
                        case 'ES384':
                            candidate = jwk.crv === 'P-384';
                            break;
                        case 'ES512':
                            candidate = jwk.crv === 'P-521';
                            break;
                        case 'Ed25519':
                            candidate = jwk.crv === 'Ed25519';
                            break;
                        case 'EdDSA':
                            candidate = jwk.crv === 'Ed25519' || jwk.crv === 'Ed448';
                            break;
                    }
                }
                return candidate;
            });
            const { 0: jwk, length } = candidates;
            if (length === 0) {
                throw new JWKSNoMatchingKey();
            }
            if (length !== 1) {
                const error = new JWKSMultipleMatchingKeys();
                const { _cached } = this;
                error[Symbol.asyncIterator] = async function* () {
                    for (const jwk of candidates) {
                        try {
                            yield await importWithAlgCache(_cached, jwk, alg);
                        }
                        catch { }
                    }
                };
                throw error;
            }
            return importWithAlgCache(this._cached, jwk, alg);
        }
    }
    async function importWithAlgCache(cache, jwk, alg) {
        const cached = cache.get(jwk) || cache.set(jwk, {}).get(jwk);
        if (cached[alg] === undefined) {
            const key = await importJWK({ ...jwk, ext: true }, alg);
            if (key instanceof Uint8Array || key.type !== 'public') {
                throw new JWKSInvalid('JSON Web Key Set members must be public keys');
            }
            cached[alg] = key;
        }
        return cached[alg];
    }
    function createLocalJWKSet(jwks) {
        const set = new LocalJWKSet(jwks);
        const localJWKSet = async (protectedHeader, token) => set.getKey(protectedHeader, token);
        Object.defineProperties(localJWKSet, {
            jwks: {
                value: () => clone(set._jwks),
                enumerable: true,
                configurable: false,
                writable: false,
            },
        });
        return localJWKSet;
    }

    const fetchJwks = async (url, timeout, options) => {
        let controller;
        let id;
        let timedOut = false;
        if (typeof AbortController === 'function') {
            controller = new AbortController();
            id = setTimeout(() => {
                timedOut = true;
                controller.abort();
            }, timeout);
        }
        const response = await fetch(url.href, {
            signal: controller ? controller.signal : undefined,
            redirect: 'manual',
            headers: options.headers,
        }).catch((err) => {
            if (timedOut)
                throw new JWKSTimeout();
            throw err;
        });
        if (id !== undefined)
            clearTimeout(id);
        if (response.status !== 200) {
            throw new JOSEError('Expected 200 OK from the JSON Web Key Set HTTP response');
        }
        try {
            return await response.json();
        }
        catch {
            throw new JOSEError('Failed to parse the JSON Web Key Set HTTP response as JSON');
        }
    };

    function isCloudflareWorkers() {
        return (typeof WebSocketPair !== 'undefined' ||
            (typeof navigator !== 'undefined' && navigator.userAgent === 'Cloudflare-Workers') ||
            (typeof EdgeRuntime !== 'undefined' && EdgeRuntime === 'vercel'));
    }
    let USER_AGENT;
    if (typeof navigator === 'undefined' || !navigator.userAgent?.startsWith?.('Mozilla/5.0 ')) {
        const NAME = 'jose';
        const VERSION = 'v5.10.0';
        USER_AGENT = `${NAME}/${VERSION}`;
    }
    const jwksCache = Symbol();
    function isFreshJwksCache(input, cacheMaxAge) {
        if (typeof input !== 'object' || input === null) {
            return false;
        }
        if (!('uat' in input) || typeof input.uat !== 'number' || Date.now() - input.uat >= cacheMaxAge) {
            return false;
        }
        if (!('jwks' in input) ||
            !isObject(input.jwks) ||
            !Array.isArray(input.jwks.keys) ||
            !Array.prototype.every.call(input.jwks.keys, isObject)) {
            return false;
        }
        return true;
    }
    class RemoteJWKSet {
        constructor(url, options) {
            if (!(url instanceof URL)) {
                throw new TypeError('url must be an instance of URL');
            }
            this._url = new URL(url.href);
            this._options = { agent: options?.agent, headers: options?.headers };
            this._timeoutDuration =
                typeof options?.timeoutDuration === 'number' ? options?.timeoutDuration : 5000;
            this._cooldownDuration =
                typeof options?.cooldownDuration === 'number' ? options?.cooldownDuration : 30000;
            this._cacheMaxAge = typeof options?.cacheMaxAge === 'number' ? options?.cacheMaxAge : 600000;
            if (options?.[jwksCache] !== undefined) {
                this._cache = options?.[jwksCache];
                if (isFreshJwksCache(options?.[jwksCache], this._cacheMaxAge)) {
                    this._jwksTimestamp = this._cache.uat;
                    this._local = createLocalJWKSet(this._cache.jwks);
                }
            }
        }
        coolingDown() {
            return typeof this._jwksTimestamp === 'number'
                ? Date.now() < this._jwksTimestamp + this._cooldownDuration
                : false;
        }
        fresh() {
            return typeof this._jwksTimestamp === 'number'
                ? Date.now() < this._jwksTimestamp + this._cacheMaxAge
                : false;
        }
        async getKey(protectedHeader, token) {
            if (!this._local || !this.fresh()) {
                await this.reload();
            }
            try {
                return await this._local(protectedHeader, token);
            }
            catch (err) {
                if (err instanceof JWKSNoMatchingKey) {
                    if (this.coolingDown() === false) {
                        await this.reload();
                        return this._local(protectedHeader, token);
                    }
                }
                throw err;
            }
        }
        async reload() {
            if (this._pendingFetch && isCloudflareWorkers()) {
                this._pendingFetch = undefined;
            }
            const headers = new Headers(this._options.headers);
            if (USER_AGENT && !headers.has('User-Agent')) {
                headers.set('User-Agent', USER_AGENT);
                this._options.headers = Object.fromEntries(headers.entries());
            }
            this._pendingFetch || (this._pendingFetch = fetchJwks(this._url, this._timeoutDuration, this._options)
                .then((json) => {
                this._local = createLocalJWKSet(json);
                if (this._cache) {
                    this._cache.uat = Date.now();
                    this._cache.jwks = json;
                }
                this._jwksTimestamp = Date.now();
                this._pendingFetch = undefined;
            })
                .catch((err) => {
                this._pendingFetch = undefined;
                throw err;
            }));
            await this._pendingFetch;
        }
    }
    function createRemoteJWKSet(url, options) {
        const set = new RemoteJWKSet(url, options);
        const remoteJWKSet = async (protectedHeader, token) => set.getKey(protectedHeader, token);
        Object.defineProperties(remoteJWKSet, {
            coolingDown: {
                get: () => set.coolingDown(),
                enumerable: true,
                configurable: false,
            },
            fresh: {
                get: () => set.fresh(),
                enumerable: true,
                configurable: false,
            },
            reload: {
                value: () => set.reload(),
                enumerable: true,
                configurable: false,
                writable: false,
            },
            reloading: {
                get: () => !!set._pendingFetch,
                enumerable: true,
                configurable: false,
            },
            jwks: {
                value: () => set._local?.jwks(),
                enumerable: true,
                configurable: false,
                writable: false,
            },
        });
        return remoteJWKSet;
    }

    const decode = decode$1;

    function decodeJwt(jwt) {
        if (typeof jwt !== 'string')
            throw new JWTInvalid('JWTs must use Compact JWS serialization, JWT must be a string');
        const { 1: payload, length } = jwt.split('.');
        if (length === 5)
            throw new JWTInvalid('Only JWTs using Compact JWS serialization can be decoded');
        if (length !== 3)
            throw new JWTInvalid('Invalid JWT');
        if (!payload)
            throw new JWTInvalid('JWTs must contain a payload');
        let decoded;
        try {
            decoded = decode(payload);
        }
        catch {
            throw new JWTInvalid('Failed to base64url decode the payload');
        }
        let result;
        try {
            result = JSON.parse(decoder.decode(decoded));
        }
        catch {
            throw new JWTInvalid('Failed to parse the decoded payload as JSON');
        }
        if (!isObject(result))
            throw new JWTInvalid('Invalid JWT Claims Set');
        return result;
    }

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
                return decodeJwt(idToken);
            }
            try {
                // Fetch JWKS
                const jwks = await createRemoteJWKSet(new URL(this.config.provider.jwksEndpoint));
                // Verify and decode the token
                const { payload } = await jwtVerify(idToken, jwks, {
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

    Object.defineProperty(exports, '__esModule', { value: true });

}));
//# sourceMappingURL=quid-sdk.umd.js.map
