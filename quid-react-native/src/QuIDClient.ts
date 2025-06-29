/**
 * QuID React Native Client
 * Main client for quantum-resistant authentication in React Native
 */

import { NativeModules, Platform, DeviceEventEmitter } from 'react-native';
import DeviceInfo from 'react-native-device-info';
import Keychain from 'react-native-keychain';
import ReactNativeBiometrics from 'react-native-biometrics';

import {
  QuIDConfig,
  QuIDIdentity,
  CreateIdentityRequest,
  AuthenticationRequest,
  AuthenticationResponse,
  DeviceCapabilities,
  BiometricType,
  SecurityLevel,
  UserVerification,
  QuIDError,
  QRAuthRequest,
  QRAuthResponse,
  IdentityBackup,
  RecoveryInfo,
  PushAuthRequest,
  PushAuthResponse,
  QuIDEvent,
  QuIDEventType,
} from './types';

// Native module interface
const { QuIDNative } = NativeModules;

/**
 * Main QuID client class for React Native
 */
export class QuIDClient {
  private config: QuIDConfig;
  private biometrics: ReactNativeBiometrics;
  private eventListeners: Map<string, Function[]> = new Map();

  constructor(config: Partial<QuIDConfig> = {}) {
    this.config = {
      securityLevel: SecurityLevel.LEVEL1,
      requireBiometrics: true,
      timeout: 60000,
      debugMode: false,
      enableBackup: true,
      ...config,
    };

    this.biometrics = new ReactNativeBiometrics({
      allowDeviceCredentials: true,
    });

    this.setupEventListeners();
  }

  // MARK: - Public API

  /**
   * Check if QuID is available on this device
   */
  static async isAvailable(): Promise<boolean> {
    try {
      if (Platform.OS === 'ios') {
        return await QuIDNative?.isSecureEnclaveAvailable() ?? false;
      } else if (Platform.OS === 'android') {
        return await QuIDNative?.isTEEAvailable() ?? false;
      }
      return false;
    } catch (error) {
      return false;
    }
  }

  /**
   * Get device capabilities
   */
  async getDeviceCapabilities(): Promise<DeviceCapabilities> {
    const [
      deviceModel,
      systemVersion,
      isJailbroken,
      biometricCapabilities,
      hasSecureHardware,
    ] = await Promise.all([
      DeviceInfo.getModel(),
      DeviceInfo.getSystemVersion(),
      DeviceInfo.isEmulator(),
      this.biometrics.isSensorAvailable(),
      this.checkSecureHardware(),
    ]);

    let biometricType = BiometricType.NONE;
    let hasBiometrics = false;

    if (biometricCapabilities.available) {
      hasBiometrics = true;
      switch (biometricCapabilities.biometryType) {
        case 'TouchID':
          biometricType = BiometricType.TOUCH_ID;
          break;
        case 'FaceID':
          biometricType = BiometricType.FACE_ID;
          break;
        case 'Biometrics':
          biometricType = Platform.OS === 'android' 
            ? BiometricType.FINGERPRINT 
            : BiometricType.UNKNOWN;
          break;
        default:
          biometricType = BiometricType.UNKNOWN;
      }
    }

    const hasPasscode = await this.checkPasscode();

    return {
      hasSecureHardware,
      hasBiometrics,
      biometricType,
      hasPasscode,
      deviceModel,
      systemVersion,
      isJailbroken,
    };
  }

  /**
   * Create a new QuID identity
   */
  async createIdentity(request: CreateIdentityRequest): Promise<QuIDIdentity> {
    try {
      const capabilities = await this.getDeviceCapabilities();
      
      if (!capabilities.hasSecureHardware) {
        throw new Error(QuIDError.SECURE_HARDWARE_NOT_AVAILABLE);
      }

      if (request.requireBiometrics && !capabilities.hasBiometrics) {
        throw new Error(QuIDError.BIOMETRIC_AUTHENTICATION_FAILED);
      }

      const identityData = {
        name: request.name,
        securityLevel: request.securityLevel ?? this.config.securityLevel,
        networks: request.networks ?? ['mobile'],
        requireBiometrics: request.requireBiometrics ?? this.config.requireBiometrics,
        metadata: request.metadata ?? {},
      };

      let identity: QuIDIdentity;

      if (Platform.OS === 'ios') {
        identity = await QuIDNative.createIdentity(identityData);
      } else if (Platform.OS === 'android') {
        identity = await QuIDNative.createIdentity(identityData);
      } else {
        throw new Error(QuIDError.SECURE_HARDWARE_NOT_AVAILABLE);
      }

      // Store identity metadata in secure storage
      await this.storeIdentityMetadata(identity);

      this.emitEvent({
        type: QuIDEventType.IDENTITY_CREATED,
        data: { identity },
        timestamp: new Date(),
      });

      return identity;
    } catch (error) {
      this.handleError('createIdentity', error);
      throw error;
    }
  }

  /**
   * Get all identities
   */
  async getIdentities(): Promise<QuIDIdentity[]> {
    try {
      if (Platform.OS === 'ios') {
        return await QuIDNative.getIdentities();
      } else if (Platform.OS === 'android') {
        return await QuIDNative.getIdentities();
      }
      return [];
    } catch (error) {
      this.handleError('getIdentities', error);
      return [];
    }
  }

  /**
   * Authenticate with QuID
   */
  async authenticate(request: AuthenticationRequest): Promise<AuthenticationResponse> {
    try {
      const capabilities = await this.getDeviceCapabilities();
      
      if (!capabilities.hasSecureHardware) {
        throw new Error(QuIDError.SECURE_HARDWARE_NOT_AVAILABLE);
      }

      const identities = await this.getIdentities();
      if (identities.length === 0) {
        throw new Error(QuIDError.NO_IDENTITIES_AVAILABLE);
      }

      const identity = request.identityId 
        ? identities.find(id => id.id === request.identityId)
        : identities[0];

      if (!identity) {
        throw new Error(QuIDError.IDENTITY_NOT_FOUND);
      }

      // Perform biometric authentication if required
      if (identity.requireBiometrics && request.userVerification !== UserVerification.DISCOURAGED) {
        await this.performBiometricAuth(`Authenticate with QuID for ${request.origin}`);
      }

      const authRequest = {
        challenge: request.challenge ?? this.generateChallenge(),
        identityId: identity.id,
        origin: request.origin,
        userVerification: request.userVerification ?? UserVerification.PREFERRED,
        timeout: request.timeout ?? this.config.timeout,
      };

      let response: AuthenticationResponse;

      if (Platform.OS === 'ios') {
        response = await QuIDNative.authenticate(authRequest);
      } else if (Platform.OS === 'android') {
        response = await QuIDNative.authenticate(authRequest);
      } else {
        throw new Error(QuIDError.SECURE_HARDWARE_NOT_AVAILABLE);
      }

      if (response.success) {
        this.emitEvent({
          type: QuIDEventType.AUTHENTICATION_SUCCESS,
          data: { identity, origin: request.origin },
          timestamp: new Date(),
        });
      } else {
        this.emitEvent({
          type: QuIDEventType.AUTHENTICATION_FAILED,
          data: { identity, origin: request.origin, error: response.error },
          timestamp: new Date(),
        });
      }

      return response;
    } catch (error) {
      this.handleError('authenticate', error);
      throw error;
    }
  }

  /**
   * Authenticate using QR code
   */
  async authenticateQR(request: QRAuthRequest): Promise<QRAuthResponse> {
    try {
      const { qrData } = request;

      // Validate QR code
      if (Date.now() > qrData.expiresAt) {
        throw new Error(QuIDError.QR_CODE_EXPIRED);
      }

      // Convert QR data to authentication request
      const authRequest: AuthenticationRequest = {
        challenge: qrData.challenge,
        identityId: request.identityId,
        origin: qrData.origin,
        userVerification: qrData.userVerification,
        timeout: qrData.expiresAt - Date.now(),
      };

      const authResponse = await this.authenticate(authRequest);

      if (authResponse.success && authResponse.credential) {
        return {
          success: true,
          response: JSON.stringify(authResponse.credential),
        };
      } else {
        return {
          success: false,
          error: authResponse.error ?? 'Authentication failed',
        };
      }
    } catch (error) {
      this.handleError('authenticateQR', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Handle push notification authentication request
   */
  async handlePushAuth(request: PushAuthRequest): Promise<PushAuthResponse> {
    try {
      if (Date.now() > request.expiresAt) {
        return {
          requestId: request.requestId,
          success: false,
          error: 'Authentication request expired',
        };
      }

      const authRequest: AuthenticationRequest = {
        challenge: request.challenge,
        origin: request.origin,
        userVerification: request.userVerification,
        timeout: request.expiresAt - Date.now(),
      };

      const authResponse = await this.authenticate(authRequest);

      return {
        requestId: request.requestId,
        success: authResponse.success,
        response: authResponse.success && authResponse.credential 
          ? JSON.stringify(authResponse.credential) 
          : undefined,
        error: authResponse.error,
      };
    } catch (error) {
      this.handleError('handlePushAuth', error);
      return {
        requestId: request.requestId,
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Delete an identity
   */
  async deleteIdentity(id: string): Promise<void> {
    try {
      const identity = (await this.getIdentities()).find(i => i.id === id);
      if (!identity) {
        throw new Error(QuIDError.IDENTITY_NOT_FOUND);
      }

      if (Platform.OS === 'ios') {
        await QuIDNative.deleteIdentity(id);
      } else if (Platform.OS === 'android') {
        await QuIDNative.deleteIdentity(id);
      }

      // Remove from secure storage
      await this.removeIdentityMetadata(id);

      this.emitEvent({
        type: QuIDEventType.IDENTITY_DELETED,
        data: { identity },
        timestamp: new Date(),
      });
    } catch (error) {
      this.handleError('deleteIdentity', error);
      throw error;
    }
  }

  /**
   * Export identity for backup
   */
  async exportIdentity(id: string): Promise<IdentityBackup> {
    try {
      if (Platform.OS === 'ios') {
        return await QuIDNative.exportIdentity(id);
      } else if (Platform.OS === 'android') {
        return await QuIDNative.exportIdentity(id);
      }
      throw new Error(QuIDError.SECURE_HARDWARE_NOT_AVAILABLE);
    } catch (error) {
      this.handleError('exportIdentity', error);
      throw error;
    }
  }

  /**
   * Get recovery information for an identity
   */
  async getRecoveryInfo(identityId: string): Promise<RecoveryInfo> {
    try {
      if (Platform.OS === 'ios') {
        return await QuIDNative.getRecoveryInfo(identityId);
      } else if (Platform.OS === 'android') {
        return await QuIDNative.getRecoveryInfo(identityId);
      }
      throw new Error(QuIDError.SECURE_HARDWARE_NOT_AVAILABLE);
    } catch (error) {
      this.handleError('getRecoveryInfo', error);
      throw error;
    }
  }

  // MARK: - Event Management

  /**
   * Add event listener
   */
  addEventListener(eventType: QuIDEventType, listener: (event: QuIDEvent) => void): void {
    if (!this.eventListeners.has(eventType)) {
      this.eventListeners.set(eventType, []);
    }
    this.eventListeners.get(eventType)!.push(listener);
  }

  /**
   * Remove event listener
   */
  removeEventListener(eventType: QuIDEventType, listener: (event: QuIDEvent) => void): void {
    const listeners = this.eventListeners.get(eventType);
    if (listeners) {
      const index = listeners.indexOf(listener);
      if (index > -1) {
        listeners.splice(index, 1);
      }
    }
  }

  // MARK: - Private Methods

  private setupEventListeners(): void {
    // Listen for biometric changes
    DeviceEventEmitter.addListener('QuIDBiometricChanged', () => {
      this.emitEvent({
        type: QuIDEventType.BIOMETRIC_CHANGED,
        data: {},
        timestamp: new Date(),
      });
    });
  }

  private emitEvent(event: QuIDEvent): void {
    const listeners = this.eventListeners.get(event.type);
    if (listeners) {
      listeners.forEach(listener => listener(event));
    }
  }

  private async checkSecureHardware(): Promise<boolean> {
    try {
      if (Platform.OS === 'ios') {
        return await QuIDNative?.isSecureEnclaveAvailable() ?? false;
      } else if (Platform.OS === 'android') {
        return await QuIDNative?.isTEEAvailable() ?? false;
      }
      return false;
    } catch {
      return false;
    }
  }

  private async checkPasscode(): Promise<boolean> {
    try {
      const result = await this.biometrics.isSensorAvailable();
      return result.available || result.error === 'DeviceCredentials';
    } catch {
      return false;
    }
  }

  private async performBiometricAuth(promptMessage: string): Promise<void> {
    try {
      const result = await this.biometrics.simplePrompt({
        promptMessage,
        cancelButtonText: 'Cancel',
      });

      if (!result.success) {
        throw new Error(QuIDError.BIOMETRIC_AUTHENTICATION_FAILED);
      }
    } catch (error) {
      throw new Error(QuIDError.BIOMETRIC_AUTHENTICATION_FAILED);
    }
  }

  private generateChallenge(): string {
    const array = new Uint8Array(32);
    // Generate random bytes - in real implementation, use crypto.getRandomValues
    for (let i = 0; i < array.length; i++) {
      array[i] = Math.floor(Math.random() * 256);
    }
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  private async storeIdentityMetadata(identity: QuIDIdentity): Promise<void> {
    try {
      const metadata = {
        id: identity.id,
        name: identity.name,
        createdAt: identity.createdAt.toISOString(),
        networks: identity.networks,
        metadata: identity.metadata,
      };

      await Keychain.setInternetCredentials(
        `quid-identity-${identity.id}`,
        identity.id,
        JSON.stringify(metadata),
        {
          accessControl: Keychain.ACCESS_CONTROL.BIOMETRY_ANY_OR_DEVICE_PASSCODE,
          accessGroup: 'com.quid.identities',
        }
      );
    } catch (error) {
      this.handleError('storeIdentityMetadata', error);
    }
  }

  private async removeIdentityMetadata(id: string): Promise<void> {
    try {
      await Keychain.resetInternetCredentials(`quid-identity-${id}`);
    } catch (error) {
      this.handleError('removeIdentityMetadata', error);
    }
  }

  private handleError(operation: string, error: any): void {
    if (this.config.debugMode) {
      console.error(`QuID ${operation} error:`, error);
    }

    this.emitEvent({
      type: QuIDEventType.SECURITY_ALERT,
      data: { operation, error: error.message ?? error },
      timestamp: new Date(),
    });
  }
}

// Default export
export default QuIDClient;