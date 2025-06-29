/**
 * Type definitions for QuID React Native SDK
 */

// Configuration types
export interface QuIDConfig {
  readonly securityLevel: SecurityLevel;
  readonly requireBiometrics: boolean;
  readonly timeout: number;
  readonly debugMode: boolean;
  readonly enableBackup: boolean;
  readonly customKeystore?: string;
}

export enum SecurityLevel {
  LEVEL1 = 'Level1', // P-256
  LEVEL2 = 'Level2', // P-384
  LEVEL3 = 'Level3', // P-521
}

export enum UserVerification {
  REQUIRED = 'required',
  PREFERRED = 'preferred',
  DISCOURAGED = 'discouraged',
}

// Identity types
export interface QuIDIdentity {
  readonly id: string;
  readonly name: string;
  readonly securityLevel: SecurityLevel;
  readonly networks: string[];
  readonly requireBiometrics: boolean;
  readonly publicKey: string;
  readonly algorithm: string;
  readonly createdAt: Date;
  readonly lastUsedAt: Date | null;
  readonly lastBackup: Date | null;
  readonly metadata: Record<string, string>;
}

export interface CreateIdentityRequest {
  readonly name: string;
  readonly securityLevel?: SecurityLevel;
  readonly networks?: string[];
  readonly requireBiometrics?: boolean;
  readonly metadata?: Record<string, string>;
}

// Authentication types
export interface AuthenticationRequest {
  readonly challenge?: string;
  readonly identityId?: string;
  readonly origin: string;
  readonly userVerification?: UserVerification;
  readonly timeout?: number;
}

export interface AuthenticationResponse {
  readonly success: boolean;
  readonly credential?: QuIDCredential;
  readonly identity?: QuIDIdentity;
  readonly error?: string;
}

export interface QuIDCredential {
  readonly id: string;
  readonly rawId: string;
  readonly response: QuIDCredentialResponse;
  readonly type: string;
}

export interface QuIDCredentialResponse {
  readonly authenticatorData: string;
  readonly clientDataJSON: string;
  readonly signature: string;
  readonly userHandle: string;
}

// Device capabilities
export interface DeviceCapabilities {
  readonly hasSecureHardware: boolean;
  readonly hasBiometrics: boolean;
  readonly biometricType: BiometricType;
  readonly hasPasscode: boolean;
  readonly deviceModel: string;
  readonly systemVersion: string;
  readonly isJailbroken: boolean;
}

export enum BiometricType {
  NONE = 'none',
  TOUCH_ID = 'touchId',
  FACE_ID = 'faceId',
  FINGERPRINT = 'fingerprint',
  FACE = 'face',
  IRIS = 'iris',
  UNKNOWN = 'unknown',
}

// QR Code types
export interface QRCodeData {
  readonly challenge: string;
  readonly origin: string;
  readonly timestamp: number;
  readonly expiresAt: number;
  readonly userVerification: UserVerification;
  readonly metadata?: Record<string, any>;
}

export interface QRAuthRequest {
  readonly qrData: QRCodeData;
  readonly identityId?: string;
}

export interface QRAuthResponse {
  readonly success: boolean;
  readonly response?: string; // Base64 encoded response
  readonly error?: string;
}

// Backup and recovery types
export interface IdentityBackup {
  readonly id: string;
  readonly name: string;
  readonly publicKey: string;
  readonly securityLevel: SecurityLevel;
  readonly networks: string[];
  readonly createdAt: Date;
  readonly metadata: Record<string, string>;
}

export interface RecoveryInfo {
  readonly identityId: string;
  readonly recoveryMethods: string[];
  readonly backupAvailable: boolean;
  readonly lastBackup: Date | null;
}

// Push notification types
export interface PushAuthRequest {
  readonly requestId: string;
  readonly challenge: string;
  readonly origin: string;
  readonly title: string;
  readonly message: string;
  readonly userVerification: UserVerification;
  readonly expiresAt: number;
}

export interface PushAuthResponse {
  readonly requestId: string;
  readonly success: boolean;
  readonly response?: string;
  readonly error?: string;
}

// Event types
export interface QuIDEvent {
  readonly type: QuIDEventType;
  readonly data: any;
  readonly timestamp: Date;
}

export enum QuIDEventType {
  IDENTITY_CREATED = 'identity_created',
  IDENTITY_DELETED = 'identity_deleted',
  AUTHENTICATION_SUCCESS = 'authentication_success',
  AUTHENTICATION_FAILED = 'authentication_failed',
  BIOMETRIC_CHANGED = 'biometric_changed',
  SECURITY_ALERT = 'security_alert',
  BACKUP_CREATED = 'backup_created',
  BACKUP_RESTORED = 'backup_restored',
}

// Error types
export enum QuIDError {
  SECURE_HARDWARE_NOT_AVAILABLE = 'secure_hardware_not_available',
  BIOMETRIC_AUTHENTICATION_FAILED = 'biometric_authentication_failed',
  IDENTITY_NOT_FOUND = 'identity_not_found',
  NO_IDENTITIES_AVAILABLE = 'no_identities_available',
  KEY_GENERATION_FAILED = 'key_generation_failed',
  SIGNING_FAILED = 'signing_failed',
  INVALID_CONFIGURATION = 'invalid_configuration',
  NETWORK_ERROR = 'network_error',
  TIMEOUT = 'timeout',
  INVALID_QR_CODE = 'invalid_qr_code',
  QR_CODE_EXPIRED = 'qr_code_expired',
  PUSH_NOTIFICATION_FAILED = 'push_notification_failed',
  BACKUP_FAILED = 'backup_failed',
  RECOVERY_FAILED = 'recovery_failed',
  UNKNOWN = 'unknown',
}

// Hook types
export interface UseQuIDIdentitiesReturn {
  readonly identities: QuIDIdentity[];
  readonly loading: boolean;
  readonly error: string | null;
  readonly refresh: () => Promise<void>;
  readonly createIdentity: (request: CreateIdentityRequest) => Promise<QuIDIdentity>;
  readonly deleteIdentity: (id: string) => Promise<void>;
}

export interface UseQuIDAuthReturn {
  readonly authenticate: (request: AuthenticationRequest) => Promise<AuthenticationResponse>;
  readonly authenticateQR: (request: QRAuthRequest) => Promise<QRAuthResponse>;
  readonly loading: boolean;
  readonly error: string | null;
}

export interface UseDeviceCapabilitiesReturn {
  readonly capabilities: DeviceCapabilities | null;
  readonly loading: boolean;
  readonly error: string | null;
  readonly refresh: () => Promise<void>;
}

// Component props
export interface QuIDSignInButtonProps {
  readonly onSuccess: (response: AuthenticationResponse) => void;
  readonly onError: (error: string) => void;
  readonly challenge?: string;
  readonly identityId?: string;
  readonly origin: string;
  readonly userVerification?: UserVerification;
  readonly style?: any;
  readonly title?: string;
  readonly disabled?: boolean;
}

export interface QuIDQRScannerProps {
  readonly onScan: (data: QRCodeData) => void;
  readonly onError: (error: string) => void;
  readonly style?: any;
  readonly overlayColor?: string;
  readonly borderColor?: string;
}

export interface QuIDQRGeneratorProps {
  readonly data: QRCodeData;
  readonly size?: number;
  readonly color?: string;
  readonly backgroundColor?: string;
  readonly logo?: any;
  readonly style?: any;
}

export interface QuIDIdentityListProps {
  readonly identities: QuIDIdentity[];
  readonly onSelect?: (identity: QuIDIdentity) => void;
  readonly onDelete?: (identity: QuIDIdentity) => void;
  readonly style?: any;
  readonly itemStyle?: any;
  readonly showDetails?: boolean;
}