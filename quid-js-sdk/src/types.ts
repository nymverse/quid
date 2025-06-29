/**
 * QuID JavaScript SDK Types
 * Core type definitions for the QuID authentication system
 */

export interface QuIDConfig {
  /** Base URL for QuID services (optional for browser extension integration) */
  baseUrl?: string;
  /** Timeout for authentication requests in milliseconds */
  timeout?: number;
  /** Default user verification requirement */
  userVerification?: UserVerificationRequirement;
  /** Enable debug logging */
  debug?: boolean;
  /** Custom extension ID for browser extension integration */
  extensionId?: string;
  /** Enable automatic fallback to WebAuthn */
  enableWebAuthnFallback?: boolean;
}

export interface QuIDIdentity {
  /** Unique identifier for the identity */
  id: string;
  /** Human-readable name for the identity */
  name?: string;
  /** Security level of the identity */
  securityLevel: SecurityLevel;
  /** Networks this identity can be used with */
  networks: string[];
  /** Whether this identity is currently active */
  isActive: boolean;
  /** Creation timestamp */
  createdAt: Date;
  /** Last used timestamp */
  lastUsedAt?: Date;
  /** Public key information */
  publicKey?: PublicKeyInfo;
}

export interface PublicKeyInfo {
  /** Algorithm used for the public key */
  algorithm: string;
  /** Public key data in hex format */
  publicKey: string;
  /** Key identifier */
  keyId: string;
}

export type SecurityLevel = 'Level1' | 'Level2' | 'Level3';

export type UserVerificationRequirement = 'required' | 'preferred' | 'discouraged';

export interface AuthenticationRequest {
  /** Challenge to be signed */
  challenge: string;
  /** Origin requesting authentication */
  origin: string;
  /** User verification requirement */
  userVerification?: UserVerificationRequirement;
  /** Timeout for the request */
  timeout?: number;
  /** Allowed credentials (for WebAuthn compatibility) */
  allowCredentials?: PublicKeyCredentialDescriptor[];
  /** Relying party information */
  rpId?: string;
}

export interface AuthenticationResponse {
  /** Whether authentication was successful */
  success: boolean;
  /** Error message if authentication failed */
  error?: string;
  /** Authentication credential */
  credential?: QuIDCredential;
  /** Identity used for authentication */
  identity?: QuIDIdentity;
}

export interface QuIDCredential {
  /** Credential identifier */
  id: string;
  /** Raw credential ID */
  rawId: string;
  /** Credential type */
  type: 'public-key';
  /** Authenticator response */
  response: {
    /** Authenticator data */
    authenticatorData: string;
    /** Client data JSON */
    clientDataJSON: string;
    /** Signature */
    signature: string;
    /** User handle */
    userHandle?: string;
  };
}

export interface SigninOptions {
  /** Challenge for authentication */
  challenge?: string;
  /** User verification requirement */
  userVerification?: UserVerificationRequirement;
  /** Timeout for authentication */
  timeout?: number;
  /** Callback when authentication completes */
  onSuccess?: (response: AuthenticationResponse) => void;
  /** Callback when authentication fails */
  onError?: (error: Error) => void;
  /** Custom styling for the signin component */
  style?: ComponentStyle;
  /** Text to display on the signin button */
  buttonText?: string;
  /** Show QuID branding */
  showBranding?: boolean;
}

export interface ComponentStyle {
  /** Button width */
  width?: string;
  /** Button height */
  height?: string;
  /** Background color */
  backgroundColor?: string;
  /** Text color */
  color?: string;
  /** Border radius */
  borderRadius?: string;
  /** Font family */
  fontFamily?: string;
  /** Font size */
  fontSize?: string;
  /** Padding */
  padding?: string;
  /** Margin */
  margin?: string;
  /** Custom CSS classes */
  className?: string;
}

export interface OAuthConfig {
  /** Client ID for OAuth */
  clientId: string;
  /** Client secret for OAuth (server-side only) */
  clientSecret?: string;
  /** Redirect URI for OAuth flow */
  redirectUri: string;
  /** OAuth scopes to request */
  scopes?: string[];
  /** OAuth provider configuration */
  provider?: OAuthProvider;
}

export interface OAuthProvider {
  /** Authorization endpoint */
  authorizationEndpoint: string;
  /** Token endpoint */
  tokenEndpoint: string;
  /** User info endpoint */
  userInfoEndpoint?: string;
  /** JWKS endpoint for token verification */
  jwksEndpoint?: string;
}

export interface OAuthTokenResponse {
  /** Access token */
  accessToken: string;
  /** Token type (usually 'Bearer') */
  tokenType: string;
  /** Token expiration time in seconds */
  expiresIn?: number;
  /** Refresh token */
  refreshToken?: string;
  /** Scopes granted */
  scope?: string;
  /** ID token (OpenID Connect) */
  idToken?: string;
}

export interface QuIDEvent {
  /** Event type */
  type: QuIDEventType;
  /** Event data */
  data?: any;
  /** Timestamp */
  timestamp: Date;
}

export type QuIDEventType = 
  | 'ready'
  | 'authentication-started'
  | 'authentication-completed'
  | 'authentication-failed'
  | 'identity-created'
  | 'identity-selected'
  | 'extension-connected'
  | 'extension-disconnected'
  | 'error';

export interface QuIDSDKError extends Error {
  /** Error code */
  code: string;
  /** Additional error details */
  details?: any;
}

export interface CreateIdentityRequest {
  /** Name for the new identity */
  name: string;
  /** Security level for the identity */
  securityLevel?: SecurityLevel;
  /** Networks the identity should support */
  networks?: string[];
}

export interface WebAuthnCredentialCreationOptions {
  publicKey: {
    challenge: ArrayBuffer;
    rp: {
      name: string;
      id?: string;
    };
    user: {
      id: ArrayBuffer;
      name: string;
      displayName: string;
    };
    pubKeyCredParams: PublicKeyCredentialParameters[];
    timeout?: number;
    excludeCredentials?: PublicKeyCredentialDescriptor[];
    authenticatorSelection?: AuthenticatorSelectionCriteria;
    attestation?: AttestationConveyancePreference;
  };
}

export interface WebAuthnCredentialRequestOptions {
  publicKey: {
    challenge: ArrayBuffer;
    timeout?: number;
    rpId?: string;
    allowCredentials?: PublicKeyCredentialDescriptor[];
    userVerification?: UserVerificationRequirement;
  };
}

// Re-export browser types for convenience
export type {
  PublicKeyCredentialDescriptor,
  PublicKeyCredentialParameters,
  AuthenticatorSelectionCriteria,
  AttestationConveyancePreference
} from './browser-types';