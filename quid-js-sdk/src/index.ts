/**
 * QuID JavaScript SDK
 * Universal quantum-resistant authentication for web applications
 */

// Core exports
export { QuIDClient } from './core/quid-client';
export { ExtensionConnector } from './core/extension-connector';
export { WebAuthnBridge } from './core/webauthn-bridge';

// OAuth exports
export { QuIDOAuthClient } from './oauth/oauth-client';

// Component exports
export { QuIDSigninButton, createSigninButton } from './components/signin-button';

// React exports
export { 
  QuIDSigninButton as QuIDSigninButtonReact,
  default as QuIDSigninButtonReactDefault 
} from './components/react/signin-button';
export { useQuID, default as useQuIDDefault } from './components/react/use-quid';

// Utility exports
export { EventEmitter } from './utils/event-emitter';
export { Logger } from './utils/logger';

// Type exports
export type {
  QuIDConfig,
  QuIDIdentity,
  PublicKeyInfo,
  SecurityLevel,
  UserVerificationRequirement,
  AuthenticationRequest,
  AuthenticationResponse,
  QuIDCredential,
  SigninOptions,
  ComponentStyle,
  OAuthConfig,
  OAuthProvider,
  OAuthTokenResponse,
  QuIDEvent,
  QuIDEventType,
  QuIDSDKError,
  CreateIdentityRequest,
  WebAuthnCredentialCreationOptions,
  WebAuthnCredentialRequestOptions
} from './types';

export type {
  PublicKeyCredentialDescriptor,
  PublicKeyCredentialParameters,
  AuthenticatorSelectionCriteria,
  AttestationConveyancePreference,
  AuthenticatorTransport
} from './browser-types';

// Default export
export default QuIDClient;