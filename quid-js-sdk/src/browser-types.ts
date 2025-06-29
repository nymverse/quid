/**
 * Browser types for WebAuthn compatibility
 * Provides type definitions for browser APIs
 */

export interface PublicKeyCredentialDescriptor {
  type: 'public-key';
  id: ArrayBuffer;
  transports?: AuthenticatorTransport[];
}

export interface PublicKeyCredentialParameters {
  type: 'public-key';
  alg: number;
}

export interface AuthenticatorSelectionCriteria {
  authenticatorAttachment?: 'platform' | 'cross-platform';
  requireResidentKey?: boolean;
  residentKey?: 'discouraged' | 'preferred' | 'required';
  userVerification?: 'required' | 'preferred' | 'discouraged';
}

export type AttestationConveyancePreference = 'none' | 'indirect' | 'direct' | 'enterprise';

export type AuthenticatorTransport = 'usb' | 'nfc' | 'ble' | 'internal';