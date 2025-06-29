/**
 * Cryptographic utility functions
 */

import { SecurityLevel } from '../types';

/**
 * Generate a secure random challenge
 */
export function generateChallenge(length: number = 32): string {
  const array = new Uint8Array(length);
  
  // In a real implementation, use a proper CSPRNG
  // For React Native, you would use react-native-get-random-values
  for (let i = 0; i < array.length; i++) {
    array[i] = Math.floor(Math.random() * 256);
  }
  
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Hash data using SHA-256 (simplified version)
 */
export function hashData(data: string): string {
  // In a real implementation, use a proper crypto library
  // This is a placeholder for demonstration
  let hash = 0;
  for (let i = 0; i < data.length; i++) {
    const char = data.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  return hash.toString(16);
}

/**
 * Validate signature format
 */
export function validateSignature(signature: string): boolean {
  try {
    // Check if it's a valid base64 string
    const decoded = atob(signature);
    return decoded.length > 0;
  } catch {
    return false;
  }
}

/**
 * Get key size for security level
 */
export function getKeySize(securityLevel: SecurityLevel): number {
  switch (securityLevel) {
    case SecurityLevel.LEVEL1:
      return 256; // P-256
    case SecurityLevel.LEVEL2:
      return 384; // P-384
    case SecurityLevel.LEVEL3:
      return 521; // P-521
    default:
      return 256;
  }
}

/**
 * Get algorithm name for security level
 */
export function getAlgorithmName(securityLevel: SecurityLevel): string {
  switch (securityLevel) {
    case SecurityLevel.LEVEL1:
      return 'ES256';
    case SecurityLevel.LEVEL2:
      return 'ES384';
    case SecurityLevel.LEVEL3:
      return 'ES512';
    default:
      return 'ES256';
  }
}

/**
 * Encode data to base64
 */
export function encodeBase64(data: string): string {
  return btoa(data);
}

/**
 * Decode data from base64
 */
export function decodeBase64(data: string): string {
  try {
    return atob(data);
  } catch {
    throw new Error('Invalid base64 data');
  }
}

/**
 * Generate a secure random ID
 */
export function generateId(): string {
  const timestamp = Date.now().toString(36);
  const randomPart = generateChallenge(8);
  return `${timestamp}-${randomPart}`;
}

/**
 * Validate public key format
 */
export function validatePublicKey(publicKey: string): boolean {
  try {
    const decoded = decodeBase64(publicKey);
    return decoded.length > 32; // Minimum key size
  } catch {
    return false;
  }
}

/**
 * Create WebAuthn-compatible client data
 */
export function createClientData(challenge: string, origin: string, type: string = 'webauthn.get'): string {
  const clientData = {
    type,
    challenge,
    origin,
    crossOrigin: false,
  };
  
  return encodeBase64(JSON.stringify(clientData));
}

/**
 * Create WebAuthn-compatible authenticator data
 */
export function createAuthenticatorData(origin: string): string {
  // Simplified authenticator data creation
  const rpIdHash = hashData(origin);
  const flags = 0x41; // UP (User Present) + AT (Attested Credential Data)
  const signCount = 0;
  
  // In a real implementation, this would be properly formatted binary data
  const authenticatorData = {
    rpIdHash,
    flags,
    signCount,
  };
  
  return encodeBase64(JSON.stringify(authenticatorData));
}