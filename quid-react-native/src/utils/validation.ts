/**
 * Validation utility functions
 */

import { 
  QuIDConfig, 
  CreateIdentityRequest, 
  AuthenticationRequest, 
  QRCodeData,
  SecurityLevel,
  UserVerification,
} from '../types';

/**
 * Validate QuID configuration
 */
export function validateConfig(config: Partial<QuIDConfig>): string[] {
  const errors: string[] = [];

  if (config.timeout !== undefined) {
    if (config.timeout < 1000 || config.timeout > 300000) {
      errors.push('Timeout must be between 1 second and 5 minutes');
    }
  }

  if (config.securityLevel !== undefined) {
    if (!Object.values(SecurityLevel).includes(config.securityLevel)) {
      errors.push('Invalid security level');
    }
  }

  return errors;
}

/**
 * Validate create identity request
 */
export function validateCreateIdentityRequest(request: CreateIdentityRequest): string[] {
  const errors: string[] = [];

  if (!request.name || typeof request.name !== 'string') {
    errors.push('Identity name is required and must be a string');
  } else if (request.name.trim().length === 0) {
    errors.push('Identity name cannot be empty');
  } else if (request.name.length > 100) {
    errors.push('Identity name must be 100 characters or less');
  }

  if (request.securityLevel !== undefined) {
    if (!Object.values(SecurityLevel).includes(request.securityLevel)) {
      errors.push('Invalid security level');
    }
  }

  if (request.networks !== undefined) {
    if (!Array.isArray(request.networks)) {
      errors.push('Networks must be an array');
    } else if (request.networks.length === 0) {
      errors.push('At least one network must be specified');
    } else {
      for (const network of request.networks) {
        if (typeof network !== 'string' || network.trim().length === 0) {
          errors.push('All network names must be non-empty strings');
          break;
        }
      }
    }
  }

  if (request.requireBiometrics !== undefined) {
    if (typeof request.requireBiometrics !== 'boolean') {
      errors.push('requireBiometrics must be a boolean');
    }
  }

  if (request.metadata !== undefined) {
    if (typeof request.metadata !== 'object' || request.metadata === null) {
      errors.push('Metadata must be an object');
    } else {
      for (const [key, value] of Object.entries(request.metadata)) {
        if (typeof key !== 'string' || typeof value !== 'string') {
          errors.push('All metadata keys and values must be strings');
          break;
        }
      }
    }
  }

  return errors;
}

/**
 * Validate authentication request
 */
export function validateAuthenticationRequest(request: AuthenticationRequest): string[] {
  const errors: string[] = [];

  if (!request.origin || typeof request.origin !== 'string') {
    errors.push('Origin is required and must be a string');
  } else if (!isValidOrigin(request.origin)) {
    errors.push('Origin must be a valid URL or domain');
  }

  if (request.challenge !== undefined) {
    if (typeof request.challenge !== 'string') {
      errors.push('Challenge must be a string');
    } else if (!isValidChallenge(request.challenge)) {
      errors.push('Challenge must be a valid hex string');
    }
  }

  if (request.identityId !== undefined) {
    if (typeof request.identityId !== 'string' || request.identityId.trim().length === 0) {
      errors.push('Identity ID must be a non-empty string');
    }
  }

  if (request.userVerification !== undefined) {
    if (!Object.values(UserVerification).includes(request.userVerification)) {
      errors.push('Invalid user verification level');
    }
  }

  if (request.timeout !== undefined) {
    if (typeof request.timeout !== 'number' || request.timeout < 1000 || request.timeout > 300000) {
      errors.push('Timeout must be a number between 1 second and 5 minutes');
    }
  }

  return errors;
}

/**
 * Validate QR code data
 */
export function validateQRCodeData(data: QRCodeData): string[] {
  const errors: string[] = [];

  if (!data.challenge || typeof data.challenge !== 'string') {
    errors.push('Challenge is required and must be a string');
  } else if (!isValidChallenge(data.challenge)) {
    errors.push('Challenge must be a valid hex string');
  }

  if (!data.origin || typeof data.origin !== 'string') {
    errors.push('Origin is required and must be a string');
  } else if (!isValidOrigin(data.origin)) {
    errors.push('Origin must be a valid URL or domain');
  }

  if (typeof data.timestamp !== 'number') {
    errors.push('Timestamp must be a number');
  } else if (data.timestamp > Date.now()) {
    errors.push('Timestamp cannot be in the future');
  }

  if (typeof data.expiresAt !== 'number') {
    errors.push('ExpiresAt must be a number');
  } else if (data.expiresAt <= data.timestamp) {
    errors.push('ExpiresAt must be after timestamp');
  } else if (data.expiresAt <= Date.now()) {
    errors.push('QR code has expired');
  }

  if (!Object.values(UserVerification).includes(data.userVerification)) {
    errors.push('Invalid user verification level');
  }

  return errors;
}

/**
 * Check if a string is a valid origin (URL or domain)
 */
export function isValidOrigin(origin: string): boolean {
  try {
    // Try to parse as URL
    new URL(origin);
    return true;
  } catch {
    // Check if it's a valid domain
    const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    return domainRegex.test(origin);
  }
}

/**
 * Check if a string is a valid hex challenge
 */
export function isValidChallenge(challenge: string): boolean {
  const hexRegex = /^[0-9a-fA-F]+$/;
  return hexRegex.test(challenge) && challenge.length >= 16 && challenge.length % 2 === 0;
}

/**
 * Check if an identity name is valid
 */
export function isValidIdentityName(name: string): boolean {
  return typeof name === 'string' && 
         name.trim().length > 0 && 
         name.length <= 100 &&
         !/[<>:"/\\|?*]/.test(name); // No invalid filename characters
}

/**
 * Check if a network name is valid
 */
export function isValidNetworkName(network: string): boolean {
  return typeof network === 'string' && 
         network.trim().length > 0 && 
         network.length <= 50 &&
         /^[a-zA-Z0-9-_]+$/.test(network); // Only alphanumeric, dash, underscore
}

/**
 * Sanitize input string
 */
export function sanitizeInput(input: string): string {
  return input.trim().replace(/[<>:"/\\|?*]/g, '');
}

/**
 * Check if two objects are equal (shallow comparison)
 */
export function isEqual(obj1: any, obj2: any): boolean {
  if (obj1 === obj2) return true;
  
  if (obj1 == null || obj2 == null) return false;
  
  if (typeof obj1 !== typeof obj2) return false;
  
  if (typeof obj1 !== 'object') return obj1 === obj2;
  
  const keys1 = Object.keys(obj1);
  const keys2 = Object.keys(obj2);
  
  if (keys1.length !== keys2.length) return false;
  
  for (const key of keys1) {
    if (!keys2.includes(key)) return false;
    if (obj1[key] !== obj2[key]) return false;
  }
  
  return true;
}