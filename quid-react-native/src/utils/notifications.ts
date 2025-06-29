/**
 * Push notification utility functions
 */

import { PushAuthRequest, PushAuthResponse } from '../types';

/**
 * Format push notification for authentication request
 */
export function formatAuthNotification(request: PushAuthRequest) {
  return {
    title: request.title || 'QuID Authentication Request',
    body: request.message || `Authentication request from ${request.origin}`,
    data: {
      type: 'quid-auth',
      requestId: request.requestId,
      challenge: request.challenge,
      origin: request.origin,
      userVerification: request.userVerification,
      expiresAt: request.expiresAt,
    },
    sound: 'default',
    badge: 1,
    priority: 'high',
    category: 'QUID_AUTH',
  };
}

/**
 * Parse authentication notification data
 */
export function parseAuthNotification(data: any): PushAuthRequest | null {
  try {
    if (data.type !== 'quid-auth') {
      return null;
    }

    return {
      requestId: data.requestId,
      challenge: data.challenge,
      origin: data.origin,
      title: data.title || 'QuID Authentication Request',
      message: data.message || `Authentication request from ${data.origin}`,
      userVerification: data.userVerification || 'preferred',
      expiresAt: data.expiresAt,
    };
  } catch {
    return null;
  }
}

/**
 * Check if notification is expired
 */
export function isNotificationExpired(request: PushAuthRequest): boolean {
  return Date.now() > request.expiresAt;
}

/**
 * Calculate time remaining for notification
 */
export function getTimeRemaining(expiresAt: number): number {
  return Math.max(0, expiresAt - Date.now());
}

/**
 * Format time remaining for display
 */
export function formatTimeRemaining(expiresAt: number): string {
  const remaining = getTimeRemaining(expiresAt);
  
  if (remaining === 0) {
    return 'Expired';
  }
  
  const seconds = Math.ceil(remaining / 1000);
  
  if (seconds < 60) {
    return `${seconds}s`;
  }
  
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  
  if (minutes < 60) {
    return remainingSeconds > 0 ? `${minutes}m ${remainingSeconds}s` : `${minutes}m`;
  }
  
  const hours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;
  
  return remainingMinutes > 0 ? `${hours}h ${remainingMinutes}m` : `${hours}h`;
}

/**
 * Generate notification action buttons
 */
export function getNotificationActions() {
  return [
    {
      id: 'approve',
      title: 'Approve',
      destructive: false,
      authenticationRequired: true,
    },
    {
      id: 'deny',
      title: 'Deny',
      destructive: true,
      authenticationRequired: false,
    },
  ];
}

/**
 * Handle notification action response
 */
export function handleNotificationAction(
  actionId: string,
  request: PushAuthRequest,
  authResponse?: any
): PushAuthResponse {
  const baseResponse: PushAuthResponse = {
    requestId: request.requestId,
    success: false,
  };

  if (isNotificationExpired(request)) {
    return {
      ...baseResponse,
      error: 'Authentication request expired',
    };
  }

  switch (actionId) {
    case 'approve':
      if (authResponse && authResponse.success) {
        return {
          ...baseResponse,
          success: true,
          response: authResponse.response,
        };
      } else {
        return {
          ...baseResponse,
          error: authResponse?.error || 'Authentication failed',
        };
      }
    
    case 'deny':
      return {
        ...baseResponse,
        error: 'User denied authentication request',
      };
    
    default:
      return {
        ...baseResponse,
        error: 'Unknown action',
      };
  }
}

/**
 * Create notification category for iOS
 */
export function createNotificationCategory() {
  return {
    id: 'QUID_AUTH',
    actions: getNotificationActions(),
    options: {
      customDismissAction: true,
      allowInCarPlay: false,
      allowAnnouncement: true,
    },
  };
}

/**
 * Create notification channel for Android
 */
export function createNotificationChannel() {
  return {
    id: 'quid-auth',
    name: 'QuID Authentication',
    description: 'Notifications for QuID authentication requests',
    importance: 4, // High importance
    sound: 'default',
    vibration: true,
    showBadge: true,
  };
}