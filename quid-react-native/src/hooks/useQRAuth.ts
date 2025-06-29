/**
 * React hook for QR code authentication
 */

import { useState, useCallback } from 'react';
import { QuIDClient } from '../QuIDClient';
import { QRCodeData, QRAuthRequest, QRAuthResponse } from '../types';

interface UseQRAuthReturn {
  scanQR: (qrString: string, identityId?: string) => Promise<QRAuthResponse>;
  generateQR: (challenge: string, origin: string, expirationMinutes?: number) => QRCodeData;
  loading: boolean;
  error: string | null;
}

export function useQRAuth(client: QuIDClient | null): UseQRAuthReturn {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const scanQR = useCallback(async (qrString: string, identityId?: string): Promise<QRAuthResponse> => {
    if (!client) {
      throw new Error('QuID client not available');
    }

    try {
      setLoading(true);
      setError(null);
      
      // Parse QR code data
      const qrData: QRCodeData = JSON.parse(qrString);
      
      // Validate QR code structure
      if (!qrData.challenge || !qrData.origin || !qrData.expiresAt) {
        throw new Error('Invalid QR code format');
      }

      const request: QRAuthRequest = {
        qrData,
        identityId,
      };
      
      const response = await client.authenticateQR(request);
      
      if (!response.success && response.error) {
        setError(response.error);
      }
      
      return response;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'QR authentication failed';
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
    }
  }, [client]);

  const generateQR = useCallback((
    challenge: string, 
    origin: string, 
    expirationMinutes: number = 5
  ): QRCodeData => {
    const now = Date.now();
    const expiresAt = now + (expirationMinutes * 60 * 1000);

    return {
      challenge,
      origin,
      timestamp: now,
      expiresAt,
      userVerification: 'preferred' as any,
      metadata: {
        version: '1.0',
        type: 'quid-auth',
      },
    };
  }, []);

  return {
    scanQR,
    generateQR,
    loading,
    error,
  };
}