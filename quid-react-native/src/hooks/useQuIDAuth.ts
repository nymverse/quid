/**
 * React hook for QuID authentication
 */

import { useState, useCallback } from 'react';
import { QuIDClient } from '../QuIDClient';
import { 
  AuthenticationRequest, 
  AuthenticationResponse, 
  UseQuIDAuthReturn,
} from '../types';

export function useQuIDAuth(client: QuIDClient | null): UseQuIDAuthReturn {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const authenticate = useCallback(async (request: AuthenticationRequest): Promise<AuthenticationResponse> => {
    if (!client) {
      throw new Error('QuID client not available');
    }

    try {
      setLoading(true);
      setError(null);
      
      const response = await client.authenticate(request);
      
      if (!response.success && response.error) {
        setError(response.error);
      }
      
      return response;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Authentication failed';
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
    }
  }, [client]);

  const authenticateQR = useCallback(async (request: any): Promise<any> => {
    if (!client) {
      throw new Error('QuID client not available');
    }

    try {
      setLoading(true);
      setError(null);
      
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

  return {
    authenticate,
    authenticateQR,
    loading,
    error,
  };
}