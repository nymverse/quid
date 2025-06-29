/**
 * useQuID React Hook
 * React hook for QuID authentication
 */

import { useEffect, useState, useCallback, useRef } from 'react';
import { QuIDClient } from '../../core/quid-client';
import {
  QuIDConfig,
  QuIDIdentity,
  AuthenticationRequest,
  AuthenticationResponse,
  CreateIdentityRequest,
  QuIDEvent
} from '../../types';

export interface UseQuIDOptions extends QuIDConfig {
  /** Auto-initialize the client */
  autoInit?: boolean;
}

export interface UseQuIDReturn {
  /** QuID client instance */
  client: QuIDClient | null;
  /** Whether QuID is ready */
  isReady: boolean;
  /** Whether QuID extension is available */
  extensionAvailable: boolean;
  /** Loading state */
  isLoading: boolean;
  /** Error state */
  error: Error | null;
  /** Available identities */
  identities: QuIDIdentity[];
  /** Authenticate with QuID */
  authenticate: (request?: Partial<AuthenticationRequest>) => Promise<AuthenticationResponse>;
  /** Create a new identity */
  createIdentity: (request: CreateIdentityRequest) => Promise<QuIDIdentity>;
  /** Refresh identities */
  refreshIdentities: () => Promise<void>;
  /** Get status */
  getStatus: () => Promise<{
    ready: boolean;
    extensionAvailable: boolean;
    identityCount: number;
    version: string;
  }>;
  /** Clear error */
  clearError: () => void;
}

/**
 * useQuID Hook
 */
export function useQuID(options: UseQuIDOptions = {}): UseQuIDReturn {
  const { autoInit = true, ...config } = options;
  
  const clientRef = useRef<QuIDClient | null>(null);
  const [isReady, setIsReady] = useState(false);
  const [extensionAvailable, setExtensionAvailable] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [identities, setIdentities] = useState<QuIDIdentity[]>([]);

  // Initialize client
  useEffect(() => {
    if (!autoInit) return;

    const initClient = async () => {
      try {
        setIsLoading(true);
        setError(null);

        clientRef.current = new QuIDClient(config);

        // Set up event listeners
        const unsubscribe = clientRef.current.on((event: QuIDEvent) => {
          switch (event.type) {
            case 'ready':
              setIsReady(true);
              setExtensionAvailable(clientRef.current?.extensionAvailable || false);
              break;
            case 'extension-connected':
              setExtensionAvailable(true);
              break;
            case 'extension-disconnected':
              setExtensionAvailable(false);
              break;
            case 'error':
              setError(event.data);
              break;
          }
        });

        // Cleanup function
        return unsubscribe;

      } catch (err) {
        setError(err instanceof Error ? err : new Error('Failed to initialize QuID'));
      } finally {
        setIsLoading(false);
      }
    };

    const cleanup = initClient();

    return () => {
      cleanup.then(unsubscribe => unsubscribe?.());
      if (clientRef.current) {
        clientRef.current.disconnect();
        clientRef.current = null;
      }
    };
  }, [autoInit, config]);

  // Load identities when ready
  useEffect(() => {
    if (isReady && extensionAvailable) {
      refreshIdentities();
    }
  }, [isReady, extensionAvailable]);

  const authenticate = useCallback(async (request: Partial<AuthenticationRequest> = {}): Promise<AuthenticationResponse> => {
    if (!clientRef.current) {
      throw new Error('QuID client not initialized');
    }

    setIsLoading(true);
    setError(null);

    try {
      const response = await clientRef.current.authenticate(request);
      return response;
    } catch (err) {
      const error = err instanceof Error ? err : new Error('Authentication failed');
      setError(error);
      return {
        success: false,
        error: error.message
      };
    } finally {
      setIsLoading(false);
    }
  }, []);

  const createIdentity = useCallback(async (request: CreateIdentityRequest): Promise<QuIDIdentity> => {
    if (!clientRef.current) {
      throw new Error('QuID client not initialized');
    }

    setIsLoading(true);
    setError(null);

    try {
      const identity = await clientRef.current.createIdentity(request);
      
      // Refresh identities list
      await refreshIdentities();
      
      return identity;
    } catch (err) {
      const error = err instanceof Error ? err : new Error('Failed to create identity');
      setError(error);
      throw error;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const refreshIdentities = useCallback(async (): Promise<void> => {
    if (!clientRef.current || !extensionAvailable) {
      setIdentities([]);
      return;
    }

    try {
      const identityList = await clientRef.current.getIdentities();
      setIdentities(identityList);
    } catch (err) {
      console.warn('Failed to refresh identities:', err);
      setIdentities([]);
    }
  }, [extensionAvailable]);

  const getStatus = useCallback(async () => {
    if (!clientRef.current) {
      return {
        ready: false,
        extensionAvailable: false,
        identityCount: 0,
        version: '1.0.0'
      };
    }

    return await clientRef.current.getStatus();
  }, []);

  const clearError = useCallback(() => {
    setError(null);
  }, []);

  return {
    client: clientRef.current,
    isReady,
    extensionAvailable,
    isLoading,
    error,
    identities,
    authenticate,
    createIdentity,
    refreshIdentities,
    getStatus,
    clearError
  };
}

export default useQuID;