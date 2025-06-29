/**
 * React hook for QuID client management
 */

import { useEffect, useState, useRef } from 'react';
import { QuIDClient } from '../QuIDClient';
import { QuIDConfig } from '../types';

interface UseQuIDClientReturn {
  client: QuIDClient | null;
  isReady: boolean;
  error: string | null;
}

export function useQuIDClient(config?: Partial<QuIDConfig>): UseQuIDClientReturn {
  const [client, setClient] = useState<QuIDClient | null>(null);
  const [isReady, setIsReady] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const configRef = useRef(config);

  useEffect(() => {
    configRef.current = config;
  }, [config]);

  useEffect(() => {
    let mounted = true;

    const initializeClient = async () => {
      try {
        setError(null);
        
        // Check if QuID is available on this device
        const isAvailable = await QuIDClient.isAvailable();
        if (!isAvailable) {
          throw new Error('QuID is not available on this device');
        }

        // Create client instance
        const newClient = new QuIDClient(configRef.current);
        
        if (mounted) {
          setClient(newClient);
          setIsReady(true);
        }
      } catch (err) {
        if (mounted) {
          setError(err instanceof Error ? err.message : 'Failed to initialize QuID client');
          setIsReady(false);
        }
      }
    };

    initializeClient();

    return () => {
      mounted = false;
    };
  }, []);

  return {
    client,
    isReady,
    error,
  };
}