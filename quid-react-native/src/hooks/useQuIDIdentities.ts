/**
 * React hook for QuID identity management
 */

import { useEffect, useState, useCallback } from 'react';
import { QuIDClient } from '../QuIDClient';
import { 
  QuIDIdentity, 
  CreateIdentityRequest, 
  UseQuIDIdentitiesReturn,
  QuIDEvent,
  QuIDEventType,
} from '../types';

export function useQuIDIdentities(client: QuIDClient | null): UseQuIDIdentitiesReturn {
  const [identities, setIdentities] = useState<QuIDIdentity[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!client) return;

    try {
      setLoading(true);
      setError(null);
      
      const fetchedIdentities = await client.getIdentities();
      setIdentities(fetchedIdentities);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch identities');
    } finally {
      setLoading(false);
    }
  }, [client]);

  const createIdentity = useCallback(async (request: CreateIdentityRequest): Promise<QuIDIdentity> => {
    if (!client) {
      throw new Error('QuID client not available');
    }

    try {
      setLoading(true);
      setError(null);
      
      const newIdentity = await client.createIdentity(request);
      setIdentities(prev => [...prev, newIdentity]);
      
      return newIdentity;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to create identity';
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
    }
  }, [client]);

  const deleteIdentity = useCallback(async (id: string): Promise<void> => {
    if (!client) {
      throw new Error('QuID client not available');
    }

    try {
      setLoading(true);
      setError(null);
      
      await client.deleteIdentity(id);
      setIdentities(prev => prev.filter(identity => identity.id !== id));
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to delete identity';
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
    }
  }, [client]);

  // Initial load and event listeners
  useEffect(() => {
    if (!client) return;

    // Load identities on mount
    refresh();

    // Listen for identity events
    const handleIdentityCreated = (event: QuIDEvent) => {
      if (event.data.identity) {
        setIdentities(prev => {
          const exists = prev.some(id => id.id === event.data.identity.id);
          return exists ? prev : [...prev, event.data.identity];
        });
      }
    };

    const handleIdentityDeleted = (event: QuIDEvent) => {
      if (event.data.identity) {
        setIdentities(prev => prev.filter(id => id.id !== event.data.identity.id));
      }
    };

    client.addEventListener(QuIDEventType.IDENTITY_CREATED, handleIdentityCreated);
    client.addEventListener(QuIDEventType.IDENTITY_DELETED, handleIdentityDeleted);

    // Cleanup
    return () => {
      client.removeEventListener(QuIDEventType.IDENTITY_CREATED, handleIdentityCreated);
      client.removeEventListener(QuIDEventType.IDENTITY_DELETED, handleIdentityDeleted);
    };
  }, [client, refresh]);

  return {
    identities,
    loading,
    error,
    refresh,
    createIdentity,
    deleteIdentity,
  };
}