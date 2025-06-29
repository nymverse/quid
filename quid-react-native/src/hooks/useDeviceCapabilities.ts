/**
 * React hook for device capabilities detection
 */

import { useEffect, useState, useCallback } from 'react';
import { QuIDClient } from '../QuIDClient';
import { DeviceCapabilities, UseDeviceCapabilitiesReturn } from '../types';

export function useDeviceCapabilities(client: QuIDClient | null): UseDeviceCapabilitiesReturn {
  const [capabilities, setCapabilities] = useState<DeviceCapabilities | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!client) return;

    try {
      setLoading(true);
      setError(null);
      
      const deviceCapabilities = await client.getDeviceCapabilities();
      setCapabilities(deviceCapabilities);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to get device capabilities');
    } finally {
      setLoading(false);
    }
  }, [client]);

  useEffect(() => {
    if (client) {
      refresh();
    }
  }, [client, refresh]);

  return {
    capabilities,
    loading,
    error,
    refresh,
  };
}