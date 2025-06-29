/**
 * QuID Client Tests
 */

import { QuIDClient } from '../src/core/quid-client';
import { QuIDConfig } from '../src/types';

describe('QuIDClient', () => {
  let client: QuIDClient;

  beforeEach(() => {
    jest.clearAllMocks();
  });

  afterEach(() => {
    if (client) {
      client.disconnect();
    }
  });

  test('should initialize with default config', () => {
    client = new QuIDClient();
    expect(client).toBeInstanceOf(QuIDClient);
    expect(client.ready).toBe(false);
  });

  test('should initialize with custom config', () => {
    const config: QuIDConfig = {
      timeout: 30000,
      userVerification: 'required',
      debug: true
    };

    client = new QuIDClient(config);
    expect(client).toBeInstanceOf(QuIDClient);
  });

  test('should emit ready event when initialized', (done) => {
    client = new QuIDClient();
    
    client.on((event) => {
      if (event.type === 'ready') {
        expect(client.ready).toBe(true);
        done();
      }
    });
  });

  test('should handle authentication request', async () => {
    client = new QuIDClient();
    
    // Wait for ready
    await new Promise((resolve) => {
      client.on((event) => {
        if (event.type === 'ready') resolve(undefined);
      });
    });

    const response = await client.authenticate({
      challenge: 'test-challenge'
    });

    expect(response).toHaveProperty('success');
  });

  test('should generate challenge when not provided', async () => {
    client = new QuIDClient();
    
    // Wait for ready
    await new Promise((resolve) => {
      client.on((event) => {
        if (event.type === 'ready') resolve(undefined);
      });
    });

    const response = await client.authenticate();
    expect(response).toHaveProperty('success');
  });

  test('should get status', async () => {
    client = new QuIDClient();
    
    // Wait for ready
    await new Promise((resolve) => {
      client.on((event) => {
        if (event.type === 'ready') resolve(undefined);
      });
    });

    const status = await client.getStatus();
    expect(status).toHaveProperty('ready');
    expect(status).toHaveProperty('extensionAvailable');
    expect(status).toHaveProperty('identityCount');
    expect(status).toHaveProperty('version');
  });

  test('should update config', () => {
    client = new QuIDClient();
    
    client.updateConfig({
      timeout: 45000,
      debug: true
    });

    // Config should be updated internally
    expect(client).toBeInstanceOf(QuIDClient);
  });

  test('should handle errors gracefully', async () => {
    client = new QuIDClient();

    // Test error handling when not ready
    try {
      await client.getIdentities();
    } catch (error) {
      expect(error).toBeInstanceOf(Error);
    }
  });

  test('should disconnect properly', () => {
    client = new QuIDClient();
    
    expect(() => {
      client.disconnect();
    }).not.toThrow();
  });
});