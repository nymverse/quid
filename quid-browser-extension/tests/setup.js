/**
 * Jest setup file for QuID Browser Extension tests
 * Sets up global mocks and utilities for testing
 */

// Mock Chrome Extension APIs
global.chrome = {
  runtime: {
    sendMessage: jest.fn(),
    onMessage: {
      addListener: jest.fn()
    },
    getManifest: () => ({ version: '1.0.0' }),
    getURL: (path) => `chrome-extension://test/${path}`,
    connectNative: jest.fn().mockReturnValue({
      onMessage: { addListener: jest.fn() },
      onDisconnect: { addListener: jest.fn() },
      postMessage: jest.fn()
    }),
    openOptionsPage: jest.fn()
  },
  action: {
    setIcon: jest.fn(),
    setBadgeText: jest.fn(),
    setBadgeBackgroundColor: jest.fn(),
    onClicked: {
      addListener: jest.fn()
    }
  },
  tabs: {
    onUpdated: {
      addListener: jest.fn()
    },
    sendMessage: jest.fn(),
    create: jest.fn()
  },
  notifications: {
    create: jest.fn(),
    onButtonClicked: {
      addListener: jest.fn()
    },
    clear: jest.fn()
  },
  scripting: {
    executeScript: jest.fn()
  },
  webRequest: {
    onBeforeRequest: {
      addListener: jest.fn()
    }
  },
  storage: {
    local: {
      get: jest.fn(),
      set: jest.fn()
    }
  }
};

// Mock Web APIs
global.crypto = {
  getRandomValues: jest.fn((arr) => {
    for (let i = 0; i < arr.length; i++) {
      arr[i] = Math.floor(Math.random() * 256);
    }
    return arr;
  })
};

// Mock DOM APIs with proper Event interface
if (typeof global.CustomEvent === 'undefined') {
  global.CustomEvent = class CustomEvent {
    constructor(type, options = {}) {
      this.type = type;
      this.detail = options.detail;
      this.bubbles = options.bubbles || false;
      this.cancelable = options.cancelable || false;
    }
  };
}

global.MutationObserver = jest.fn().mockImplementation(() => ({
  observe: jest.fn(),
  disconnect: jest.fn()
}));

// Mock navigator with credentials API
global.navigator = {
  credentials: {
    create: jest.fn(),
    get: jest.fn()
  }
};

// Mock console to reduce noise in tests
global.console = {
  log: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  info: jest.fn(),
  debug: jest.fn()
};

// Mock fetch for API calls
global.fetch = jest.fn(() =>
  Promise.resolve({
    ok: true,
    json: () => Promise.resolve({}),
    text: () => Promise.resolve(''),
    status: 200,
    headers: new Map()
  })
);

// Setup fake timers for testing
// Note: Individual tests can override this if needed