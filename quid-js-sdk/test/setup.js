/**
 * Jest setup for QuID JavaScript SDK tests
 */

// Mock browser APIs
global.crypto = {
  getRandomValues: jest.fn((arr) => {
    for (let i = 0; i < arr.length; i++) {
      arr[i] = Math.floor(Math.random() * 256);
    }
    return arr;
  }),
  subtle: {
    digest: jest.fn().mockResolvedValue(new ArrayBuffer(32))
  }
};

// Mock navigator
global.navigator = {
  credentials: {
    create: jest.fn(),
    get: jest.fn()
  }
};

// Mock window
global.window = {
  location: {
    origin: 'https://example.com',
    hostname: 'example.com'
  },
  chrome: {
    runtime: {
      sendMessage: jest.fn(),
      getURL: jest.fn((path) => `chrome-extension://test/${path}`)
    }
  },
  addEventListener: jest.fn(),
  removeEventListener: jest.fn(),
  dispatchEvent: jest.fn(),
  CustomEvent: jest.fn((type, options) => ({
    type,
    detail: options?.detail
  }))
};

// Mock fetch
global.fetch = jest.fn(() =>
  Promise.resolve({
    ok: true,
    json: () => Promise.resolve({}),
    text: () => Promise.resolve('')
  })
);

// Mock console methods
global.console = {
  ...console,
  debug: jest.fn(),
  log: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn()
};