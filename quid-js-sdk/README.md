# QuID JavaScript SDK

Universal quantum-resistant authentication for web applications.

## Features

- 🔐 **Quantum-Resistant**: Uses ML-DSA signatures for post-quantum security
- 🌐 **Universal**: Works across all web frameworks and vanilla JavaScript
- 🔒 **WebAuthn Compatible**: Seamless replacement for WebAuthn APIs
- ⚡ **Easy Integration**: Simple components and hooks for React/Vue
- 🛡️ **Security First**: Built-in security policies and validation
- 📱 **Cross-Platform**: Browser extension integration with fallback support

## Quick Start

### Installation

```bash
npm install @quid/sdk
```

### Basic Usage

```javascript
import { QuIDClient, createSigninButton } from '@quid/sdk';

// Initialize QuID client
const quid = new QuIDClient();

// Create a signin button
createSigninButton('#signin-container', {
  onSuccess: (response) => {
    console.log('Authentication successful:', response);
  },
  onError: (error) => {
    console.error('Authentication failed:', error);
  }
});
```

### React Integration

```jsx
import { QuIDSigninButton, useQuID } from '@quid/sdk';

function App() {
  const { authenticate, identities, isReady } = useQuID();

  const handleSuccess = (response) => {
    console.log('Signed in:', response);
  };

  return (
    <div>
      <QuIDSigninButton 
        onSuccess={handleSuccess}
        buttonText="Sign in with QuID"
      />
      
      {isReady && (
        <p>Found {identities.length} identities</p>
      )}
    </div>
  );
}
```

### Vue Integration

```vue
<template>
  <div>
    <QuIDSigninButton 
      @success="handleSuccess"
      button-text="Sign in with QuID"
    />
  </div>
</template>

<script setup>
import { QuIDSigninButton } from '@quid/sdk/vue';

const handleSuccess = (response) => {
  console.log('Signed in:', response);
};
</script>
```

## API Reference

### QuIDClient

The main client for QuID authentication operations.

```javascript
const client = new QuIDClient({
  timeout: 60000,
  userVerification: 'preferred',
  debug: false
});
```

#### Methods

- `authenticate(options)` - Authenticate with QuID
- `getIdentities()` - Get available identities
- `createIdentity(config)` - Create a new identity
- `getStatus()` - Get connection status
- `updateConfig(config)` - Update configuration

### Components

#### QuIDSigninButton

Ready-to-use signin button component.

**Props:**
- `buttonText` - Button text (default: "Sign in with QuID")
- `style` - Custom styling object
- `userVerification` - Verification requirement
- `onSuccess` - Success callback
- `onError` - Error callback

#### useQuID Hook (React)

React hook for QuID integration.

```javascript
const {
  client,
  isReady,
  extensionAvailable,
  identities,
  authenticate,
  createIdentity
} = useQuID();
```

### OAuth Integration

QuID provides OAuth/OIDC integration for existing authentication systems.

```javascript
import { QuIDOAuthClient } from '@quid/sdk';

const oauth = new QuIDOAuthClient({
  clientId: 'your-client-id',
  redirectUri: 'https://yourapp.com/callback',
  scopes: ['openid', 'profile']
});

// Generate auth URL
const authUrl = oauth.generateAuthUrl();

// Handle callback
const { tokens, userInfo } = await oauth.handleCallback(callbackUrl);
```

## Browser Extension

For full functionality, install the QuID browser extension:

- [Chrome Web Store](https://chrome.google.com/webstore/detail/quid-universal-auth/...)
- [Firefox Add-ons](https://addons.mozilla.org/firefox/addon/quid-universal-auth/)

The SDK automatically detects and uses the extension when available, with WebAuthn fallback.

## Security

QuID uses quantum-resistant cryptography (ML-DSA) and follows security best practices:

- All authentication requests are validated
- HTTPS-only by default (configurable for development)
- Rate limiting and origin validation
- Secure challenge generation
- Memory-safe operations

## Examples

Check out the `/examples` directory for complete implementations:

- **Vanilla JavaScript**: Basic integration example
- **React**: Full-featured React application
- **Vue**: Complete Vue.js integration
- **OAuth**: Server-side OAuth integration

## Configuration

### QuIDConfig

```typescript
interface QuIDConfig {
  baseUrl?: string;              // QuID service URL
  timeout?: number;              // Request timeout (ms)
  userVerification?: string;     // 'required' | 'preferred' | 'discouraged'
  debug?: boolean;               // Enable debug logging
  extensionId?: string;          // Custom extension ID
  enableWebAuthnFallback?: boolean; // Enable WebAuthn fallback
}
```

### Component Styling

All components accept custom styling:

```javascript
createSigninButton('#container', {
  style: {
    width: '300px',
    height: '48px',
    backgroundColor: '#667eea',
    borderRadius: '8px',
    fontSize: '16px'
  }
});
```

## Development

### Building

```bash
npm install
npm run build
```

### Testing

```bash
npm test
npm run test:coverage
```

### Linting

```bash
npm run lint
npm run lint:fix
```

## Browser Support

- Chrome 70+
- Firefox 65+
- Safari 13+
- Edge 79+

WebAuthn fallback requires browsers with WebAuthn support.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Run tests and linting
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

- [Documentation](https://docs.quid.dev)
- [GitHub Issues](https://github.com/quid-dev/quid-js-sdk/issues)
- [Community Discord](https://discord.gg/quid)

---

**Made with ❤️ by the QuID Team**