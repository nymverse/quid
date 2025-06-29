# QuID React Native SDK

A comprehensive React Native SDK for quantum-resistant authentication using QuID technology.

## Features

- **Quantum-Resistant Authentication**: Uses ML-DSA signatures for future-proof security
- **Hardware Security**: Integrates with iOS Secure Enclave and Android TEE
- **Biometric Integration**: Supports Touch ID, Face ID, and Android biometrics
- **QR Code Authentication**: Seamless cross-device authentication flows
- **Push Notifications**: Real-time authentication requests
- **Identity Management**: Create, manage, and backup quantum-resistant identities
- **React Hooks**: Easy-to-use hooks for React Native development
- **TypeScript**: Full TypeScript support with comprehensive type definitions

## Installation

```bash
npm install @quid/react-native

# For iOS
cd ios && pod install

# For Android, add to android/settings.gradle:
include ':@quid_react-native'
project(':@quid_react-native').projectDir = new File(rootProject.projectDir, '../node_modules/@quid/react-native/android')
```

## Quick Start

### 1. Initialize QuID Client

```typescript
import { useQuIDClient } from '@quid/react-native';

function App() {
  const { client, isReady, error } = useQuIDClient({
    securityLevel: SecurityLevel.LEVEL1,
    requireBiometrics: true,
    timeout: 60000,
    debugMode: __DEV__,
  });

  if (!isReady) {
    return <LoadingScreen />;
  }

  if (error) {
    return <ErrorScreen error={error} />;
  }

  return <MainApp client={client} />;
}
```

### 2. Manage Identities

```typescript
import { useQuIDIdentities } from '@quid/react-native';

function IdentityManager({ client }) {
  const { identities, loading, createIdentity, deleteIdentity } = useQuIDIdentities(client);

  const handleCreateIdentity = async () => {
    try {
      const identity = await createIdentity({
        name: 'My Identity',
        securityLevel: SecurityLevel.LEVEL1,
        networks: ['mobile', 'web'],
        requireBiometrics: true,
      });
      console.log('Identity created:', identity);
    } catch (error) {
      console.error('Failed to create identity:', error);
    }
  };

  return (
    <View>
      <Button title="Create Identity" onPress={handleCreateIdentity} />
      <QuIDIdentityList 
        identities={identities}
        onDelete={deleteIdentity}
      />
    </View>
  );
}
```

### 3. Authenticate

```typescript
import { useQuIDAuth } from '@quid/react-native';

function AuthenticationScreen({ client }) {
  const { authenticate, loading } = useQuIDAuth(client);

  const handleAuthenticate = async () => {
    try {
      const response = await authenticate({
        origin: 'example.com',
        userVerification: UserVerification.PREFERRED,
      });
      
      if (response.success) {
        console.log('Authentication successful:', response.credential);
      } else {
        console.error('Authentication failed:', response.error);
      }
    } catch (error) {
      console.error('Authentication error:', error);
    }
  };

  return (
    <QuIDSignInButton
      client={client}
      origin="example.com"
      onSuccess={(response) => console.log('Success:', response)}
      onError={(error) => console.error('Error:', error)}
    />
  );
}
```

### 4. QR Code Authentication

```typescript
import { useQRAuth } from '@quid/react-native';
import { QuIDQRScanner, QuIDQRGenerator } from '@quid/react-native';

function QRAuthScreen({ client }) {
  const { scanQR, generateQR, loading } = useQRAuth(client);

  const handleQRScan = async (qrData) => {
    try {
      const response = await scanQR(JSON.stringify(qrData));
      if (response.success) {
        console.log('QR Authentication successful');
      }
    } catch (error) {
      console.error('QR Authentication failed:', error);
    }
  };

  const qrData = generateQR('challenge123', 'example.com', 5);

  return (
    <View>
      <Text>Scan QR Code:</Text>
      <QuIDQRScanner
        onScan={handleQRScan}
        onError={(error) => console.error(error)}
      />
      
      <Text>Or show this QR Code:</Text>
      <QuIDQRGenerator data={qrData} size={200} />
    </View>
  );
}
```

## API Reference

### Hooks

#### `useQuIDClient(config?)`
Initializes and manages the QuID client instance.

**Parameters:**
- `config` (optional): QuID configuration object

**Returns:**
- `client`: QuID client instance
- `isReady`: Boolean indicating if client is ready
- `error`: Error message if initialization failed

#### `useQuIDIdentities(client)`
Manages QuID identities.

**Returns:**
- `identities`: Array of QuID identities
- `loading`: Boolean indicating if operation is in progress
- `error`: Error message if any
- `refresh`: Function to refresh identities list
- `createIdentity`: Function to create new identity
- `deleteIdentity`: Function to delete identity

#### `useQuIDAuth(client)`
Handles authentication operations.

**Returns:**
- `authenticate`: Function to perform authentication
- `authenticateQR`: Function to authenticate via QR code
- `loading`: Boolean indicating if authentication is in progress
- `error`: Error message if any

#### `useDeviceCapabilities(client)`
Gets device security capabilities.

**Returns:**
- `capabilities`: Device capabilities object
- `loading`: Boolean indicating if loading
- `error`: Error message if any
- `refresh`: Function to refresh capabilities

#### `useQRAuth(client)`
Handles QR code authentication.

**Returns:**
- `scanQR`: Function to scan and authenticate QR code
- `generateQR`: Function to generate QR code data
- `loading`: Boolean indicating if operation is in progress
- `error`: Error message if any

### Components

#### `QuIDSignInButton`
A button component for QuID authentication.

**Props:**
- `client`: QuID client instance
- `onSuccess`: Callback for successful authentication
- `onError`: Callback for authentication error
- `origin`: Origin domain/URL
- `challenge?`: Optional challenge string
- `identityId?`: Optional specific identity ID
- `userVerification?`: User verification level
- `style?`: Custom styles
- `title?`: Button title text
- `disabled?`: Whether button is disabled

#### `QuIDQRScanner`
A QR code scanner component for authentication.

**Props:**
- `onScan`: Callback when valid QR code is scanned
- `onError`: Callback for scan errors
- `style?`: Custom styles
- `overlayColor?`: Overlay color
- `borderColor?`: Scanner border color

#### `QuIDQRGenerator`
A QR code generator component.

**Props:**
- `data`: QR code data object
- `size?`: QR code size (default: 200)
- `color?`: QR code color (default: black)
- `backgroundColor?`: Background color (default: white)
- `logo?`: Optional logo image
- `style?`: Custom styles

#### `QuIDIdentityList`
A list component for displaying identities.

**Props:**
- `identities`: Array of identities to display
- `onSelect?`: Callback when identity is selected
- `onDelete?`: Callback when identity is deleted
- `style?`: Custom styles
- `itemStyle?`: Custom item styles
- `showDetails?`: Whether to show identity details

## Security Features

### Hardware Security Integration

- **iOS**: Secure Enclave integration for hardware-backed key storage
- **Android**: Trusted Execution Environment (TEE) support
- **Key Protection**: Private keys never leave secure hardware

### Biometric Authentication

- **iOS**: Touch ID and Face ID support
- **Android**: Fingerprint and face recognition
- **Fallback**: Device passcode as fallback option

### Quantum Resistance

- **ML-DSA Signatures**: NIST-approved post-quantum cryptography
- **Algorithm Agility**: Support for multiple security levels
- **Future-Proof**: Ready for quantum computing threats

## Platform Requirements

### iOS
- iOS 13.0 or later
- Device with Secure Enclave (iPhone 5s or later)
- Biometric hardware (optional but recommended)

### Android
- Android API level 23 (Android 6.0) or later
- Hardware security module (HSM) or TEE support
- Biometric hardware (optional but recommended)

## Development

### Building

```bash
npm run build
```

### Testing

```bash
npm test
```

### Linting

```bash
npm run lint
```

### Type Checking

```bash
npm run typecheck
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

- Documentation: [QuID Docs](https://docs.quid.dev)
- Issues: [GitHub Issues](https://github.com/nym-corp/quid/issues)
- Security: security@quid.dev