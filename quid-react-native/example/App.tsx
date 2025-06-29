/**
 * QuID React Native Example App
 */

import React, { useState } from 'react';
import {
  SafeAreaView,
  ScrollView,
  StatusBar,
  StyleSheet,
  Text,
  View,
  Alert,
  Button,
} from 'react-native';

import {
  useQuIDClient,
  useQuIDIdentities,
  useQuIDAuth,
  useDeviceCapabilities,
  QuIDSignInButton,
  QuIDIdentityList,
  QuIDQRGenerator,
  SecurityLevel,
  UserVerification,
} from '@quid/react-native';

function App(): JSX.Element {
  const { client, isReady, error } = useQuIDClient({
    securityLevel: SecurityLevel.LEVEL1,
    requireBiometrics: true,
    timeout: 60000,
    debugMode: true,
  });

  if (error) {
    return (
      <SafeAreaView style={styles.container}>
        <View style={styles.center}>
          <Text style={styles.error}>Error: {error}</Text>
        </View>
      </SafeAreaView>
    );
  }

  if (!isReady) {
    return (
      <SafeAreaView style={styles.container}>
        <View style={styles.center}>
          <Text>Initializing QuID...</Text>
        </View>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="dark-content" />
      <QuIDApp client={client} />
    </SafeAreaView>
  );
}

function QuIDApp({ client }: { client: any }) {
  const { identities, loading, createIdentity, deleteIdentity } = useQuIDIdentities(client);
  const { authenticate } = useQuIDAuth(client);
  const { capabilities } = useDeviceCapabilities(client);
  const [currentView, setCurrentView] = useState<'identities' | 'auth' | 'qr' | 'capabilities'>('identities');

  const handleCreateIdentity = async () => {
    try {
      await createIdentity({
        name: `Identity ${identities.length + 1}`,
        securityLevel: SecurityLevel.LEVEL1,
        networks: ['mobile', 'example'],
        requireBiometrics: true,
      });
      Alert.alert('Success', 'Identity created successfully');
    } catch (error) {
      Alert.alert('Error', `Failed to create identity: ${error}`);
    }
  };

  const handleAuthenticate = async () => {
    try {
      const response = await authenticate({
        origin: 'example.com',
        userVerification: UserVerification.PREFERRED,
      });
      
      if (response.success) {
        Alert.alert('Success', 'Authentication successful');
      } else {
        Alert.alert('Failed', response.error || 'Authentication failed');
      }
    } catch (error) {
      Alert.alert('Error', `Authentication error: ${error}`);
    }
  };

  const generateQRData = () => {
    const now = Date.now();
    return {
      challenge: 'example-challenge-' + now,
      origin: 'example.com',
      timestamp: now,
      expiresAt: now + 5 * 60 * 1000, // 5 minutes
      userVerification: UserVerification.PREFERRED,
      metadata: {
        version: '1.0',
        type: 'quid-auth',
      },
    };
  };

  const renderCurrentView = () => {
    switch (currentView) {
      case 'identities':
        return (
          <View style={styles.content}>
            <Text style={styles.title}>Identities ({identities.length})</Text>
            <Button title="Create Identity" onPress={handleCreateIdentity} disabled={loading} />
            <QuIDIdentityList
              identities={identities}
              onDelete={deleteIdentity}
              style={styles.identityList}
            />
          </View>
        );
      
      case 'auth':
        return (
          <View style={styles.content}>
            <Text style={styles.title}>Authentication</Text>
            <QuIDSignInButton
              client={client}
              origin="example.com"
              onSuccess={() => Alert.alert('Success', 'Authenticated!')}
              onError={(error) => Alert.alert('Error', error)}
              style={styles.authButton}
            />
            <Button title="Test Authentication" onPress={handleAuthenticate} />
          </View>
        );
      
      case 'qr':
        return (
          <View style={styles.content}>
            <Text style={styles.title}>QR Code Authentication</Text>
            <QuIDQRGenerator
              data={generateQRData()}
              size={200}
              style={styles.qrCode}
            />
            <Text style={styles.subtitle}>Scan this QR code with another device</Text>
          </View>
        );
      
      case 'capabilities':
        return (
          <View style={styles.content}>
            <Text style={styles.title}>Device Capabilities</Text>
            {capabilities && (
              <View style={styles.capabilitiesContainer}>
                <Text>Secure Hardware: {capabilities.hasSecureHardware ? '✅' : '❌'}</Text>
                <Text>Biometrics: {capabilities.hasBiometrics ? '✅' : '❌'}</Text>
                <Text>Biometric Type: {capabilities.biometricType}</Text>
                <Text>Passcode: {capabilities.hasPasscode ? '✅' : '❌'}</Text>
                <Text>Device: {capabilities.deviceModel}</Text>
                <Text>OS Version: {capabilities.systemVersion}</Text>
                <Text>Jailbroken: {capabilities.isJailbroken ? '⚠️' : '✅'}</Text>
              </View>
            )}
          </View>
        );
      
      default:
        return null;
    }
  };

  return (
    <View style={styles.container}>
      <View style={styles.tabBar}>
        <Button
          title="Identities"
          onPress={() => setCurrentView('identities')}
          color={currentView === 'identities' ? '#007AFF' : '#8E8E93'}
        />
        <Button
          title="Auth"
          onPress={() => setCurrentView('auth')}
          color={currentView === 'auth' ? '#007AFF' : '#8E8E93'}
        />
        <Button
          title="QR"
          onPress={() => setCurrentView('qr')}
          color={currentView === 'qr' ? '#007AFF' : '#8E8E93'}
        />
        <Button
          title="Device"
          onPress={() => setCurrentView('capabilities')}
          color={currentView === 'capabilities' ? '#007AFF' : '#8E8E93'}
        />
      </View>
      
      <ScrollView style={styles.scrollView}>
        {renderCurrentView()}
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f8f9fa',
  },
  center: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  error: {
    color: '#FF3B30',
    fontSize: 16,
    textAlign: 'center',
    margin: 20,
  },
  tabBar: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    paddingVertical: 10,
    backgroundColor: '#ffffff',
    borderBottomWidth: 1,
    borderBottomColor: '#e5e5ea',
  },
  scrollView: {
    flex: 1,
  },
  content: {
    padding: 16,
  },
  title: {
    fontSize: 24,
    fontWeight: '600',
    marginBottom: 16,
    textAlign: 'center',
  },
  subtitle: {
    fontSize: 16,
    color: '#8E8E93',
    textAlign: 'center',
    marginTop: 16,
  },
  identityList: {
    marginTop: 16,
  },
  authButton: {
    marginBottom: 16,
  },
  qrCode: {
    alignSelf: 'center',
    marginBottom: 16,
  },
  capabilitiesContainer: {
    backgroundColor: '#ffffff',
    padding: 16,
    borderRadius: 12,
    shadowColor: '#000',
    shadowOffset: {
      width: 0,
      height: 2,
    },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 3,
  },
});

export default App;