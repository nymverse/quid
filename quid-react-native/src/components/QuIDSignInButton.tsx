/**
 * QuID Sign In Button Component
 */

import React, { useState } from 'react';
import {
  TouchableOpacity,
  Text,
  StyleSheet,
  ActivityIndicator,
  View,
  Alert,
} from 'react-native';
import { QuIDSignInButtonProps } from '../types';
import { useQuIDAuth } from '../hooks';

export const QuIDSignInButton: React.FC<QuIDSignInButtonProps & { client: any }> = ({
  client,
  onSuccess,
  onError,
  challenge,
  identityId,
  origin,
  userVerification = 'preferred',
  style,
  title = 'Sign in with QuID',
  disabled = false,
}) => {
  const { authenticate, loading } = useQuIDAuth(client);
  const [isAuthenticating, setIsAuthenticating] = useState(false);

  const handlePress = async () => {
    if (disabled || loading || isAuthenticating) return;

    try {
      setIsAuthenticating(true);

      const response = await authenticate({
        challenge,
        identityId,
        origin,
        userVerification,
      });

      if (response.success) {
        onSuccess(response);
      } else {
        onError(response.error || 'Authentication failed');
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Authentication failed';
      onError(errorMessage);
      
      // Show alert for user feedback
      Alert.alert(
        'Authentication Failed',
        errorMessage,
        [{ text: 'OK' }]
      );
    } finally {
      setIsAuthenticating(false);
    }
  };

  const isLoading = loading || isAuthenticating;
  const isDisabled = disabled || isLoading;

  return (
    <TouchableOpacity
      style={[
        styles.button,
        style,
        isDisabled && styles.buttonDisabled,
      ]}
      onPress={handlePress}
      disabled={isDisabled}
      activeOpacity={0.8}
    >
      <View style={styles.content}>
        {isLoading && (
          <ActivityIndicator
            size="small"
            color="#ffffff"
            style={styles.spinner}
          />
        )}
        <Text style={[styles.text, isDisabled && styles.textDisabled]}>
          {isLoading ? 'Authenticating...' : title}
        </Text>
      </View>
    </TouchableOpacity>
  );
};

const styles = StyleSheet.create({
  button: {
    backgroundColor: '#007AFF',
    paddingHorizontal: 24,
    paddingVertical: 12,
    borderRadius: 8,
    alignItems: 'center',
    justifyContent: 'center',
    minHeight: 48,
    shadowColor: '#000',
    shadowOffset: {
      width: 0,
      height: 2,
    },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 3,
  },
  buttonDisabled: {
    backgroundColor: '#A0A0A0',
    shadowOpacity: 0,
    elevation: 0,
  },
  content: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
  },
  text: {
    color: '#ffffff',
    fontSize: 16,
    fontWeight: '600',
    textAlign: 'center',
  },
  textDisabled: {
    color: '#ffffff',
    opacity: 0.7,
  },
  spinner: {
    marginRight: 8,
  },
});