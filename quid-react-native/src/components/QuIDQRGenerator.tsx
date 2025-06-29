/**
 * QuID QR Code Generator Component
 */

import React from 'react';
import { View, StyleSheet, Text } from 'react-native';
import QRCode from 'react-native-qrcode-svg';
import { QuIDQRGeneratorProps } from '../types';

export const QuIDQRGenerator: React.FC<QuIDQRGeneratorProps> = ({
  data,
  size = 200,
  color = '#000000',
  backgroundColor = '#ffffff',
  logo,
  style,
}) => {
  const qrValue = JSON.stringify(data);
  const isExpired = Date.now() > data.expiresAt;

  if (isExpired) {
    return (
      <View style={[styles.container, style, { width: size, height: size }]}>
        <View style={styles.expiredContainer}>
          <Text style={styles.expiredText}>QR Code Expired</Text>
          <Text style={styles.expiredSubtext}>Please generate a new one</Text>
        </View>
      </View>
    );
  }

  return (
    <View style={[styles.container, style]}>
      <QRCode
        value={qrValue}
        size={size}
        color={color}
        backgroundColor={backgroundColor}
        logo={logo}
        logoSize={size * 0.2}
        logoBackgroundColor={backgroundColor}
        logoMargin={2}
        logoBorderRadius={4}
        quietZone={10}
      />
      <View style={styles.info}>
        <Text style={styles.originText}>{data.origin}</Text>
        <Text style={styles.expiryText}>
          Expires in {Math.max(0, Math.ceil((data.expiresAt - Date.now()) / 1000))}s
        </Text>
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    alignItems: 'center',
    justifyContent: 'center',
    padding: 16,
    backgroundColor: '#ffffff',
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
  info: {
    marginTop: 12,
    alignItems: 'center',
  },
  originText: {
    fontSize: 16,
    fontWeight: '600',
    color: '#333333',
    textAlign: 'center',
  },
  expiryText: {
    fontSize: 12,
    color: '#666666',
    marginTop: 4,
    textAlign: 'center',
  },
  expiredContainer: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: '#f8f8f8',
    borderRadius: 8,
    padding: 20,
  },
  expiredText: {
    fontSize: 18,
    fontWeight: '600',
    color: '#ff3b30',
    textAlign: 'center',
  },
  expiredSubtext: {
    fontSize: 14,
    color: '#666666',
    marginTop: 8,
    textAlign: 'center',
  },
});