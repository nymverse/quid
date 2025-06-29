/**
 * QuID QR Code Scanner Component
 */

import React, { useState, useEffect } from 'react';
import {
  View,
  StyleSheet,
  Text,
  Alert,
  Dimensions,
  TouchableOpacity,
} from 'react-native';
import { RNCamera } from 'react-native-camera';
import { QuIDQRScannerProps, QRCodeData } from '../types';

const { width, height } = Dimensions.get('window');

export const QuIDQRScanner: React.FC<QuIDQRScannerProps> = ({
  onScan,
  onError,
  style,
  overlayColor = 'rgba(0, 0, 0, 0.5)',
  borderColor = '#007AFF',
}) => {
  const [isScanning, setIsScanning] = useState(true);
  const [hasPermission, setHasPermission] = useState<boolean | null>(null);

  useEffect(() => {
    // Request camera permission
    RNCamera.requestPermission({ permissionDialogTitle: 'Permission to use camera', permissionDialogMessage: 'We need your permission to use your camera for QR code scanning' })
      .then((status) => {
        setHasPermission(status === 'authorized');
      })
      .catch((error) => {
        console.error('Camera permission error:', error);
        setHasPermission(false);
      });
  }, []);

  const handleBarCodeRead = (event: any) => {
    if (!isScanning) return;

    try {
      const qrData: QRCodeData = JSON.parse(event.data);
      
      // Validate QR code structure
      if (!qrData.challenge || !qrData.origin || !qrData.expiresAt) {
        throw new Error('Invalid QR code format');
      }

      // Check if QR code is expired
      if (Date.now() > qrData.expiresAt) {
        onError('QR code has expired');
        return;
      }

      // Validate it's a QuID authentication QR code
      if (qrData.metadata?.type !== 'quid-auth') {
        throw new Error('Not a QuID authentication QR code');
      }

      setIsScanning(false);
      onScan(qrData);
      
      // Re-enable scanning after a delay
      setTimeout(() => {
        setIsScanning(true);
      }, 2000);
      
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Invalid QR code';
      onError(errorMessage);
      
      Alert.alert(
        'Invalid QR Code',
        errorMessage,
        [
          {
            text: 'OK',
            onPress: () => {
              // Brief pause before allowing scanning again
              setTimeout(() => {
                setIsScanning(true);
              }, 1000);
            },
          },
        ]
      );
    }
  };

  const resetScanning = () => {
    setIsScanning(true);
  };

  if (hasPermission === null) {
    return (
      <View style={[styles.container, style]}>
        <Text style={styles.message}>Requesting camera permission...</Text>
      </View>
    );
  }

  if (hasPermission === false) {
    return (
      <View style={[styles.container, style]}>
        <Text style={styles.message}>Camera permission is required to scan QR codes</Text>
        <TouchableOpacity style={styles.permissionButton} onPress={() => {
          // Re-request permission
          RNCamera.requestPermission({})
            .then((status) => {
              setHasPermission(status === 'authorized');
            });
        }}>
          <Text style={styles.permissionButtonText}>Grant Permission</Text>
        </TouchableOpacity>
      </View>
    );
  }

  return (
    <View style={[styles.container, style]}>
      <RNCamera
        style={styles.camera}
        onBarCodeRead={isScanning ? handleBarCodeRead : undefined}
        barCodeTypes={[RNCamera.Constants.BarCodeType.qr]}
        captureAudio={false}
        autoFocus={RNCamera.Constants.AutoFocus.on}
        flashMode={RNCamera.Constants.FlashMode.off}
      >
        {/* Overlay */}
        <View style={styles.overlay}>
          {/* Top overlay */}
          <View style={[styles.overlaySection, { backgroundColor: overlayColor }]} />
          
          {/* Middle section with scanning area */}
          <View style={styles.middleSection}>
            <View style={[styles.sideOverlay, { backgroundColor: overlayColor }]} />
            <View style={styles.scanningArea}>
              <View style={[styles.corner, styles.topLeft, { borderColor }]} />
              <View style={[styles.corner, styles.topRight, { borderColor }]} />
              <View style={[styles.corner, styles.bottomLeft, { borderColor }]} />
              <View style={[styles.corner, styles.bottomRight, { borderColor }]} />
            </View>
            <View style={[styles.sideOverlay, { backgroundColor: overlayColor }]} />
          </View>
          
          {/* Bottom overlay */}
          <View style={[styles.overlaySection, { backgroundColor: overlayColor }]}>
            <Text style={styles.instructionText}>
              {isScanning ? 'Position QR code within the frame' : 'Processing...'}
            </Text>
            {!isScanning && (
              <TouchableOpacity style={styles.resetButton} onPress={resetScanning}>
                <Text style={styles.resetButtonText}>Scan Again</Text>
              </TouchableOpacity>
            )}
          </View>
        </View>
      </RNCamera>
    </View>
  );
};

const scanningAreaSize = Math.min(width, height) * 0.7;

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#000000',
  },
  camera: {
    flex: 1,
  },
  overlay: {
    flex: 1,
  },
  overlaySection: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  middleSection: {
    flexDirection: 'row',
    height: scanningAreaSize,
  },
  sideOverlay: {
    flex: 1,
  },
  scanningArea: {
    width: scanningAreaSize,
    height: scanningAreaSize,
    position: 'relative',
  },
  corner: {
    position: 'absolute',
    width: 30,
    height: 30,
    borderWidth: 4,
  },
  topLeft: {
    top: 0,
    left: 0,
    borderBottomWidth: 0,
    borderRightWidth: 0,
  },
  topRight: {
    top: 0,
    right: 0,
    borderBottomWidth: 0,
    borderLeftWidth: 0,
  },
  bottomLeft: {
    bottom: 0,
    left: 0,
    borderTopWidth: 0,
    borderRightWidth: 0,
  },
  bottomRight: {
    bottom: 0,
    right: 0,
    borderTopWidth: 0,
    borderLeftWidth: 0,
  },
  message: {
    fontSize: 18,
    color: '#ffffff',
    textAlign: 'center',
    margin: 20,
  },
  instructionText: {
    fontSize: 16,
    color: '#ffffff',
    textAlign: 'center',
    marginTop: 20,
  },
  resetButton: {
    backgroundColor: '#007AFF',
    paddingHorizontal: 20,
    paddingVertical: 10,
    borderRadius: 8,
    marginTop: 20,
  },
  resetButtonText: {
    color: '#ffffff',
    fontSize: 16,
    fontWeight: '600',
  },
  permissionButton: {
    backgroundColor: '#007AFF',
    paddingHorizontal: 24,
    paddingVertical: 12,
    borderRadius: 8,
    marginTop: 20,
  },
  permissionButtonText: {
    color: '#ffffff',
    fontSize: 16,
    fontWeight: '600',
  },
});