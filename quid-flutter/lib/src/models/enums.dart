/// Enumerations for QuID Flutter SDK

/// Security levels for quantum-resistant cryptography
enum SecurityLevel {
  /// Standard security using P-256 curve
  level1('Level1', 256, 'ES256'),
  
  /// Enhanced security using P-384 curve
  level2('Level2', 384, 'ES384'),
  
  /// Maximum security using P-521 curve
  level3('Level3', 521, 'ES512');

  const SecurityLevel(this.displayName, this.keySize, this.algorithm);

  final String displayName;
  final int keySize;
  final String algorithm;

  /// Get display name with description
  String get fullDisplayName {
    switch (this) {
      case SecurityLevel.level1:
        return 'Standard Security (P-256)';
      case SecurityLevel.level2:
        return 'Enhanced Security (P-384)';
      case SecurityLevel.level3:
        return 'Maximum Security (P-521)';
    }
  }
}

/// User verification requirements for authentication
enum UserVerification {
  /// User verification is required
  required('required'),
  
  /// User verification is preferred but not required
  preferred('preferred'),
  
  /// User verification is discouraged
  discouraged('discouraged');

  const UserVerification(this.value);
  
  final String value;

  /// Create from string value
  static UserVerification fromString(String value) {
    return UserVerification.values.firstWhere(
      (e) => e.value == value,
      orElse: () => UserVerification.preferred,
    );
  }
}

/// Types of biometric authentication available
enum BiometricType {
  /// No biometric authentication available
  none('none', 'None'),
  
  /// Touch ID (iOS)
  touchId('touchId', 'Touch ID'),
  
  /// Face ID (iOS)
  faceId('faceId', 'Face ID'),
  
  /// Fingerprint (Android)
  fingerprint('fingerprint', 'Fingerprint'),
  
  /// Face recognition (Android)
  face('face', 'Face Recognition'),
  
  /// Iris scanner
  iris('iris', 'Iris Scanner'),
  
  /// Unknown biometric type
  unknown('unknown', 'Unknown');

  const BiometricType(this.value, this.displayName);
  
  final String value;
  final String displayName;

  /// Create from string value
  static BiometricType fromString(String value) {
    return BiometricType.values.firstWhere(
      (e) => e.value == value,
      orElse: () => BiometricType.unknown,
    );
  }

  /// Check if biometric type is available
  bool get isAvailable => this != BiometricType.none;
}

/// QuID event types for event listeners
enum QuIDEventType {
  /// Identity was created
  identityCreated('identity_created'),
  
  /// Identity was updated
  identityUpdated('identity_updated'),
  
  /// Identity was deleted
  identityDeleted('identity_deleted'),
  
  /// Authentication was successful
  authenticationSuccess('authentication_success'),
  
  /// Authentication failed
  authenticationFailed('authentication_failed'),
  
  /// Biometric settings changed
  biometricChanged('biometric_changed'),
  
  /// Security alert
  securityAlert('security_alert'),
  
  /// Backup was created
  backupCreated('backup_created'),
  
  /// Backup was restored
  backupRestored('backup_restored'),
  
  /// QR code was scanned
  qrCodeScanned('qr_code_scanned'),
  
  /// Push notification received
  pushNotificationReceived('push_notification_received');

  const QuIDEventType(this.value);
  
  final String value;

  /// Create from string value
  static QuIDEventType fromString(String value) {
    return QuIDEventType.values.firstWhere(
      (e) => e.value == value,
      orElse: () => QuIDEventType.securityAlert,
    );
  }
}

/// Authentication status
enum AuthenticationStatus {
  /// Authentication is idle
  idle,
  
  /// Authentication is in progress
  loading,
  
  /// Authentication was successful
  success,
  
  /// Authentication failed
  failure,
  
  /// Authentication was cancelled by user
  cancelled,
  
  /// Authentication timed out
  timeout;

  /// Check if authentication is in progress
  bool get isLoading => this == AuthenticationStatus.loading;
  
  /// Check if authentication was successful
  bool get isSuccess => this == AuthenticationStatus.success;
  
  /// Check if authentication failed
  bool get isFailure => this == AuthenticationStatus.failure;
  
  /// Check if authentication is complete (success or failure)
  bool get isComplete => isSuccess || isFailure || this == AuthenticationStatus.cancelled || this == AuthenticationStatus.timeout;
}

/// QR code scan status
enum QRScanStatus {
  /// Scanner is idle
  idle,
  
  /// Scanner is active and scanning
  scanning,
  
  /// Valid QR code was detected
  detected,
  
  /// QR code was processed successfully
  success,
  
  /// Invalid QR code detected
  invalid,
  
  /// QR code has expired
  expired,
  
  /// Scanner error occurred
  error;

  /// Check if scanner is active
  bool get isScanning => this == QRScanStatus.scanning;
  
  /// Check if QR code was successfully processed
  bool get isSuccess => this == QRScanStatus.success;
  
  /// Check if there was an error
  bool get hasError => this == QRScanStatus.invalid || this == QRScanStatus.expired || this == QRScanStatus.error;
}

/// Platform types
enum PlatformType {
  /// iOS platform
  ios,
  
  /// Android platform
  android,
  
  /// Web platform
  web,
  
  /// Desktop platforms (Windows, macOS, Linux)
  desktop,
  
  /// Unknown platform
  unknown;

  /// Check if platform supports hardware security
  bool get supportsHardwareSecurity {
    switch (this) {
      case PlatformType.ios:
      case PlatformType.android:
        return true;
      default:
        return false;
    }
  }

  /// Check if platform supports biometric authentication
  bool get supportsBiometrics {
    switch (this) {
      case PlatformType.ios:
      case PlatformType.android:
        return true;
      default:
        return false;
    }
  }
}

/// Identity backup status
enum BackupStatus {
  /// No backup available
  none,
  
  /// Backup is up to date
  current,
  
  /// Backup is outdated
  outdated,
  
  /// Backup is in progress
  inProgress,
  
  /// Backup failed
  failed;

  /// Check if backup is available
  bool get isAvailable => this != BackupStatus.none;
  
  /// Check if backup needs update
  bool get needsUpdate => this == BackupStatus.outdated;
}

/// Network connection status
enum NetworkStatus {
  /// Network is connected
  connected,
  
  /// Network is disconnected
  disconnected,
  
  /// Network status is unknown
  unknown;

  /// Check if network is available
  bool get isConnected => this == NetworkStatus.connected;
}