/// QuID Flutter SDK
/// 
/// A comprehensive Flutter SDK for quantum-resistant authentication using QuID technology.
/// 
/// Features:
/// - Quantum-resistant authentication with ML-DSA signatures
/// - Hardware security integration (Secure Enclave, TEE)
/// - Biometric authentication support
/// - QR code authentication flows
/// - Push notification integration
/// - Identity management
/// - Cross-platform compatibility

library quid_flutter;

// Core exports
export 'src/quid_client.dart';
export 'src/quid_config.dart';

// Models
export 'src/models/quid_identity.dart';
export 'src/models/quid_credential.dart';
export 'src/models/authentication_request.dart';
export 'src/models/authentication_response.dart';
export 'src/models/device_capabilities.dart';
export 'src/models/qr_auth_data.dart';
export 'src/models/push_auth_request.dart';
export 'src/models/enums.dart';
export 'src/models/exceptions.dart';

// Services
export 'src/services/biometric_service.dart';
export 'src/services/secure_storage_service.dart';
export 'src/services/notification_service.dart';
export 'src/services/qr_service.dart';

// Widgets
export 'src/widgets/quid_signin_button.dart';
export 'src/widgets/quid_qr_scanner.dart';
export 'src/widgets/quid_qr_generator.dart';
export 'src/widgets/quid_identity_list.dart';

// Utils
export 'src/utils/crypto_utils.dart';
export 'src/utils/validation_utils.dart';
export 'src/utils/platform_utils.dart';