/**
 * QuID Core Types
 * Data structures and enums for QuID iOS library
 */

import Foundation
import Security

// MARK: - Configuration

public struct QuIDConfig {
    public let securityLevel: SecurityLevel
    public let requireBiometrics: Bool
    public let timeout: TimeInterval
    public let debugMode: Bool
    
    public init(
        securityLevel: SecurityLevel = .level1,
        requireBiometrics: Bool = true,
        timeout: TimeInterval = 60.0,
        debugMode: Bool = false
    ) {
        self.securityLevel = securityLevel
        self.requireBiometrics = requireBiometrics
        self.timeout = timeout
        self.debugMode = debugMode
    }
}

// MARK: - Security Levels

public enum SecurityLevel: String, CaseIterable, Codable {
    case level1 = "Level1"
    case level2 = "Level2"
    case level3 = "Level3"
    
    public var displayName: String {
        switch self {
        case .level1:
            return "Standard Security (P-256)"
        case .level2:
            return "Enhanced Security (P-384)"
        case .level3:
            return "Maximum Security (P-521)"
        }
    }
    
    public var keySize: Int {
        switch self {
        case .level1:
            return 256
        case .level2:
            return 384
        case .level3:
            return 521
        }
    }
}

// MARK: - User Verification

public enum UserVerification: String, CaseIterable, Codable {
    case required = "required"
    case preferred = "preferred"
    case discouraged = "discouraged"
}

// MARK: - Identity Types

public struct QuIDIdentity: Codable {
    public let id: String
    public let name: String
    public let securityLevel: SecurityLevel
    public let networks: [String]
    public let requireBiometrics: Bool
    public let publicKey: String
    public let algorithm: String
    public let createdAt: Date
    public let lastUsedAt: Date?
    public let lastBackup: Date?
    public let metadata: [String: String]
    
    // Internal reference to private key (not codable)
    internal let privateKeyRef: SecKey
    
    public init(
        id: String,
        name: String,
        securityLevel: SecurityLevel,
        networks: [String],
        requireBiometrics: Bool,
        publicKey: String,
        algorithm: String,
        privateKeyRef: SecKey,
        createdAt: Date = Date(),
        lastUsedAt: Date? = nil,
        lastBackup: Date? = nil,
        metadata: [String: String] = [:]
    ) {
        self.id = id
        self.name = name
        self.securityLevel = securityLevel
        self.networks = networks
        self.requireBiometrics = requireBiometrics
        self.publicKey = publicKey
        self.algorithm = algorithm
        self.privateKeyRef = privateKeyRef
        self.createdAt = createdAt
        self.lastUsedAt = lastUsedAt
        self.lastBackup = lastBackup
        self.metadata = metadata
    }
    
    // Custom coding to exclude privateKeyRef
    private enum CodingKeys: String, CodingKey {
        case id, name, securityLevel, networks, requireBiometrics
        case publicKey, algorithm, createdAt, lastUsedAt, lastBackup, metadata
    }
}

public struct CreateIdentityRequest {
    public let name: String
    public let securityLevel: SecurityLevel
    public let networks: [String]
    public let requireBiometrics: Bool
    public let metadata: [String: String]
    
    public init(
        name: String,
        securityLevel: SecurityLevel = .level1,
        networks: [String] = ["mobile"],
        requireBiometrics: Bool = true,
        metadata: [String: String] = [:]
    ) {
        self.name = name
        self.securityLevel = securityLevel
        self.networks = networks
        self.requireBiometrics = requireBiometrics
        self.metadata = metadata
    }
}

// MARK: - Authentication Types

public struct AuthenticationResponse {
    public let success: Bool
    public let credential: QuIDCredential?
    public let identity: QuIDIdentity?
    public let error: String?
    
    public init(
        success: Bool,
        credential: QuIDCredential? = nil,
        identity: QuIDIdentity? = nil,
        error: String? = nil
    ) {
        self.success = success
        self.credential = credential
        self.identity = identity
        self.error = error
    }
}

public struct QuIDCredential {
    public let id: String
    public let rawId: String
    public let response: QuIDCredentialResponse
    public let type: String
    
    public init(id: String, rawId: String, response: QuIDCredentialResponse, type: String) {
        self.id = id
        self.rawId = rawId
        self.response = response
        self.type = type
    }
}

public struct QuIDCredentialResponse {
    public let authenticatorData: String
    public let clientDataJSON: String
    public let signature: String
    public let userHandle: String
    
    public init(
        authenticatorData: String,
        clientDataJSON: String,
        signature: String,
        userHandle: String
    ) {
        self.authenticatorData = authenticatorData
        self.clientDataJSON = clientDataJSON
        self.signature = signature
        self.userHandle = userHandle
    }
}

// MARK: - Device Capabilities

public struct DeviceCapabilities {
    public let hasSecureEnclave: Bool
    public let hasBiometrics: Bool
    public let biometricType: BiometricType
    public let hasPasscode: Bool
    public let deviceModel: String
    public let systemVersion: String
    
    public init(
        hasSecureEnclave: Bool,
        hasBiometrics: Bool,
        biometricType: BiometricType,
        hasPasscode: Bool,
        deviceModel: String,
        systemVersion: String
    ) {
        self.hasSecureEnclave = hasSecureEnclave
        self.hasBiometrics = hasBiometrics
        self.biometricType = biometricType
        self.hasPasscode = hasPasscode
        self.deviceModel = deviceModel
        self.systemVersion = systemVersion
    }
}

// MARK: - Backup and Recovery

public struct IdentityBackup: Codable {
    public let id: String
    public let name: String
    public let publicKey: Data
    public let securityLevel: SecurityLevel
    public let networks: [String]
    public let createdAt: Date
    public let metadata: [String: String]
    
    public init(
        id: String,
        name: String,
        publicKey: Data,
        securityLevel: SecurityLevel,
        networks: [String],
        createdAt: Date,
        metadata: [String: String]
    ) {
        self.id = id
        self.name = name
        self.publicKey = publicKey
        self.securityLevel = securityLevel
        self.networks = networks
        self.createdAt = createdAt
        self.metadata = metadata
    }
}

public struct RecoveryInfo {
    public let identityId: String
    public let recoveryMethods: [String]
    public let backupAvailable: Bool
    public let lastBackup: Date?
    
    public init(
        identityId: String,
        recoveryMethods: [String],
        backupAvailable: Bool,
        lastBackup: Date?
    ) {
        self.identityId = identityId
        self.recoveryMethods = recoveryMethods
        self.backupAvailable = backupAvailable
        self.lastBackup = lastBackup
    }
}

// MARK: - Errors

public enum QuIDError: Error {
    case secureEnclaveNotAvailable
    case biometricAuthenticationFailed
    case identityNotFound
    case noIdentitiesAvailable
    case keyGenerationFailed(String)
    case keyExportFailed(String)
    case keyDeletionFailed(String)
    case signingFailed(String)
    case signatureVerificationFailed(String)
    case keychainError(OSStatus)
    case invalidConfiguration
    case networkError(String)
    case timeout
    case unknown(String)
    
    public var localizedDescription: String {
        switch self {
        case .secureEnclaveNotAvailable:
            return "Secure Enclave is not available on this device"
        case .biometricAuthenticationFailed:
            return "Biometric authentication failed"
        case .identityNotFound:
            return "QuID identity not found"
        case .noIdentitiesAvailable:
            return "No QuID identities are available"
        case .keyGenerationFailed(let message):
            return "Key generation failed: \(message)"
        case .keyExportFailed(let message):
            return "Key export failed: \(message)"
        case .keyDeletionFailed(let message):
            return "Key deletion failed: \(message)"
        case .signingFailed(let message):
            return "Signing failed: \(message)"
        case .signatureVerificationFailed(let message):
            return "Signature verification failed: \(message)"
        case .keychainError(let status):
            return "Keychain error: \(status)"
        case .invalidConfiguration:
            return "Invalid QuID configuration"
        case .networkError(let message):
            return "Network error: \(message)"
        case .timeout:
            return "Operation timed out"
        case .unknown(let message):
            return "Unknown error: \(message)"
        }
    }
}