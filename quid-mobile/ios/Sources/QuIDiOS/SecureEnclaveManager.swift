/**
 * Secure Enclave Manager
 * Handles Secure Enclave operations for QuID on iOS
 */

import Foundation
import Security
import CryptoKit
import LocalAuthentication

@available(iOS 13.0, macOS 10.15, *)
class SecureEnclaveManager {
    
    // MARK: - Properties
    
    private let accessControl: SecAccessControl
    
    // MARK: - Initialization
    
    init() throws {
        // Create access control for Secure Enclave operations
        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryAny],
            &error
        ) else {
            throw QuIDError.secureEnclaveNotAvailable
        }
        
        self.accessControl = accessControl
    }
    
    
    // MARK: - Public Methods
    
    /**
     * Check if Secure Enclave is available on this device
     */
    static func isAvailable() -> Bool {
        var error: Unmanaged<CFError>?
        let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage],
            &error
        )
        
        return accessControl != nil && error == nil
    }
    
    /**
     * Generate a key pair in the Secure Enclave
     */
    func generateKeyPair(
        securityLevel: SecurityLevel,
        requireBiometrics: Bool
    ) async throws -> SecureEnclaveKeyPair {
        
        let keyId = "quid-key-\(UUID().uuidString)"
        let tag = "com.quid.key.\(keyId)".data(using: .utf8)!
        
        // Configure key attributes based on security level
        var keyAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: getKeySizeForSecurityLevel(securityLevel),
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: accessControl
            ]
        ]
        
        // Generate key pair
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(keyAttributes as CFDictionary, &error) else {
            if let error = error?.takeRetainedValue() {
                throw QuIDError.keyGenerationFailed(CFErrorGetDescription(error) as String)
            }
            throw QuIDError.keyGenerationFailed("Unknown error")
        }
        
        // Get public key
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw QuIDError.keyGenerationFailed("Failed to extract public key")
        }
        
        // Export public key data
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) else {
            throw QuIDError.keyGenerationFailed("Failed to export public key")
        }
        
        return SecureEnclaveKeyPair(
            id: keyId,
            privateKeyRef: privateKey,
            publicKeyRef: publicKey,
            publicKeyData: publicKeyData as Data,
            algorithm: getAlgorithmForSecurityLevel(securityLevel),
            tag: tag
        )
    }
    
    /**
     * Sign a challenge with a private key from Secure Enclave
     */
    func signChallenge(
        challenge: String,
        privateKey: SecKey,
        algorithm: SigningAlgorithm
    ) async throws -> String {
        
        let challengeData = challenge.data(using: .utf8)!
        let signedData = try await signData(
            data: challengeData,
            privateKey: privateKey,
            algorithm: algorithm
        )
        
        return signedData.base64EncodedString()
    }
    
    /**
     * Sign arbitrary data with a private key from Secure Enclave
     */
    func signData(
        data: Data,
        privateKey: SecKey,
        algorithm: SigningAlgorithm
    ) async throws -> Data {
        
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let signature = try self.performSigning(
                        data: data,
                        privateKey: privateKey,
                        algorithm: algorithm
                    )
                    continuation.resume(returning: signature)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }
    
    /**
     * Export public key data
     */
    func exportPublicKey(_ privateKey: SecKey) async throws -> Data {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw QuIDError.keyExportFailed("Failed to get public key")
        }
        
        var error: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) else {
            if let error = error?.takeRetainedValue() {
                throw QuIDError.keyExportFailed(CFErrorGetDescription(error) as String)
            }
            throw QuIDError.keyExportFailed("Failed to export public key")
        }
        
        return publicKeyData as Data
    }
    
    /**
     * Delete a key from Secure Enclave
     */
    func deleteKey(_ privateKey: SecKey) async throws {
        // Get the tag for this key
        guard let tag = getKeyTag(privateKey) else {
            throw QuIDError.keyDeletionFailed("Could not get key tag")
        }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess else {
            throw QuIDError.keyDeletionFailed("SecItemDelete failed with status: \(status)")
        }
    }
    
    /**
     * Verify a signature
     */
    func verifySignature(
        data: Data,
        signature: Data,
        publicKey: SecKey,
        algorithm: SigningAlgorithm
    ) throws -> Bool {
        
        var error: Unmanaged<CFError>?
        let isValid = SecKeyVerifySignature(
            publicKey,
            algorithm.secKeyAlgorithm,
            data as CFData,
            signature as CFData,
            &error
        )
        
        if let error = error?.takeRetainedValue() {
            throw QuIDError.signatureVerificationFailed(CFErrorGetDescription(error) as String)
        }
        
        return isValid
    }
    
    // MARK: - Private Methods
    
    private func performSigning(
        data: Data,
        privateKey: SecKey,
        algorithm: SigningAlgorithm
    ) throws -> Data {
        
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            algorithm.secKeyAlgorithm,
            data as CFData,
            &error
        ) else {
            if let error = error?.takeRetainedValue() {
                throw QuIDError.signingFailed(CFErrorGetDescription(error) as String)
            }
            throw QuIDError.signingFailed("Unknown signing error")
        }
        
        return signature as Data
    }
    
    private func getKeySizeForSecurityLevel(_ level: SecurityLevel) -> Int {
        switch level {
        case .level1:
            return 256 // P-256
        case .level2:
            return 384 // P-384
        case .level3:
            return 521 // P-521
        }
    }
    
    private func getAlgorithmForSecurityLevel(_ level: SecurityLevel) -> SigningAlgorithm {
        switch level {
        case .level1:
            return .ecdsaSignatureMessageX962SHA256
        case .level2:
            return .ecdsaSignatureMessageX962SHA384
        case .level3:
            return .ecdsaSignatureMessageX962SHA512
        }
    }
    
    private func getKeyTag(_ privateKey: SecKey) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecValueRef as String: privateKey,
            kSecReturnAttributes as String: true
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        guard status == errSecSuccess,
              let attributes = item as? [String: Any],
              let tag = attributes[kSecAttrApplicationTag as String] as? Data else {
            return nil
        }
        
        return tag
    }
}

// MARK: - Supporting Types

struct SecureEnclaveKeyPair {
    let id: String
    let privateKeyRef: SecKey
    let publicKeyRef: SecKey
    let publicKeyData: Data
    let algorithm: SigningAlgorithm
    let tag: Data
}

enum SigningAlgorithm {
    case ecdsaSignatureMessageX962SHA256
    case ecdsaSignatureMessageX962SHA384
    case ecdsaSignatureMessageX962SHA512
    
    var secKeyAlgorithm: SecKeyAlgorithm {
        switch self {
        case .ecdsaSignatureMessageX962SHA256:
            return .ecdsaSignatureMessageX962SHA256
        case .ecdsaSignatureMessageX962SHA384:
            return .ecdsaSignatureMessageX962SHA384
        case .ecdsaSignatureMessageX962SHA512:
            return .ecdsaSignatureMessageX962SHA512
        }
    }
}