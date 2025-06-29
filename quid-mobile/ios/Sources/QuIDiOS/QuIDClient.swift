/**
 * QuID iOS Client
 * Main client for QuID authentication on iOS with Secure Enclave integration
 */

import Foundation
import Security
import LocalAuthentication
import CryptoKit
import Crypto

@available(iOS 13.0, macOS 10.15, *)
public class QuIDClient {
    
    // MARK: - Properties
    
    private let secureEnclave: SecureEnclaveManager
    private let biometricAuth: BiometricAuthManager
    private let identityManager: IdentityManager
    private let keychain: KeychainManager
    private var config: QuIDConfig
    
    // MARK: - Initialization
    
    public init(config: QuIDConfig = QuIDConfig()) {
        self.config = config
        self.secureEnclave = SecureEnclaveManager()
        self.biometricAuth = BiometricAuthManager()
        self.identityManager = IdentityManager(keychain: KeychainManager())
        self.keychain = KeychainManager()
    }
    
    // MARK: - Public API
    
    /**
     * Check if QuID is available on this device
     */
    public static func isAvailable() -> Bool {
        return SecureEnclaveManager.isAvailable()
    }
    
    /**
     * Get device capabilities
     */
    public func getDeviceCapabilities() -> DeviceCapabilities {
        return DeviceCapabilities(
            hasSecureEnclave: secureEnclave.isAvailable(),
            hasBiometrics: biometricAuth.isAvailable(),
            biometricType: biometricAuth.getBiometricType(),
            hasPasscode: biometricAuth.hasPasscode(),
            deviceModel: UIDevice.current.model,
            systemVersion: UIDevice.current.systemVersion
        )
    }
    
    /**
     * Create a new QuID identity
     */
    public func createIdentity(
        name: String,
        securityLevel: SecurityLevel = .level1,
        networks: [String] = ["mobile"],
        requireBiometrics: Bool = true
    ) async throws -> QuIDIdentity {
        
        let identityRequest = CreateIdentityRequest(
            name: name,
            securityLevel: securityLevel,
            networks: networks,
            requireBiometrics: requireBiometrics
        )
        
        // Generate key pair in Secure Enclave
        let keyPair = try await secureEnclave.generateKeyPair(
            securityLevel: securityLevel,
            requireBiometrics: requireBiometrics
        )
        
        // Create identity
        let identity = try await identityManager.createIdentity(
            request: identityRequest,
            keyPair: keyPair
        )
        
        // Store private key metadata in keychain
        try await keychain.storePrivateKeyMetadata(
            identityId: identity.id,
            keyId: keyPair.id,
            tag: keyPair.tag
        )
        
        // Store identity in keychain
        try await keychain.storeIdentity(identity)
        
        return identity
    }
    
    /**
     * Get all available identities
     */
    public func getIdentities() async throws -> [QuIDIdentity] {
        return try await identityManager.getAllIdentities()
    }
    
    /**
     * Authenticate with QuID
     */
    public func authenticate(
        challenge: String? = nil,
        identityId: String? = nil,
        origin: String,
        userVerification: UserVerification = .preferred
    ) async throws -> AuthenticationResponse {
        
        let authChallenge = challenge ?? generateChallenge()
        
        // Select identity
        let identity: QuIDIdentity
        if let identityId = identityId {
            guard let foundIdentity = try await identityManager.getIdentity(id: identityId) else {
                throw QuIDError.identityNotFound
            }
            identity = foundIdentity
        } else {
            // Use default identity
            let identities = try await getIdentities()
            guard let defaultIdentity = identities.first else {
                throw QuIDError.noIdentitiesAvailable
            }
            identity = defaultIdentity
        }
        
        // Perform biometric authentication if required
        if identity.requireBiometrics && userVerification != .discouraged {
            let biometricResult = try await biometricAuth.authenticate(
                reason: "Authenticate with QuID for \(origin)"
            )
            
            if !biometricResult.success {
                throw QuIDError.biometricAuthenticationFailed
            }
        }
        
        // Sign challenge with Secure Enclave
        let signature = try await secureEnclave.signChallenge(
            challenge: authChallenge,
            privateKey: identity.privateKeyRef,
            algorithm: identity.algorithm
        )
        
        // Create authentication response
        let response = AuthenticationResponse(
            success: true,
            credential: QuIDCredential(
                id: identity.id,
                rawId: identity.id,
                response: QuIDCredentialResponse(
                    authenticatorData: createAuthenticatorData(origin: origin),
                    clientDataJSON: createClientDataJSON(challenge: authChallenge, origin: origin),
                    signature: signature,
                    userHandle: identity.id
                ),
                type: "public-key"
            ),
            identity: identity
        )
        
        return response
    }
    
    /**
     * Sign arbitrary data with an identity
     */
    public func signData(
        data: Data,
        identityId: String,
        requireBiometrics: Bool = true
    ) async throws -> Data {
        
        guard let identity = try await identityManager.getIdentity(id: identityId) else {
            throw QuIDError.identityNotFound
        }
        
        // Perform biometric authentication if required
        if requireBiometrics && identity.requireBiometrics {
            let biometricResult = try await biometricAuth.authenticate(
                reason: "Sign data with QuID identity"
            )
            
            if !biometricResult.success {
                throw QuIDError.biometricAuthenticationFailed
            }
        }
        
        // Sign data with Secure Enclave
        return try await secureEnclave.signData(
            data: data,
            privateKey: identity.privateKeyRef,
            algorithm: identity.algorithm
        )
    }
    
    /**
     * Delete an identity
     */
    public func deleteIdentity(id: String) async throws {
        guard let identity = try await identityManager.getIdentity(id: id) else {
            throw QuIDError.identityNotFound
        }
        
        // Delete from Secure Enclave
        try await secureEnclave.deleteKey(identity.privateKeyRef)
        
        // Delete from keychain
        try await keychain.deleteIdentity(id: id)
        
        // Delete private key metadata
        try await keychain.deletePrivateKeyMetadata(identityId: id)
        
        // Delete from identity manager
        try await identityManager.deleteIdentity(id: id)
    }
    
    /**
     * Export identity for backup (public key only)
     */
    public func exportIdentity(id: String) async throws -> IdentityBackup {
        guard let identity = try await identityManager.getIdentity(id: id) else {
            throw QuIDError.identityNotFound
        }
        
        let publicKeyData = try await secureEnclave.exportPublicKey(identity.privateKeyRef)
        
        return IdentityBackup(
            id: identity.id,
            name: identity.name,
            publicKey: publicKeyData,
            securityLevel: identity.securityLevel,
            networks: identity.networks,
            createdAt: identity.createdAt,
            metadata: identity.metadata
        )
    }
    
    /**
     * Get identity recovery information
     */
    public func getRecoveryInfo(identityId: String) async throws -> RecoveryInfo {
        guard let identity = try await identityManager.getIdentity(id: identityId) else {
            throw QuIDError.identityNotFound
        }
        
        return RecoveryInfo(
            identityId: identity.id,
            recoveryMethods: ["biometric", "passcode"],
            backupAvailable: true,
            lastBackup: identity.lastBackup
        )
    }
    
    // MARK: - Private Methods
    
    private func generateChallenge() -> String {
        let data = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        return data.hexString
    }
    
    private func createAuthenticatorData(origin: String) -> String {
        // Create WebAuthn-compatible authenticator data
        let rpIdHash = SHA256.hash(data: origin.data(using: .utf8)!)
        let flags: UInt8 = 0x41 // UP (User Present) + AT (Attested Credential Data)
        let signCount: UInt32 = 0
        
        var authenticatorData = Data()
        authenticatorData.append(rpIdHash.data)
        authenticatorData.append(flags)
        authenticatorData.append(withUnsafeBytes(of: signCount.bigEndian) { Data($0) })
        
        return authenticatorData.base64EncodedString()
    }
    
    private func createClientDataJSON(challenge: String, origin: String) -> String {
        let clientData = [
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": origin,
            "crossOrigin": false
        ] as [String: Any]
        
        let jsonData = try! JSONSerialization.data(withJSONObject: clientData)
        return jsonData.base64EncodedString()
    }
}

// MARK: - Extensions

extension Data {
    var hexString: String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}

extension SHA256.Digest {
    var data: Data {
        return Data(self)
    }
}