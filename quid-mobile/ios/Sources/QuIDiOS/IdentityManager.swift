/**
 * Identity Manager
 * Manages QuID identities on iOS
 */

import Foundation
import Security

@available(iOS 13.0, macOS 10.15, *)
class IdentityManager {
    
    // MARK: - Properties
    
    private let keychain: KeychainManager
    private var identitiesCache: [String: QuIDIdentity] = [:]
    
    // MARK: - Initialization
    
    init(keychain: KeychainManager) {
        self.keychain = keychain
    }
    
    // MARK: - Public Methods
    
    /**
     * Create a new identity
     */
    func createIdentity(
        request: CreateIdentityRequest,
        keyPair: SecureEnclaveKeyPair
    ) async throws -> QuIDIdentity {
        
        let identityId = UUID().uuidString
        let publicKeyString = keyPair.publicKeyData.base64EncodedString()
        
        let identity = QuIDIdentity(
            id: identityId,
            name: request.name,
            securityLevel: request.securityLevel,
            networks: request.networks,
            requireBiometrics: request.requireBiometrics,
            publicKey: publicKeyString,
            algorithm: keyPair.algorithm.rawValue,
            privateKeyRef: keyPair.privateKeyRef,
            createdAt: Date(),
            lastUsedAt: nil,
            lastBackup: nil,
            metadata: request.metadata
        )
        
        // Store in cache
        identitiesCache[identityId] = identity
        
        return identity
    }
    
    /**
     * Get an identity by ID
     */
    func getIdentity(id: String) async throws -> QuIDIdentity? {
        // Check cache first
        if let cachedIdentity = identitiesCache[id] {
            return cachedIdentity
        }
        
        // Load from keychain
        if let identity = try await keychain.loadIdentity(id: id) {
            identitiesCache[id] = identity
            return identity
        }
        
        return nil
    }
    
    /**
     * Get all identities
     */
    func getAllIdentities() async throws -> [QuIDIdentity] {
        let identities = try await keychain.loadAllIdentities()
        
        // Update cache
        for identity in identities {
            identitiesCache[identity.id] = identity
        }
        
        return identities
    }
    
    /**
     * Update an identity
     */
    func updateIdentity(_ identity: QuIDIdentity) async throws {
        // Update cache
        identitiesCache[identity.id] = identity
        
        // Update keychain
        try await keychain.updateIdentity(identity)
    }
    
    /**
     * Delete an identity
     */
    func deleteIdentity(id: String) async throws {
        // Remove from cache
        identitiesCache.removeValue(forKey: id)
        
        // Remove from keychain
        try await keychain.deleteIdentity(id: id)
    }
    
    /**
     * Update last used timestamp for an identity
     */
    func updateLastUsed(identityId: String) async throws {
        guard let identity = try await getIdentity(id: identityId) else {
            throw QuIDError.identityNotFound
        }
        
        let updatedIdentity = QuIDIdentity(
            id: identity.id,
            name: identity.name,
            securityLevel: identity.securityLevel,
            networks: identity.networks,
            requireBiometrics: identity.requireBiometrics,
            publicKey: identity.publicKey,
            algorithm: identity.algorithm,
            privateKeyRef: identity.privateKeyRef,
            createdAt: identity.createdAt,
            lastUsedAt: Date(),
            lastBackup: identity.lastBackup,
            metadata: identity.metadata
        )
        
        try await updateIdentity(updatedIdentity)
    }
    
    /**
     * Get identities for a specific network
     */
    func getIdentitiesForNetwork(_ network: String) async throws -> [QuIDIdentity] {
        let allIdentities = try await getAllIdentities()
        return allIdentities.filter { $0.networks.contains(network) }
    }
    
    /**
     * Check if an identity exists
     */
    func identityExists(id: String) async throws -> Bool {
        return try await getIdentity(id: id) != nil
    }
    
    /**
     * Get identity statistics
     */
    func getIdentityStats() async throws -> IdentityStats {
        let identities = try await getAllIdentities()
        
        let securityLevelCounts = identities.reduce(into: [SecurityLevel: Int]()) { counts, identity in
            counts[identity.securityLevel, default: 0] += 1
        }
        
        let biometricEnabledCount = identities.filter { $0.requireBiometrics }.count
        let recentlyUsedCount = identities.filter { identity in
            guard let lastUsed = identity.lastUsedAt else { return false }
            return lastUsed.timeIntervalSinceNow > -86400 // Within 24 hours
        }.count
        
        return IdentityStats(
            totalIdentities: identities.count,
            securityLevelCounts: securityLevelCounts,
            biometricEnabledCount: biometricEnabledCount,
            recentlyUsedCount: recentlyUsedCount
        )
    }
}

// MARK: - Supporting Types

struct IdentityStats {
    let totalIdentities: Int
    let securityLevelCounts: [SecurityLevel: Int]
    let biometricEnabledCount: Int
    let recentlyUsedCount: Int
}

extension SigningAlgorithm {
    var rawValue: String {
        switch self {
        case .ecdsaSignatureMessageX962SHA256:
            return "ES256"
        case .ecdsaSignatureMessageX962SHA384:
            return "ES384"
        case .ecdsaSignatureMessageX962SHA512:
            return "ES512"
        }
    }
}