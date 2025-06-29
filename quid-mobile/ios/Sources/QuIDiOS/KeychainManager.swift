/**
 * Keychain Manager
 * Handles secure storage of QuID identities in iOS Keychain
 */

import Foundation
import Security

@available(iOS 13.0, macOS 10.15, *)
class KeychainManager {
    
    // MARK: - Constants
    
    private let service = "com.quid.ios"
    private let identityPrefix = "quid-identity-"
    private let privateKeyPrefix = "quid-privatekey-"
    
    // MARK: - Public Methods
    
    /**
     * Store an identity in the keychain
     */
    func storeIdentity(_ identity: QuIDIdentity) async throws {
        // Store identity metadata
        let identityData = try JSONEncoder().encode(identity)
        let identityKey = identityPrefix + identity.id
        
        let identityQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: identityKey,
            kSecValueData as String: identityData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        // Delete existing entry first
        SecItemDelete(identityQuery as CFDictionary)
        
        let identityStatus = SecItemAdd(identityQuery as CFDictionary, nil)
        guard identityStatus == errSecSuccess else {
            throw QuIDError.keychainError(identityStatus)
        }
    }
    
    /**
     * Load an identity from the keychain
     */
    func loadIdentity(id: String) async throws -> QuIDIdentity? {
        let identityKey = identityPrefix + id
        
        let identityQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: identityKey,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var identityItem: CFTypeRef?
        let identityStatus = SecItemCopyMatching(identityQuery as CFDictionary, &identityItem)
        
        guard identityStatus == errSecSuccess,
              let identityData = identityItem as? Data else {
            if identityStatus == errSecItemNotFound {
                return nil
            }
            throw QuIDError.keychainError(identityStatus)
        }
        
        // Decode identity metadata
        var identity = try JSONDecoder().decode(QuIDIdentity.self, from: identityData)
        
        // Load private key reference
        identity = try await loadPrivateKeyForIdentity(identity)
        
        return identity
    }
    
    /**
     * Load all identities from the keychain
     */
    func loadAllIdentities() async throws -> [QuIDIdentity] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnData as String: true,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        
        var items: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &items)
        
        guard status == errSecSuccess,
              let itemArray = items as? [[String: Any]] else {
            if status == errSecItemNotFound {
                return []
            }
            throw QuIDError.keychainError(status)
        }
        
        var identities: [QuIDIdentity] = []
        
        for item in itemArray {
            guard let account = item[kSecAttrAccount as String] as? String,
                  account.hasPrefix(identityPrefix),
                  let data = item[kSecValueData as String] as? Data else {
                continue
            }
            
            do {
                var identity = try JSONDecoder().decode(QuIDIdentity.self, from: data)
                identity = try await loadPrivateKeyForIdentity(identity)
                identities.append(identity)
            } catch {
                // Skip corrupted entries
                continue
            }
        }
        
        return identities
    }
    
    /**
     * Update an identity in the keychain
     */
    func updateIdentity(_ identity: QuIDIdentity) async throws {
        let identityKey = identityPrefix + identity.id
        let identityData = try JSONEncoder().encode(identity)
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: identityKey
        ]
        
        let attributes: [String: Any] = [
            kSecValueData as String: identityData
        ]
        
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        guard status == errSecSuccess else {
            throw QuIDError.keychainError(status)
        }
    }
    
    /**
     * Delete an identity from the keychain
     */
    func deleteIdentity(id: String) async throws {
        let identityKey = identityPrefix + id
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: identityKey
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw QuIDError.keychainError(status)
        }
    }
    
    /**
     * Store private key metadata for an identity
     */
    func storePrivateKeyMetadata(identityId: String, keyId: String, tag: Data) async throws {
        let privateKeyKey = privateKeyPrefix + identityId
        
        let metadata = PrivateKeyMetadata(
            identityId: identityId,
            keyId: keyId,
            tag: tag,
            createdAt: Date()
        )
        
        let metadataData = try JSONEncoder().encode(metadata)
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: privateKeyKey,
            kSecValueData as String: metadataData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        // Delete existing entry first
        SecItemDelete(query as CFDictionary)
        
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw QuIDError.keychainError(status)
        }
    }
    
    /**
     * Load private key metadata for an identity
     */
    func loadPrivateKeyMetadata(identityId: String) async throws -> PrivateKeyMetadata? {
        let privateKeyKey = privateKeyPrefix + identityId
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: privateKeyKey,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        guard status == errSecSuccess,
              let data = item as? Data else {
            if status == errSecItemNotFound {
                return nil
            }
            throw QuIDError.keychainError(status)
        }
        
        return try JSONDecoder().decode(PrivateKeyMetadata.self, from: data)
    }
    
    /**
     * Delete private key metadata for an identity
     */
    func deletePrivateKeyMetadata(identityId: String) async throws {
        let privateKeyKey = privateKeyPrefix + identityId
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: privateKeyKey
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw QuIDError.keychainError(status)
        }
    }
    
    /**
     * Clear all QuID data from keychain
     */
    func clearAllData() async throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw QuIDError.keychainError(status)
        }
    }
    
    /**
     * Get keychain statistics
     */
    func getKeychainStats() async throws -> KeychainStats {
        let identities = try await loadAllIdentities()
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        
        var items: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &items)
        
        var totalItems = 0
        if status == errSecSuccess, let itemArray = items as? [[String: Any]] {
            totalItems = itemArray.count
        }
        
        return KeychainStats(
            totalItems: totalItems,
            identityCount: identities.count,
            privateKeyCount: identities.count // Each identity has one private key
        )
    }
    
    // MARK: - Private Methods
    
    private func loadPrivateKeyForIdentity(_ identity: QuIDIdentity) async throws -> QuIDIdentity {
        guard let metadata = try await loadPrivateKeyMetadata(identityId: identity.id) else {
            throw QuIDError.identityNotFound
        }
        
        // Load private key from Secure Enclave using tag
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: metadata.tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        guard status == errSecSuccess,
              let privateKey = item as? SecKey else {
            throw QuIDError.keyExportFailed("Failed to load private key from Secure Enclave")
        }
        
        // Create new identity with loaded private key reference
        return QuIDIdentity(
            id: identity.id,
            name: identity.name,
            securityLevel: identity.securityLevel,
            networks: identity.networks,
            requireBiometrics: identity.requireBiometrics,
            publicKey: identity.publicKey,
            algorithm: identity.algorithm,
            privateKeyRef: privateKey,
            createdAt: identity.createdAt,
            lastUsedAt: identity.lastUsedAt,
            lastBackup: identity.lastBackup,
            metadata: identity.metadata
        )
    }
}

// MARK: - Supporting Types

private struct PrivateKeyMetadata: Codable {
    let identityId: String
    let keyId: String
    let tag: Data
    let createdAt: Date
}

struct KeychainStats {
    let totalItems: Int
    let identityCount: Int
    let privateKeyCount: Int
}