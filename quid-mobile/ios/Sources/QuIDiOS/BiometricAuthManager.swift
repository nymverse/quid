/**
 * Biometric Authentication Manager
 * Handles biometric authentication for QuID on iOS
 */

import Foundation
import LocalAuthentication

@available(iOS 13.0, macOS 10.15, *)
class BiometricAuthManager {
    
    // MARK: - Properties
    
    private let context = LAContext()
    
    // MARK: - Public Methods
    
    /**
     * Check if biometric authentication is available
     */
    func isAvailable() -> Bool {
        var error: NSError?
        return context.canEvaluatePolicy(.biometryAny, error: &error)
    }
    
    /**
     * Get the type of biometric authentication available
     */
    func getBiometricType() -> BiometricType {
        guard isAvailable() else { return .none }
        
        switch context.biometryType {
        case .none:
            return .none
        case .touchID:
            return .touchID
        case .faceID:
            return .faceID
        @unknown default:
            return .unknown
        }
    }
    
    /**
     * Check if device has a passcode set
     */
    func hasPasscode() -> Bool {
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
    }
    
    /**
     * Perform biometric authentication
     */
    func authenticate(reason: String) async throws -> BiometricAuthResult {
        let context = LAContext()
        
        // Configure context
        context.localizedFallbackTitle = "Use Passcode"
        context.localizedCancelTitle = "Cancel"
        
        do {
            let success = try await context.evaluatePolicy(
                .biometryAny,
                localizedReason: reason
            )
            
            return BiometricAuthResult(
                success: success,
                biometricType: getBiometricType(),
                error: nil
            )
            
        } catch let error as LAError {
            return BiometricAuthResult(
                success: false,
                biometricType: getBiometricType(),
                error: mapLAError(error)
            )
        } catch {
            return BiometricAuthResult(
                success: false,
                biometricType: getBiometricType(),
                error: .unknown(error.localizedDescription)
            )
        }
    }
    
    /**
     * Authenticate with passcode fallback
     */
    func authenticateWithPasscode(reason: String) async throws -> BiometricAuthResult {
        let context = LAContext()
        
        do {
            let success = try await context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: reason
            )
            
            return BiometricAuthResult(
                success: success,
                biometricType: getBiometricType(),
                error: nil
            )
            
        } catch let error as LAError {
            return BiometricAuthResult(
                success: false,
                biometricType: getBiometricType(),
                error: mapLAError(error)
            )
        } catch {
            return BiometricAuthResult(
                success: false,
                biometricType: getBiometricType(),
                error: .unknown(error.localizedDescription)
            )
        }
    }
    
    /**
     * Check if biometrics have changed since last authentication
     */
    func biometricsChanged() -> Bool {
        let context = LAContext()
        var error: NSError?
        
        guard context.canEvaluatePolicy(.biometryAny, error: &error) else {
            return false
        }
        
        // This would require storing the evaluatedPolicyDomainState from previous authentications
        // For now, we'll return false
        return false
    }
    
    /**
     * Get biometric authentication capabilities
     */
    func getCapabilities() -> BiometricCapabilities {
        let context = LAContext()
        var error: NSError?
        
        let canUseBiometry = context.canEvaluatePolicy(.biometryAny, error: &error)
        let canUsePasscode = context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
        
        return BiometricCapabilities(
            biometryAvailable: canUseBiometry,
            biometryType: getBiometricType(),
            passcodeAvailable: canUsePasscode,
            biometryLockout: error?.code == LAError.biometryLockout.rawValue,
            biometryNotEnrolled: error?.code == LAError.biometryNotEnrolled.rawValue
        )
    }
    
    // MARK: - Private Methods
    
    private func mapLAError(_ error: LAError) -> BiometricAuthError {
        switch error.code {
        case .authenticationFailed:
            return .authenticationFailed
        case .userCancel:
            return .userCancel
        case .userFallback:
            return .userFallback
        case .systemCancel:
            return .systemCancel
        case .passcodeNotSet:
            return .passcodeNotSet
        case .biometryNotAvailable:
            return .biometryNotAvailable
        case .biometryNotEnrolled:
            return .biometryNotEnrolled
        case .biometryLockout:
            return .biometryLockout
        case .appCancel:
            return .appCancel
        case .invalidContext:
            return .invalidContext
        case .notInteractive:
            return .notInteractive
        default:
            return .unknown(error.localizedDescription)
        }
    }
}

// MARK: - Supporting Types

enum BiometricType {
    case none
    case touchID
    case faceID
    case unknown
    
    var displayName: String {
        switch self {
        case .none:
            return "None"
        case .touchID:
            return "Touch ID"
        case .faceID:
            return "Face ID"
        case .unknown:
            return "Unknown"
        }
    }
}

struct BiometricAuthResult {
    let success: Bool
    let biometricType: BiometricType
    let error: BiometricAuthError?
}

struct BiometricCapabilities {
    let biometryAvailable: Bool
    let biometryType: BiometricType
    let passcodeAvailable: Bool
    let biometryLockout: Bool
    let biometryNotEnrolled: Bool
}

enum BiometricAuthError: Error {
    case authenticationFailed
    case userCancel
    case userFallback
    case systemCancel
    case passcodeNotSet
    case biometryNotAvailable
    case biometryNotEnrolled
    case biometryLockout
    case appCancel
    case invalidContext
    case notInteractive
    case unknown(String)
    
    var localizedDescription: String {
        switch self {
        case .authenticationFailed:
            return "Authentication was not successful because the user failed to provide valid credentials."
        case .userCancel:
            return "Authentication was canceled by the user."
        case .userFallback:
            return "Authentication was canceled because the user tapped the fallback button."
        case .systemCancel:
            return "Authentication was canceled by system."
        case .passcodeNotSet:
            return "Authentication could not start because the passcode is not set on the device."
        case .biometryNotAvailable:
            return "Authentication could not start because biometric authentication is not available on the device."
        case .biometryNotEnrolled:
            return "Authentication could not start because the user is not enrolled in biometric authentication."
        case .biometryLockout:
            return "Authentication was not successful because there were too many failed biometric authentication attempts."
        case .appCancel:
            return "Authentication was canceled by application."
        case .invalidContext:
            return "The context is invalid."
        case .notInteractive:
            return "Not interactive."
        case .unknown(let message):
            return message
        }
    }
}