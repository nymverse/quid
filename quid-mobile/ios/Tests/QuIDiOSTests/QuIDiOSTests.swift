import XCTest
@testable import QuIDiOS

@available(iOS 13.0, macOS 10.15, *)
final class QuIDiOSTests: XCTestCase {
    
    func testQuIDClientInitialization() throws {
        let config = QuIDConfig(
            securityLevel: .level1,
            requireBiometrics: true,
            timeout: 30.0,
            debugMode: true
        )
        
        let client = try QuIDClient(config: config)
        XCTAssertNotNil(client)
    }
    
    func testDeviceCapabilities() throws {
        let client = try QuIDClient()
        let capabilities = client.getDeviceCapabilities()
        
        XCTAssertNotNil(capabilities.deviceModel)
        XCTAssertNotNil(capabilities.systemVersion)
    }
    
    func testSecurityLevels() {
        let level1 = SecurityLevel.level1
        XCTAssertEqual(level1.keySize, 256)
        XCTAssertEqual(level1.displayName, "Standard Security (P-256)")
        
        let level2 = SecurityLevel.level2
        XCTAssertEqual(level2.keySize, 384)
        
        let level3 = SecurityLevel.level3
        XCTAssertEqual(level3.keySize, 521)
    }
    
    func testBiometricTypes() {
        let touchID = BiometricType.touchID
        XCTAssertEqual(touchID.displayName, "Touch ID")
        
        let faceID = BiometricType.faceID
        XCTAssertEqual(faceID.displayName, "Face ID")
    }
    
    func testQuIDErrorDescriptions() {
        let error1 = QuIDError.secureEnclaveNotAvailable
        XCTAssertEqual(error1.localizedDescription, "Secure Enclave is not available on this device")
        
        let error2 = QuIDError.biometricAuthenticationFailed
        XCTAssertEqual(error2.localizedDescription, "Biometric authentication failed")
        
        let error3 = QuIDError.identityNotFound
        XCTAssertEqual(error3.localizedDescription, "QuID identity not found")
    }
    
    func testCreateIdentityRequest() {
        let request = CreateIdentityRequest(
            name: "Test Identity",
            securityLevel: .level2,
            networks: ["mobile", "web"],
            requireBiometrics: false,
            metadata: ["test": "value"]
        )
        
        XCTAssertEqual(request.name, "Test Identity")
        XCTAssertEqual(request.securityLevel, .level2)
        XCTAssertEqual(request.networks, ["mobile", "web"])
        XCTAssertFalse(request.requireBiometrics)
        XCTAssertEqual(request.metadata["test"], "value")
    }
    
    func testUserVerificationEnums() {
        XCTAssertEqual(UserVerification.required.rawValue, "required")
        XCTAssertEqual(UserVerification.preferred.rawValue, "preferred")
        XCTAssertEqual(UserVerification.discouraged.rawValue, "discouraged")
    }
}