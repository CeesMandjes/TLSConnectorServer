# TLSConnectorServer
Server implementation for Android SafetyNet Attestation check. This implementation provides a nonce and validates SafetyNet's signed attestation. The SafetyNet check will pass when the integrity of the Android device and application is satisfied.

Path to request nonce (GET request): '/index.php/api/getnonce'. <br/>
Path to validates SafetyNet's signed attestation (POST request): '/index.php/api/validatejws'. <br/>
    The signed attestation needs to in a POST request encapsulated in variable with the name 'jws'.

Configuration:
- Set package name of Android application in '$APKpackageNameExpected'.
- Set certificate hash which signed the APK of the Android application in '$APKCertificateDigestSha256Expected'.
<br/>
NOTE: A client implementation (Android application) for the SafetyNet Attestation check is required. See: https://github.com/CeesMandjes/TLSConnector
<br/><br/>
