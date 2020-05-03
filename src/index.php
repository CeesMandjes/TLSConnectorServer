<?php
/*
    Server implementation for Android SafetyNet Attestation check. This implementation provides a nonce and validates SafetyNet's signed attestation. 
    The SafetyNet check will pass when the integrity of the Android device and application is satisfied.

    Path to request nonce (GET request): '/index.php/api/getnonce'
    Path to validates SafetyNet's signed attestation (POST request): '/index.php/api/validatejws' 
        The signed attestation needs to in a POST request encapsulated in variable with the name 'jws'

    Configuration:
    - Set package name of Android application in '$APKpackageNameExpected'
    - Set certificate hash which signed the APK of the Android application in '$APKCertificateDigestSha256Expected'

    @author Cees Mandjes
*/

// Database file for the Nonce for SafetyNet session
$nonceFile = "nonce.txt";
// Path to the CA certificate of SafetyNet's attestation
$googleCertificateFile = "GoogleCertificate.pem";
// Expected parameters value for application for SafetyNet validation
$APKpackageNameExpected = "com.example.tlsconnector";
$APKCertificateDigestSha256Expected = "11a4fc5754ded4c10144a02b974998c9b5da7c0b1d06220517b6f78a528d97eb";
$ctsProfileMatchExpected = "true";
$basicIntegrityExpected = "true";
 
// Entry point of the application
$request = str_replace("/index.php", "", $_SERVER["REQUEST_URI"]);
 
// First step for SafetyNet check is to get a nonce
if (0 === strpos($request, "/api/getnonce")) 
{
    // Get signed attestestion in JWS format
    $nonce = generateNonce($nonceFile);
    echo $nonce;
// Second step for SafetyNet check is to validate SafetyNet's attestation
} 
elseif (0 === strpos($request, "/api/validatejws")) 
{
    // Get signed attestestion in JWS format
    $rawJWS = getJWSRaw();
    if($rawJWS !== null)
    {
        // Read expected nonce from the database file, this nonce is generated upon the first request
        $nonceExpected = file_get_contents($nonceFile);
        // Verify the signature of the provided attestation
        $isJWSSignatureValid = verifyJWSIntegrity($rawJWS, $googleCertificateFile);
        // Validate the payload of the provided attestion
        $isJWSPayloadValid = validateJWS($rawJWS, $nonceExpected, $APKpackageNameExpected, $APKCertificateDigestSha256Expected, $ctsProfileMatchExpected, $basicIntegrityExpected);
        //Final result
        if ($isJWSSignatureValid === true && $isJWSPayloadValid === true) 
        {
            echo "Android Safetynet Attestation check passed.";
        } 
        else 
        {
            echo "Android Safetynet Attestation check failed.";
        }
    }
// Invalid request
} 
else 
{
    echo "Error: Invalid request.";
}
 
/**
* Generates a nonce, stores it in the database file and returns the nonce to the user.
*
* @param String $fileName Name the database file
*
* @return Nonce
*/
function generateNonce($fileName)
{
    // generates a new nonce
    $cstrong = true;
    $nonce = base64_encode(openssl_random_pseudo_bytes(32, $cstrong));
    //Store nonce in database file
    $newFile= fopen($fileName, "w+");
    fwrite($newFile, $nonce);
    fclose($newFile);
    //Return nonce
    return $nonce;
}
 
/**
* Gets SafetyNet's signed attestion, in JWS format, from the POST body. The attestion should be given in POST's parameter "jws".
*
* @return SafetyNet attestion in JWS format
*/
function getJWSRaw()
{
    if (!isset($_POST["jws"]) || $_POST["jws"] == "") 
    {
        echo "Error: JWS object not sent to server via a POST request. ";
        return null;
    }
    // Check whether the provided attestion is in JWS format
    $rawJWS = $_POST["jws"];
    if (count(explode(".", $rawJWS)) === 3) 
    {
        return $_POST["jws"];
    }
    echo "Error: Provided attestion is not in JWS format. ";
    return null;
}
 
/**
* Verifies SafetyNet's signed attestion in JWS format. By verifying the signature itself and whether the CA of the certificate used for this signature is Google"s root certificate.
*
* @param String $rawJWS SafetyNet's signed attestion in JWS format
* @param String $googleCertificateFile Path to Google"s root certificate
*
* @return Whether the SafetyNet's attestion signature and the certificate used for this is correct
*/
function verifyJWSIntegrity($rawJWS, $googleCertificateFile)
{
    list($headerEncoded, $payloadEncoded, $signatureEncoded) = explode(".", $rawJWS);   
    $header = json_decode(base64_decode($headerEncoded), true);
    $signature = base64_decode(strtr($signatureEncoded, "-_", "+/"));
 
    if (strtolower($header["alg"]) === "none")
    {
        echo "Error: alg is not defined in provided JWS. ";
        return false;
    }
    $certJWS = getCertificateInPemFormat($header);
    $validateJWSSignature = verifyJWSSignature($headerEncoded, $payloadEncoded, $signature, $certJWS);
    $validateCertificate = verifyCertificate($certJWS, $googleCertificateFile);
 
    if ($validateJWSSignature && $validateCertificate)
    {
 
        return true;
    }   
    return false;
}
 
/**
* Extracts the certificate from SafetyNet's signed attestion header, and returns it in PEM format.
*
* @param JSON $headerJWS SafetyNet's signed attestion header
*
* @return Certificate in PEM format
*/
function getCertificateInPemFormat($headerJWS)
{
    $certPEMFormat = "-----BEGIN CERTIFICATE-----\r\n" . chunk_split($headerJWS["x5c"][0], 64, "\r\n") . "-----END CERTIFICATE-----\r\n";
    return openssl_x509_read($certPEMFormat);
}
 
/**
* Verifies SafetyNet's signed attestion certificate by checking whether this certificate"s CA is Google's root certificate.
*
* @param PEM $certJWS SafetyNet's signed attestion certificate in PEM format
* @param String $googleCertificateFile Path to Google"s root certificate
*
* @return Whether the SafetyNet's attestion certificate is correct
*/
function verifyCertificate($certJWS, $googleCertificateFile)
{
    openssl_x509_export_to_file($certJWS, "jwsCertificate.pem");
    exec("openssl verify -CAfile ". $googleCertificateFile ." jwsCertificate.pem", $output, $return_var);

    if ($return_var === 0) 
    {
        return true;
    }
    return false;
}
 
/**
* Verifies SafetyNet's signed attestion signature.
*
* @param String $headerJWSEncoded SafetyNet's signed attestion encoded header
* @param String $payloadEncoded SafetyNet's signed attestion encoded payload
* @param String $signature SafetyNet's signed attestion signature
* @param PEM $certJWS SafetyNet's signed attestion certificate in PEM format
*
* @return Whether SafetyNet's attestion signature is correct
*/
function verifyJWSSignature($headerJWSEncoded, $payloadEncoded, $signature, $certJWS)
{
    $certJWSPubKey = openssl_pkey_get_public($certJWS);
    $payLoadToVerify = utf8_decode($headerJWSEncoded . "." . $payloadEncoded);
    return openssl_verify($payLoadToVerify, $signature, $certJWSPubKey, OPENSSL_ALGO_SHA256);
}

/**
* Validates SafetyNet's signed attestion payload by the given expected values. When it did not pass the SafetyNet check, it prints Google's given advice.
*
* @param String $rawJWS SafetyNet's signed attestion
* @param String $nonceExpected Expected nonce
* @param String $APKpackageNameExpected Expected APK package name
* @param String $APKDigestSha256Expected Expected APK SHA256 digest
* @param String $APKCertificateDigestSha256Expected Expected APK SHA265 certificate
*
* @return Whether SafetyNet's attestion payload matches the given expected values
*/
function validateJWS($rawJWS, $nonceExpected, $APKpackageNameExpected, $APKCertificateDigestSha256Expected, $ctsProfileMatchExpected, $basicIntegrityExpected)
{
    $payload = getJWSPayload($rawJWS);
    $result = validateJWSPayload($payload, $nonceExpected, $APKpackageNameExpected, $APKCertificateDigestSha256Expected, $ctsProfileMatchExpected, $basicIntegrityExpected);
    //When it did not pass the SafetyNet check, it prints Google's given advice
    if($result === false)
    {
        printAdvice($payload);
    }
    return $result;
}
 
/**
* Gets SafetyNet's signed attestion payload.
*
* @param String $rawJWS SafetyNet's signed attestion
*
* @return SafetyNet's signed attestion payload in JSON format
*/
function getJWSPayload($rawJWS)
{
    $jwsSplit = explode(".", $rawJWS);
    if (count($jwsSplit) !== 3) {
        echo "Error: JWS string must contain 3 dot separated component. ";
        return null;
    }
    $jwsPayload = $jwsSplit[1];
    // TODO: Remove, writes last received raw JWS in a file for analysis.
    $newFile= fopen("jwsRaw.txt", "w+");
    fwrite($newFile, $rawJWS);
    fclose($newFile);
    // TODO: Remove, writes last received JWS payload in a file for analysis.
    $newFile= fopen("jwsPayload.txt", "w+");
    fwrite($newFile, print_r(json_decode(base64_decode($jwsPayload), true),true));
    fclose($newFile);
    return json_decode(base64_decode($jwsPayload), true);
}
 
/**
* Gets each parameter from the provided SafetyNet's signed attestion payload, and compares it with the given expected value.
*
* @param JSON $payloadJWS SafetyNet's signed attestion payload in JSON format
* @param String $nonceExpected Expected nonce
* @param String $APKpackageNameExpected Expected APK package name
* @param String $APKDigestSha256Expected Expected APK SHA256 digest
* @param String $APKCertificateDigestSha256Expected Expected APK SHA265 certificate
*
* @return Whether each parameter of the provided SafetyNet's attestion payload matches the given expected values
*/
function validateJWSPayload($payloadJWS, $nonceExpected, $APKpackageNameExpected, $APKCertificateDigestSha256Expected, $ctsProfileMatchExpected, $basicIntegrityExpected)
{
    $nonceReceived = base64_decode($payloadJWS["nonce"]);
    $APKpackageNameRecieved = $payloadJWS["apkPackageName"];
    $APKCertificateDigestSha256Received = bin2hex(base64_decode($payloadJWS["apkCertificateDigestSha256"][0]));   
    $ctsProfileMatchReceieved = $payloadJWS["ctsProfileMatch"] ? "true" : "false";
    $basicIntegrityReceived = $payloadJWS["basicIntegrity"] ? "true" : "false"; 

    $nonceIsValid = isInputEqualToExpected($nonceReceived, $nonceExpected, "nonce");
    $APKpackageNameIsValid = isInputEqualToExpected($APKpackageNameRecieved, $APKpackageNameExpected, "APK package name");
    $APKCertificateDigestSha256IsValid = isInputEqualToExpected($APKCertificateDigestSha256Received, $APKCertificateDigestSha256Expected, "APK certificate digest Sha256");
    $ctsProfileMatchIsValid = isInputEqualToExpected($ctsProfileMatchReceieved, $ctsProfileMatchExpected, "ctsProfileMatch");
    $basicIntegrityIsValid = isInputEqualToExpected($basicIntegrityReceived, $basicIntegrityExpected, "basicIntegrity"); 
    //Check whether it passess the SafetyNet check
    if ($nonceIsValid === true && $APKpackageNameIsValid === true && $APKCertificateDigestSha256IsValid === true &&
        $ctsProfileMatchIsValid === true && $basicIntegrityIsValid === true)
    {
        return true;
    }
    return false; 
}
 
/**
* Compares provided input with an expecter value. Prints an error when it does not match.
*
* @param String $input Input value
* @param String $expected Expected value
* @param String $inputName Name of value
*
* @return Whether the given Input and Expectec value matches
*/
function isInputEqualToExpected($input, $expected, $inputName)
{
    if (strcmp($input, $expected) === 0) 
    {
        return true;
    }
    echo "Error: The provided $inputName does not correspond with the expected value (Provided:[$input] Expected:[$expected]). ";
    return false;
}

/**
* Checks whether Google gave an advive in the provided SafetyNet's signed attestion payload. If that is the case, this function prints it.
*
* @param JSON $payloadJWS SafetyNet's signed attestion payload in JSON format
*/
function printAdvice($payloadJWS)
{
    if(array_key_exists("advice", $payloadJWS))
    {
        echo "Advice: " . $payloadJWS["advice"] . ". ";
    }
}
?>