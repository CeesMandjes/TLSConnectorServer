<?php
// Database file for the Nonce for SafetyNet session
$nonceFile = "nonce.txt";
// Path to the CA certificate of SafetyNet"s attestation
$googleCertificateFile = "GoogleCertificate.pem";
// Expected parameters value for application for SafetyNet validation
$APKpackageNameExpected = "com.example.tlsconnector";
$APKDigestSha256Expected = "56fb3dc8f1e859f4a0fa3b6db9fffd367ab405cfa3fb0c40993de6cb6da3908e";
$APKCertificateDigestSha256Expected = "11a4fc5754ded4c10144a02b974998c9b5da7c0b1d06220517b6f78a528d97eb";
 
// Entry point of the application
$request = str_replace("/index.php", "", $_SERVER["REQUEST_URI"]);
 
// First step for SafetyNet check is to get a nonce
if (0 === strpos($request, "/api/getnonce")) {
    // Get signed attestestion in JWS format
    $nonce = generateNonce($nonceFile);
    echo $nonce;
// Second step for SafetyNet check is to validate SafetyNet"s attestation
} elseif (0 === strpos($request, "/api/validatejws")) {
    // Get signed attestestion in JWS format
    $rawJWS = getJWSRaw();
    if($rawJWS !== null)
    {
        // Read expected nonce from the database file, this nonce is generated upon the first request
        $nonceExpected = file_get_contents($nonceFile);
        // Verify the signature of the provided attestation
        $isJWSSignatureValid = verifyJWSIntegrity($rawJWS, $googleCertificateFile);
        // Validate the payload of the provided attestion
        $isJWSPayloadValid = validateJWS($rawJWS, $nonceExpected, $APKpackageNameExpected, $APKDigestSha256Expected, $APKCertificateDigestSha256Expected);
        //Final result
        if ($isJWSSignatureValid === true && $isJWSPayloadValid === true) {
            echo "Succes: Android Safetynet check passed.";
        } else {
            echo "Error: Android Safetynet check failed.";
        }
    }
// Invalid request
} else {
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
* Gets SafetyNet"s signed attestion, in JWS format, from the POST body. The attestion should be given in POST"s parameter "jws".
*
* @return SafetyNet attestion in JWS format
*/
function getJWSRaw()
{
    if (!isset($_POST["jws"]) || $_POST["jws"] == "") {
        echo "Error: JWS object not sent to server via a POST request.";
        return null;
    }
    // Check whether the provided attestion is in JWS format
    $rawJWS = $_POST["jws"];
    if (count(explode(".", $rawJWS)) === 3) {
        return $_POST["jws"];
    }
    echo "Error: Provided attestion is not in JWS format.";
    return null;
}
 
/**
* Verifies SafetyNet"s signed attestion in JWS format. By verifying the signature itself and whether the CA of the certificate used for this signature is Google"s root certificate.
*
* @param String $rawJWS SafetyNet"s signed attestion in JWS format
* @param String $googleCertificateFile Path to Google"s root certificate
*
* @return Whether the SafetyNet"s attestion signature and the certificate used for this is correct
*/
function verifyJWSIntegrity($rawJWS, $googleCertificateFile)
{
    list($headerEncoded, $payloadEncoded, $signatureEncoded) = explode(".", $rawJWS);   
    $header = json_decode(base64_decode($headerEncoded), true);
    $signature = base64_decode(strtr($signatureEncoded, "-_", "+/"));
 
    if (strtolower($header["alg"]) === "none")
    {
        echo "Error: alg is not defined in provided JWS";
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
* Extracts the certificate from SafetyNet"s signed attestion header, and returns it in PEM format.
*
* @param JSON $headerJWS SafetyNet"s signed attestion header
*
* @return Certificate in PEM format
*/
function getCertificateInPemFormat($headerJWS)
{
    $certPEMFormat = "-----BEGIN CERTIFICATE-----\r\n" . chunk_split($headerJWS["x5c"][0], 64, "\r\n") . "-----END CERTIFICATE-----\r\n";
    return openssl_x509_read($certPEMFormat);
}
 
/**
* Verifies SafetyNet"s signed attestion certificate by checking whether this certificate"s CA is Google"s root certificate.
*
* @param PEM $certJWS SafetyNet"s signed attestion certificate in PEM format
* @param String $googleCertificateFile Path to Google"s root certificate
*
* @return Whether the SafetyNet"s attestion certificate is correct
*/
function verifyCertificate($certJWS, $googleCertificateFile)
{
    openssl_x509_export_to_file($certJWS, "jwsCertificate.pem");
    exec("openssl verify -CAfile ". $googleCertificateFile ." jwsCertificate.pem", $output, $return_var);
    if ($return_var === 0) {
        return true;
    }
    return false;
}
 
/**
* Verifies SafetyNet"s signed attestion signature.
*
* @param String $headerJWSEncoded SafetyNet"s signed attestion encoded header
* @param String $payloadEncoded SafetyNet"s signed attestion encoded payload
* @param String $signature SafetyNet"s signed attestion signature
* @param PEM $certJWS SafetyNet"s signed attestion certificate in PEM format
*
* @return Whether SafetyNet"s attestion signature is correct
*/
function verifyJWSSignature($headerJWSEncoded, $payloadEncoded, $signature, $certJWS)
{
    $certJWSPubKey = openssl_pkey_get_public($certJWS);
    $payLoadToVerify = utf8_decode($headerJWSEncoded . "." . $payloadEncoded);
    return openssl_verify($payLoadToVerify, $signature, $certJWSPubKey, OPENSSL_ALGO_SHA256);
}

/**
* Validates SafetyNet"s signed attestion payload by the given expected values.
*
* @param String $rawJWS SafetyNet"s signed attestion
* @param String $nonceExpected Expected nonce
* @param String $APKpackageNameExpected Expected APK package name
* @param String $APKDigestSha256Expected Expected APK SHA256 digest
* @param String $APKCertificateDigestSha256Expected Expected APK SHA265 certificate
*
* @return Whether SafetyNet"s attestion payload matches the given expected values
*/
function validateJWS($rawJWS, $nonceExpected, $APKpackageNameExpected, $APKDigestSha256Expected, $APKCertificateDigestSha256Expected)
{
    $payload = getJWSPayload($rawJWS);
    return validateJWSPayload($payload, $nonceExpected, $APKpackageNameExpected, $APKDigestSha256Expected, $APKCertificateDigestSha256Expected);
}
 
/**
* Gets SafetyNet"s signed attestion payload.
*
* @param String $rawJWS SafetyNet"s signed attestion
*
* @return SafetyNet"s signed attestion payload in JSON format
*/
function getJWSPayload($rawJWS)
{
    $jwsSplit = explode(".", $rawJWS);
    if (count($jwsSplit) !== 3) {
        echo "JWS string must contain 3 dot separated component";
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
* Gets each parameter from the provided SafetyNet"s signed attestion payload, and compares it with the given expected value.
*
* @param JSON $payloadJWS SafetyNet"s signed attestion payload in JSON format
* @param String $nonceExpected Expected nonce
* @param String $APKpackageNameExpected Expected APK package name
* @param String $APKDigestSha256Expected Expected APK SHA256 digest
* @param String $APKCertificateDigestSha256Expected Expected APK SHA265 certificate
*
* @return Whether each parameter of the provided SafetyNet"s attestion payload matches the given expected values
*/
function validateJWSPayload($payloadJWS, $nonceExpected, $APKpackageNameExpected, $APKDigestSha256Expected, $APKCertificateDigestSha256Expected)
{
    $nonceReceived = base64_decode($payloadJWS["nonce"]);
    $APKpackageNameRecieved = $payloadJWS["apkPackageName"];
    $APKDigestSha256Recieved = bin2hex(base64_decode($payloadJWS["apkDigestSha256"]));
    $APKCertificateDigestSha256Received = bin2hex(base64_decode($payloadJWS["apkCertificateDigestSha256"][0]));   
    $ctsProfileMatchReceieved = $payloadJWS["ctsProfileMatch"] ? "true" : "false";
    $basicIntegrityReceived = $payloadJWS["ctsProfileMatch"] ? "true" : "false";
 
    // When the apk is updated, its signature changes. By writing the last seen signature in a file, it is easier to update its value
    $newFile= fopen("apkSigFile.txt", "w+");
    fwrite($newFile, $APKDigestSha256Recieved);
    fclose($newFile); 
 
    $nonceIsValid = isInputEqualToExpected($nonceReceived, $nonceExpected, "nonce");
    $APKpackageNameIsValid = isInputEqualToExpected($APKpackageNameRecieved, $APKpackageNameExpected, "APK package name");
    $APKDigestSha256IsValid = isInputEqualToExpected($APKDigestSha256Recieved, $APKDigestSha256Expected, "APK digest Sha256");
    $APKCertificateDigestSha256IsValid = isInputEqualToExpected($APKCertificateDigestSha256Received, $APKCertificateDigestSha256Expected, "APK certificate digest Sha256");
    $ctsProfileMatchIsValid = isInputEqualToExpected($ctsProfileMatchReceieved, "true", "ctsProfileMatch");
    $basicIntegrityIsValid = isInputEqualToExpected($basicIntegrityReceived, "true", "basicIntegrity"); 
 
    if ($nonceIsValid === true && $APKpackageNameIsValid === true && $APKDigestSha256IsValid === true && $APKCertificateDigestSha256IsValid === true &&
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
    if (strcmp($input, $expected) === 0) {
        return true;
    }
    echo "Error: The provided $inputName does not correspond with the expected value (Provided:[$input] Expected:[$expected])";
    return false;
}
?>