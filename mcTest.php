<?php
require __DIR__ . '/../vendor/autoload.php';

use Mastercard\Developer\OAuth\Utils\AuthenticationUtils;
use Mastercard\Developer\OAuth\OAuth;
use Mastercard\Developer\Signers\CurlRequestSigner;
use Mastercard\Developer\Encryption\FieldValueEncoding;
use Mastercard\Developer\Utils\EncryptionUtils;
use Mastercard\Developer\Encryption\FieldLevelEncryption;

$consumerKey = 'iIJ3b3jFAClV4ujaSmBFkBdVCBho1UDAmQzzSOFr5e56b80f!06e94ea629234dc3bb179cac02729fd40000000000000000';
$signingKeyAlias = 'keyalias';
$signingKeyPassword = 'keystorepassword';
$signingKeyPkcs12FilePath = '../res/mdes/test_mc_tokenization-sandbox.p12';
$encryptionCertificateFilePath = "../res/mdes/digital-enablement-sandbox-encryption-key.crt";
$decryptionKeyFilePath = "../res/mdes/digital-enablement-sandbox-decryption-key.key";

$signingKey = AuthenticationUtils::loadSigningKey(
    $signingKeyPkcs12FilePath,
    $signingKeyAlias,
    $signingKeyPassword);

$uri = 'https://sandbox.api.mastercard.com/mdes/digitization/static/1/0/tokenize';


$method = 'POST';
$queryParams = array();
$fundingAccountInfo = [
    'encryptedPayload' => [
        'encryptedData' => [
            'cardAccountData' => [
                'accountNumber' => '5123456789012345',
                'expiryMonth' => '09',
                'expiryYear' => '25',
                'securityCode' => '123',
            ],
        ],
    ]
];


$decryptionKey = EncryptionUtils::loadDecryptionKey($signingKeyPkcs12FilePath, $signingKeyAlias, $signingKeyPassword);
$encryptionCertificate = EncryptionUtils::loadEncryptionCertificate($encryptionCertificateFilePath);

$config = \Mastercard\Developer\Encryption\FieldLevelEncryptionConfigBuilder::aFieldLevelEncryptionConfig()
//    ->withEncryptionPath('$.encryptedPayload.encryptedData', '$.encryptedPayload')
    ->withEncryptionPath('$.fundingAccountInfo.encryptedPayload.encryptedData', '$.fundingAccountInfo.encryptedPayload')

    ->withDecryptionPath('$.encryptedPayload', '$.encryptedPayload.encryptedData')
    ->withEncryptionCertificate($encryptionCertificate)
    ->withDecryptionKey($decryptionKey)
    ->withOaepPaddingDigestAlgorithm('SHA-512')
    ->withEncryptedValueFieldName('encryptedData')
    ->withEncryptedKeyFieldName('encryptedKey')
    ->withIvFieldName('iv')
    ->withOaepPaddingDigestAlgorithmFieldName('oaepHashingAlgorithm')
    ->withEncryptionCertificateFingerprintFieldName('publicKeyFingerprint')
    ->withEncryptionCertificateFingerprint('243E6992EA467F1CBB9973FACFCC3BF17B5CD007')

    ->withFieldValueEncoding(FieldValueEncoding::HEX)
    ->build();
$encryptedFundingAccountInfo = FieldLevelEncryption::encryptPayload(json_encode($fundingAccountInfo), $config);
$fundingAccountInfo = json_decode($encryptedFundingAccountInfo, true);

$payLoad=json_encode([
    'responseHost'=>'wayforpay.com',
    'requestId'=>microtime(true),
    'tokenType'=>'CLOUD',
    'tokenRequestorId'=>'98765432101',
    'fundingAccountInfo' => $fundingAccountInfo,
    'consumerLanguage'=>'en',
    'decisioningData'=>[
        'recommendation'=>'APPROVED',
        'recommendationAlgorithmVersion'=>'01',
    ],
]);
$header = ['Content-type: aplication/json'];


$authHeader = OAuth::getAuthorizationHeader($uri, $method, $payLoad, $consumerKey, $signingKey);

$req = 'curl '.$uri.' -H \'Content-type: aplication/json\' -H \'Authorization: '.$authHeader.'\' -d \''.$payLoad.'\'';
echo $req;
echo "\n\n";
echo `$req`;
echo "\n";
die();




$handle = curl_init($uri);
curl_setopt_array($handle, array(CURLOPT_RETURNTRANSFER => 1));
$signer = new CurlRequestSigner($consumerKey, $signingKey);
$signer->sign($handle, $method, $header, $payLoad);
curl_setopt($handle, CURLOPT_POSTFIELDS, $payLoad);

$result = curl_exec($handle);
curl_close($handle);
echo($result);
