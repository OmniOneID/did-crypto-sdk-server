---
puppeteer:
    pdf:
        format: A4
        displayHeaderFooter: true
        landscape: false
        scale: 0.8
        margin:
            top: 1.2cm
            right: 1cm
            bottom: 1cm
            left: 1cm
    image:
        quality: 100
        fullPage: false
---

Crypto SDK Server API
==

- title: Crypto SDK Server API
- author: Seung-Jae Yeo
- date: 2024-08-30
- version: v1.0.0

| Version | Date       | Changes               |
| ------- | ---------- | ---------------------- |
| v1.0.0  | 2024-08-30 | Initial creation       |


<div style="page-break-after: always;"></div>

# Table of Contents
- [1. APIs](#1-apis)
    - [1.1 CryptoUtils](#11-cryptoutils)
      - [1.1.1 generateKeyPair](#111-generatekeypair)
      - [1.1.2 compressPublicKey](#112-compresspublickey)
      - [1.1.3 unCompressPublicKey](#113-uncompresspublickey)
      - [1.1.4 generateNonce](#114-generatenonce)
      - [1.1.5 generateSalt](#115-generatesalt)
      - [1.1.6 generateSharedSecret](#116-generatesharedsecret)
      - [1.1.7 pbkdf2](#117-pbkdf2)
      - [1.1.8 encrypt](#118-encrypt)
      - [1.1.9 decrypt](#119-decrypt)
    - [1.2 DigestUtils](#12-digestutils)
      - [1.2.1 getDigest](#121-getdigest)
    - [1.3 MultiBaseUtils](#13-multibaseutils)
      - [1.3.1 encode](#131-encode)
      - [1.3.2 decode](#132-decode)
    - [1.4 SignatureUtils](#14-signatureutils)
      - [1.4.1 generateCompactSignature](#141-generatecompactsignature)
      - [1.4.2 generateEccSignatureFromHashedData](#142-generateeccsignaturefromhasheddata)
      - [1.4.3 convertToCompactSignature](#143-converttocompactsignature)
      - [1.4.4 verifyCompactSignWithCompressedKey](#144-verifycompactsignwithcompressedkey)
- [2. Enumerator](#2-enumerator)
    - [2.1 DidKeyType](#21-didkeytype)
    - [2.2 EccCurveType](#22-ecccurvetype)
    - [2.3 EncryptionType](#23-encryptiontype)
    - [2.4 EncryptionMode](#24-encryptionmode)
    - [2.5 SymmetricKeySize](#25-symmetrickeysize)
    - [2.6 SymmetricPaddingType](#26-symmetricpaddingtype)
    - [2.7 SymmetricCipherType](#27-symmetricciphertype)
    - [2.8 DigestType](#28-digesttype)
    - [2.9 MultiBaseType](#29-multibasetype)
- [3. Reference Classes](#3-reference-classes)
    - [3.1 KeyPairInterface](#31-keypairinterface)
    - [3.2 CipherInfo](#32-cipherinfo)
    - [3.3 EcKeyPair](#33-eckeypair)
# 1. APIs
## 1.1 CryptoUtils

## 1.1.1 generateKeyPair

### Class Name
`CryptoUtils`

### Function Name
`generateKeyPair`

### Function Description
`Generates a key pair consisting of a public key and a private key.`

### Input Parameters

| Parameter | Type         | Description              | **M/O** | **Notes**          |
|-----------|--------------|--------------------------|---------|--------------------|
| didKeyType | DidKeyType   | Did key type Enum         | M       | [Link](#21-didkeytype) |

### Output Parameters

| Type              | Description              | **M/O** | **Notes**            |
|-------------------|--------------------------|---------|----------------------|
| KeyPairInterface  | KeyPair interface         | M       | [Link](#31-keypairinterface) |

### Function Declaration

```java
KeyPairInterface generateKeyPair(DidKeyType didKeyType) -> throws CryptoException
```

### Function Usage
```java
String didKeyTypeStr = "Secp256r1VerificationKey2018";
DidKeyType didKeyType = DidKeyType.fromString(didKeyTypeStr);

KeyPairInterface ecKeyPair = CryptoUtils.generateKeyPair(didKeyType);
```

<br>

## 1.1.2 compressPublicKey

### Class Name
`CryptoUtils`

### Function Name
`compressPublicKey`

### Function Description
`Compresses an ECC type public key.`

### Input Parameters

| Parameter                      | Type          | Description                                 | **M/O** | **Note** |
|--------------------------------|---------------|---------------------------------------------|---------|----------|
| unCompressedPublicKeyBytes     | byte[]        | Uncompressed public key in byte array type | M       |          |
| eccCurveType                   | EccCurveType  | Elliptic curve type Enum                    | M       | [Link](#22-ecccurvetype) |

### Output Parameters

| Type   | Description                         | **M/O** | **Note** |
|--------|-------------------------------------|---------|----------|
| byte[] | Compressed public key in byte array type | M       |          |

### Function Declaration

```java
byte[] compressPublicKey(byte[] unCompressedPublicKeyBytes, EccCurveType eccCurveType) -> throws CryptoException
```

### Function Usage
```java
String eccCurveTypeStr = "Secp256r1";
EccCurveType eccCurveType = EccCurveType.fromString(eccCurveTypeStr);

PublicKey pubKey = (ECPublicKey)keyPair.getPublicKey();

byte[] compressPubKey = CryptoUtils.compressPublicKey(pubKey.getEncoded(), eccCurveType);
```

<br>

## 1.1.3 unCompressPublicKey

### Class Name
`CryptoUtils`

### Function Name
`unCompressPublicKey`

### Function Description
`Uncompresses a compressed public key.`

### Input Parameters

| Parameter               | Type            | Description                  | **M/O** | **Notes**                  |
|-------------------------|-----------------|------------------------------|---------|------------------------------|
| compressedPublicKey   | byte[]          | compressed public key in byte array type | M       |                              |
| eccCurveType            | EccCurveType    | Elliptic curve type Enum      | M       | [Link](#22-ecccurvetype)     |

### Output Parameters

| Type    | Description                           | **M/O** | **Notes** |
|---------|---------------------------------------|---------|-------------|
| byte[]  | Uncompressed public key as a byte array | M       |             |

### Function Declaration

```java
byte[] unCompressPublicKey(byte[] compressedPublicKey, EccCurveType eccCurveType) -> throws CryptoException
```

### Function Usage
```java
String eccCurveTypeStr = "Secp256r1";
EccCurveType eccCurveType = EccCurveType.fromString(eccCurveTypeStr);

String multiBaseTypeStr = "f";
MultiBaseType multiBaseType = MultiBaseType.getByCharacter(multiBaseTypeStr);

byte[] compressPubKey = CryptoUtils.compressPublicKey(pubKey.getEncoded(), eccCurveType);
byte[] unCompressPubKey = CryptoUtils.unCompressPublicKey(compressPubKey, eccCurveType);
```

<br>

## 1.1.4 generateNonce

### Class Name
`CryptoUtils`

### Function Name
`generateNonce`

### Function Description
`Generates a nonce value.`

### Input Parameters
| Parameter | Type | Description               | **M/O** | **Notes** |
|-----------|------|---------------------------|---------|-------------|
| length    | int  | Length of the nonce to generate | M       |             |


### Output Parameters
| Type    | Description           | **M/O** | **Notes** |
|---------|-----------------------|---------|-------------|
| byte[]  | Generated nonce       | M       |             |

### Function Declaration

```java
byte[] generateNonce(int length) -> throws CryptoException
```

### Function Usage
```java
int nonceLength = 16;
byte[] nonce = CryptoUtils.generateNonce(nonceLength);
```

<br>

## 1.1.5 generateSalt

### Class Name
`CryptoUtils`

### Function Name
`generateSalt`

### Function Description
`Generates a salt value.`

### Input Parameters

n/a

### Output Parameters

| Type   | Description     | **M/O** | **Notes** |
|--------|-----------------|---------|-------------|
| byte[] | Generated salt value | M | |


### Function Declaration

```java
byte[] generateSalt() -> throws CryptoException
```

### Function Usage
```java
byte[] salt = CryptoUtils.generateSalt();
```

<br>

## 1.1.6 generateSharedSecret

### Class Name
`CryptoUtils`

### Function Name
`generateSharedSecret`

### Function Description
`Generates a SharedSecret used for encryption/decryption using ECC keys.`<br/> `Only SECP256R1 and SECP256K1 types of encryption keys are available.`

### Input Parameters

| Parameter    | Type         | Description          | **M/O** | **Notes**                  |
|--------------|--------------|----------------------|---------|----------------------------|
| compressedPublicKeyBytes    | byte[]       | Receiver's compressed public key | M       |                            |
| privateKeyBytes   | byte[]       | Sender's private key  | M       |                            |
| eccCurveType | EccCurveType | Elliptic curve type Enum | M       | [Link](#22-ecccurvetype)   |


### Output Parameters

| Type   | Description        | **M/O** | **Notes** |
|--------|--------------------|---------|-----------|
| byte[] | SharedSecret value | M       |           |


### Function Declaration

```java
byte[] generateSharedSecret(byte[] compressedPublicKeyBytes, byte[] privateKey, EccCurveType eccCurveType) -> throws CryptoException
```

### Function Usage
```java
EccCurveType eccCurveType = ecKeyPair.getECType()

byte[] priKey = ((ECPrivateKey) ecKeyPair.getPrivateKey()).getEncoded();
byte[] compressPubKey = CryptoUtils.compressPublicKey(pubKey.getEncoded(), eccCurveType);

byte[] sharedSecret = CryptoUtils.generateSharedSecret(compressPubKey, priKey, eccCurveType);
```

<br>

## 1.1.7 pbkdf2

### Class Name
`CryptoUtils`

### Function Name
`pbkdf2`

### Function Description
`Derives an encryption key from the wallet password using the PBKDF2 algorithm.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **Notes** |
|-----------|--------|----------------------------|---------|----------|
| password  | char[] | Password                   | M       |          |
| salt      | byte[] | Encryption salt            | M       |          |
| iterator  | int    | Number of iterations       | M       |          |
| keySize   | int    | Length of the key to be generated | M |          |


### Output Parameters

| Type    | Description                | **M/O** | **Notes** |
|---------|----------------------------|---------|----------|
| byte[]  | Key derived through PBKDF2 | M       |          |


### Function Declaration

```java
byte[] pbkdf2(char[] password, byte[] salt, int iterator, int keySize) -> throws CryptoException
```

### Function Usage
```java
byte[] password;
byte[] salt = CryptoUtils.generateSalt();

int iterator;
int keySize;

byte[] derivedKey = CryptoUtils.pbkdf2(char[] password, byte[] salt, int iterator, int keySize)
```

<br>

## 1.1.8 encrypt

### Class Name
`CryptoUtils`

### Function Name
`encrypt`

### Function Description
`Encrypts data using the AES algorithm.`

### Input Parameters

| Parameter   | Type        | Description                  | **M/O** | **Notes**          |
|-------------|-------------|------------------------------|---------|--------------------|
| source      | byte[]      | The plaintext data to be encrypted | M       |                    |
| cipherInfo  | CipherInfo  | Encryption information       | M       | [Link](#32-cipherinfo) |
| key         | byte[]      | Encryption key               | M       |                    |
| iv          | byte[]      | Initialization Vector (IV)   | M       |                    |



### Output Parameters

| Type   | Description | **M/O** | **Notes** |
|--------|-------------|---------|-----------|
| byte[] | Ciphertext  | M       |           |


### Function Declaration

```java
byte[] encrypt(byte[] source, CipherInfo cipherInfo, byte[] key, byte[] iv) -> throws CryptoException
```

### Function Usage
```java
String cipherTypeStr = "AES-256-CBC";
String paddingTypeStr = "PKCS5Padding";

SymmetricCipherType symCipherType = SymmetricCipherType.fromString(cipherTypeStr);
SymmetricPaddingType symPaddingType = SymmetricPaddingType.fromString(paddingTypeStr);

CipherInfo cipherInfo = new CipherInfo(symCipherType, symPaddingType);

// Key and iv values derived from SharedSecret
byte[] key;
byte[] iv;

String testData = "EncData";

byte[] encData = CryptoUtils.encrypt(testData.getBytes(), cipherInfo, key, iv);
```

<br>

## 1.1.9 decrypt

### Class Name
`CryptoUtils`

### Function Name
`decrypt`

### Function Description
`Decrypts data encrypted using the AES algorithm.`

### Input Parameters

| Parameter    | Type        | Description               | **M/O** | **Notes** |
|--------------|-------------|---------------------------|---------|-------------|
| cipherText   | byte[]      | The encrypted data to be decrypted | M       |             |
| cipherInfo   | CipherInfo  | Encryption information     | M       | [Link](#32-cipherinfo) |
| key          | byte[]      | Decryption key            | M       |             |
| iv           | byte[]      | Initialization Vector (IV) | M       |             |



### Output Parameters

| Type   | Description         | **M/O** | **Notes** |
|--------|---------------------|---------|-------------|
| byte[] | Plaintext data      | M       |             |


### Function Declaration

```java
byte[] decrypt(byte[] cipherText, CipherInfo cipherInfo, byte[] key, byte[] iv) -> throws CryptoException
```

### Function Usage
```java
String cipherTypeStr = "AES-256-CBC";
String paddingTypeStr = "PKCS5Padding";

SymmetricCipherType symCipherType = SymmetricCipherType.fromString(cipherTypeStr);
SymmetricPaddingType symPaddingType = SymmetricPaddingType.fromString(paddingTypeStr);

CipherInfo cipherInfo = new CipherInfo(symCipherType, symPaddingType);

// Key and IV derived from SharedSecret
byte[] key;
byte[] iv;

String encodedEncData = "f2516f7865d2e99635a4d6934f3328966ad55d191e02d83da7b8d616b20cb9b0f";
byte[] encData = MultiBaseUtils.decode(encodedEncData);

byte[] decData = CryptoUtils.decrypt(encData, cipherInfo, key, iv);
```

<br>

## 1.2 DigestUtils

## 1.2.1 getDigest

### Class Name
`CryptoUtils`

### Function Name
`getDigest`

### Function Description
`Hashes data using SHA functions.`

### Input Parameters

| Parameter  | Type       | Description          | **M/O** | **Notes** |
|------------|------------|----------------------|---------|-----------|
| source     | byte[]     | Original data        | M       |           |
| digestType | DigestType | Hash algorithm type  | M       | [Link](#28-digesttype) |

### Output Parameters

| Type   | Description   | **M/O** | **Notes** |
|--------|---------------|---------|-----------|
| byte[] | Hash data     | M       |           |

### Function Declaration

```java
byte[] getDigest(byte[] source, DigestType digestType) throws CryptoException
```

### Function Usage
```java
String digestTypeStr = "sha256";
DigestType digestType = DigestType.fromString(digestTypeStr);

String testData = "Test Data";
byte[] sha256 = DigestUtils.getDigest(testData.getBytes(), digestType);
```

<br>

## 1.3 MultiBaseUtils

## 1.3.1 encode

### Class Name
`MultiBaseUtils`

### Function Name
`encode`

### Function Description
`Converts binary data into characters based on the selected MultiBase type.`

### Input Parameters

| Parameter | Type            | Description            | **M/O** | **Notes** |
|-----------|-----------------|------------------------|---------|-----------|
| source    | byte[]          | Original data          | M       |           |
| baseType  | MultiBaseType   | MultiBase encoding type| M       | [Link](#29-multibasetype) |


### Output Parameters

| Type   | Description         | **M/O** | **Notes** |
|--------|---------------------|---------|-----------|
| String | Encoded data        | M       |           |


### Function Declaration

```java
String encode(byte[] source, MultiBaseType baseType) throws CryptoException
```

### Function Usage
```java
String multiBaseTypeStr = "f";
MultiBaseType multiBaseType = MultiBaseType.getByCharacter(multiBaseTypeStr);

byte[] testData = "testData".getBytes();
String encoded = MultiBaseUtils.encode(testData, multiBaseType);
```

<br>

## 1.3.2 decode

### Class Name
`MultiBaseUtils`

### Function Name
`decode`

### Function Description
`Decodes data encoded in MultiBase format.`

### Input Parameters

| Parameter | Type   | Description          | **M/O** | **Notes** |
|-----------|--------|----------------------|---------|-----------|
| multibase | String | Encoded data         | M       |           |


### Output Parameters

| Type   | Description    | **M/O** | **Notes** |
|--------|----------------|---------|-----------|
| byte[] | Original data  | M       |           |


### Function Declaration

```java
byte[] decode(String multibase) throws CryptoException
```

### Function Usage
```java
String multibaseBase16 = "f68656c6c6f2c20776f726c6421";

byte[] source = MultiBaseUtils.decode(multibaseBase16);
```

<br>

## 1.4 SignatureUtils

## 1.4.1 generateCompactSignature

### Class Name
`SignatureUtils`

### Function Name
`generateCompactSignature`

### Function Description
`Signs data using an elliptic curve key with the ECDSA algorithm, generates a signature value in ASN.1 DER format, and then converts it to a Compact signature.`

### Input Parameters

| Parameter       | Type           | Description                      | **M/O** | **Notes**                      |
|-----------------|----------------|----------------------------------|---------|----------------------------------|
| keyPair         | EcKeyPair      | Elliptic curve key pair           | M       | [Link](#33-eckeypair)             |
| hashedSource    | byte[]         | Hashed source data                | M       |                                  |
| eccCurveType    | EccCurveType   | Elliptic curve algorithm          | M       | [Link](#22-ecccurvetype)          |


### Output Parameters

| Type    | Description            | **M/O** | **Notes** |
|---------|------------------------|---------|-------------|
| byte[]  | Signed data            | M       |             |


### Function Declaration

```java
byte[] generateCompactSignature(EcKeyPair keyPair, byte[] hashedSource, EccCurveType eccCurveType) -> throws CryptoException
```

### Function Usage
```java
String didKeyTypeStr = "Secp256r1VerificationKey2018";
DidKeyType didKeyType = DidKeyType.fromString(didKeyTypeStr);

String eccCurveTypeStr = "Secp256r1";
EccCurveType eccCurveType = EccCurveType.fromString(eccCurveTypeStr);

EcKeyPair keyPair = (EcKeyPair) CryptoUtils.generateKeyPair(didKeyType);

String rawData = "SignatureData";

String digestTypeStr = "sha256";
DigestType digestType = DigestType.fromString(digestTypeStr);

byte[] hashedsource = DigestUtils.getDigest(rawData.getBytes(), digestType);
byte[] compactSign = SignatureUtils.generateCompactSignature(keyPair, hashedsource, eccCurveType);
```

<br>

## 1.4.2 generateEccSignatureFromHashedData

### Class Name
`SignatureUtils`

### Function Name
`generateEccSignatureFromHashedData`

### Function Description
`Generates a signature value in ASN.1 DER format using an elliptic curve key with the ECDSA algorithm.`

### Input Parameters

| Parameter      | Type          | Description                  | **M/O** | **Notes**                        |
|----------------|---------------|------------------------------|---------|----------------------------------|
| privateKey     | PrivateKey    | Signature private key         | M       | Refer to `java.security.PrivateKey` |
| hashedSource   | byte[]        | Hashed source data            | M       |                                  |


### Output Parameters

| Type   | Description        | **M/O** | **Notes** |
|--------|--------------------|---------|-----------|
| byte[] | Signed data        | M       |           |


### Function Declaration

```java
byte[] generateEccSignatureFromHashedData(PrivateKey privateKey, byte[] hashedSource) -> throws CryptoException
```

### Function Usage
```java
String didKeyTypeStr = "Secp256r1VerificationKey2018";
DidKeyType didKeyType = DidKeyType.fromString(didKeyTypeStr);

String eccCurveTypeStr = "Secp256r1";
EccCurveType eccCurveType = EccCurveType.fromString(eccCurveTypeStr);

EcKeyPair keyPair = (EcKeyPair) CryptoUtils.generateKeyPair(didKeyType);

String rawData = "SignatureData";

String digestTypeStr = "sha256";
DigestType digestType = DigestType.fromString(digestTypeStr);

byte[] hashedsource = DigestUtils.getDigest(rawData.getBytes(), digestType);

byte[] eccSign = SignatureUtils.generateEccSignatureFromHashedData((PrivateKey)keyPair.getPrivateKey(), hashedsource);
```

<br>

## 1.4.3 convertToCompactSignature

### Class Name
`SignatureUtils`

### Function Name
`convertToCompactSignature`

### Function Description
`Converts a signature value in ASN.1 DER format to a compact signature.`

### Input Parameters

| Parameter      | Type          | Description           | **M/O** | **Notes**                 |
|----------------|---------------|-----------------------|---------|---------------------------|
| publicKey      | PublicKey      | The public key for signing | M       | Refer to java.security.PublicKey |
| hashedSource   | byte[]         | The hashed original data | M       |                           |
| signatureBytes | byte[]         | ECDSA signature value  | M       |                           |
| eccCurveType   | EccCurveType   | Elliptic curve algorithm | M       | [Link](#22-ecccurvetype)  |


### Output Parameters

| Type   | Description           | **M/O** | **Notes** |
|--------|-----------------------|---------|-----------|
| byte[] | Compressed signature data | M       |           |


### Function Declaration

```java
byte[] convertToCompactSignature(PublicKey publicKey, byte[] hashedsource, byte[] signatureBytes, EccCurveType eccCurveType) -> throws CryptoException
```

### Function Usage
```java
String didKeyTypeStr = "Secp256r1VerificationKey2018";
DidKeyType didKeyType = DidKeyType.fromString(didKeyTypeStr);

String eccCurveTypeStr = "Secp256r1";
EccCurveType eccCurveType = EccCurveType.fromString(eccCurveTypeStr);

EcKeyPair keyPair = (EcKeyPair) CryptoUtils.generateKeyPair(didKeyType);

String rawData = "SignatureData";

String digestTypeStr = "sha256";
DigestType digestType = DigestType.fromString(digestTypeStr);

byte[] hashedsource = DigestUtils.getDigest(rawData.getBytes(), digestType);

byte[] eccSign = SignatureUtils.generateEccSignatureFromHashedData((PrivateKey)keyPair.getPrivateKey(), hashedsource, eccCurveType);

byte[] compactSign = SignatureUtils.convertToCompactSignature((PublicKey)keyPair.getPublicKey(), hashedsource, eccSign, eccCurveType);
```

<br>

## 1.4.4 verifyCompactSignWithCompressedKey

### Class Name
`SignatureUtils`

### Function Name
`verifyCompactSignWithCompressedKey`

### Function Description
`Verifies the compact signature.`

### Input Parameters

| Parameter                | Type            | Description                    | **M/O** | **Notes**                         |
|--------------------------|-----------------|--------------------------------|---------|-----------------------------------|
| compressedpublicKeyBytes | byte[]          | Compressed public key           | M       |                                   |
| hashedsource             | byte[]          | Hashed original data            | M       |                                   |
| signatureBytes           | byte[]          | Compressed ECDSA signature      | M       |                                   |
| eccCurveType             | EccCurveType    | Elliptic curve algorithm        | M       | [Link](#22-ecccurvetype)          |


### Output Parameters

void


### Function Declaration

```java
void verifyCompactSignWithCompressedKey(byte[] compressedpublicKeyBytes, byte[] hashedsource, byte[] signatureBytes, EccCurveType eccCurveType) -> throws CryptoException
```

### Function Usage
```java
String eccCurveTypeStr = "Secp256r1";
EccCurveType eccCurveType = EccCurveType.fromString(eccCurveTypeStr);

byte[] uncompressedPublicKeyBytes = publicKey.getEncoded();
byte[] compressedPublicKeyBytes = CryptoUtils.compressPublicKey(uncompressedPublicKeyBytes, eccCurveType);

// Hashed signature source
byte[] hashedSource;
// Compact signature value
byte[] compactSign;

SignatureUtils.verifyCompactSignWithCompressedKey(compressedPublicKeyBytes, hashedsource, compactSign, eccCurveType);
```

<br>

# Enumerator
## 2.1 DidKeyType

### Declaration
```java
public enum DidKeyType {
  RSA_VERIFICATION_KEY_2018("RsaVerificationKey2018"), 
  SECP256K1_VERIFICATION_KEY_2018("Secp256k1VerificationKey2018"),
  SECP256R1_VERIFICATION_KEY_2018("Secp256r1VerificationKey2018");
}
```
### Usage
```java
String didKeyTypeStr = "Secp256r1VerificationKey2018";

DidKeyType didKeyType = DidKeyType.fromString(didKeyTypeStr);
```

## 2.2 EccCurveType

### Declaration

```java
public enum EccCurveType {
	Secp256k1("Secp256k1"),
	Secp256r1("Secp256r1");
}
```

### Usage
```java
String eccCurveTypeStr = "Secp256r1";

EccCurveType eccCurveType = EccCurveType.fromString(eccCurveTypeStr);
```

## 2.3 EncryptionType

### Declaration

```java
public enum EncryptionType {
  AES("AES");
}
```

### Usage
```java
String encryptionTypeStr = "AES";

EncryptionType encryptionType = EncryptionType.fromString(encryptionTypeStr);
```

## 2.4 EncryptionMode

### Declaration

```java
public enum EncryptionMode {
  CBC("CBC"), ECB("ECB");
}
```

### Usage
```java
String encryptionModeStr = "CBC";

EncryptionMode encryptionMode = EncryptionMode.fromString(encryptionModeStr);
```

## 2.5 SymmetricKeySize

### Declaration

```java
public enum SymmetricKeySize {
  Size128("128 bits"),
  Size256("256 bits");
}
```

### Usage
```java
String symmetricKeySizeStr = "256 bits";

SymmetricKeySize symmetricKeySize = SymmetricKeySize.fromString(symmetricKeySizeStr);
```

## 2.6 SymmetricPaddingType

### Declaration

```java
public enum SymmetricPaddingType {
  NOPAD("NoPadding"), PKCS5("PKCS5Padding");
}
```

### Usage
```java
String symmetricPaddingTypeStr = "256 bits";

SymmetricPaddingType symmetricPaddingType = SymmetricPaddingType.fromString(symmetricPaddingTypeStr);
```

## 2.7 SymmetricCipherType

### Declaration

```java
public enum SymmetricCipherType {
	AES_128_CBC("AES-128-CBC"),
	AES_128_ECB("AES-128-ECB"), 
	AES_256_CBC("AES-256-CBC"),
	AES_256_ECB("AES-256-ECB");
}
```

### Usage
```java
String symmetricCipherTypeStr = "AES-256-CBC";

SymmetricCipherType symmetricCipherType = SymmetricCipherType.fromString(symmetricCipherTypeStr);
```

## 2.8 DigestType

### Declaration

```java
public enum DigestType {
	SHA256("sha256"), SHA512("sha512"), SHA384("sha384");
}
```

### Usage
```java
String digestTypeStr = "sha256";

DigestType digestType = DigestType.fromString(digestTypeStr);
```

## 2.9 MultiBaseType

### Declaration

```java
public enum MultiBaseType {
	base16("f"), 
	base16upper("F"), 
	base58btc("z"),
	base64url("u"),
	base64("m");
}
```

### Usage
```java
String multiBaseTypeStr = "f";

MultiBaseType multiBaseType = MultiBaseType.getByCharacter(multiBaseTypeStr);
```

<br>

# 3. Reference Classes

## 3.1 KeyPairInterface

### Declaration

```java
public interface KeyPairInterface {
  public PublicKey getPublicKey();
  public void setPublicKey(PublicKey publicKey);
  public PrivateKey getPrivateKey();
  public void setPrivateKey(PrivateKey privateKey);
}
// For PublicKey, PrivateKey types, see java.security.PublicKey, PrivateKey
```

## 3.2 CipherInfo

### Declaration

```java
public class CipherInfo {
  private EncryptionType type;
  private EncryptionMode mode;
  private SymmetricKeySize size;
  private SymmetricPaddingType padding;

  public CipherInfo(SymmetricCipherType cipherType, SymmetricPaddingType paddingType) throws CryptoException {}
}
```

### Usage
```java
String cipherTypeStr = "AES-256-CBC";
String paddingTypeStr = "PKCS5Padding";

SymmetricCipherType symCipherType = SymmetricCipherType.fromString(cipherTypeStr);
SymmetricPaddingType symPaddingType = SymmetricPaddingType.fromString(paddingTypeStr);

CipherInfo cipherInfo = new CipherInfo(symCipherType, symPaddingType);
```

### Property
| Parameter       | Type                  | Description                 | **M/O** | **Notes**                         |
|-----------------|-----------------------|-----------------------------|---------|-----------------------------------|
| type            | EncryptionType        | Encryption algorithm type   | M       | [Link](#23-encryptiontype)         |
| mode            | EncryptionMode        | Block cipher mode           | M       | [Link](#24-encryptionmode)         |
| size            | SymmetricKeySize      | Key length                  | M       | [Link](#25-symmetrickeysize)       |
| paddingType     | SymmetricPaddingType  | Padding type                | M       | [Link](#26-symmetricpaddingtype)   |
| cipherType      | SymmetricCipherType   | Cipher type                 | M       | [Link](#27-symmetricciphertype)    |

## 3.3 EcKeyPair

### Declaration

```java
public class EcKeyPair implements KeyPairInterface{
  EccCurveType eccCurveType;
  private ECPublicKey publicKey; 
  private ECPrivateKey privateKey;
}
```

### Property
| Parameter    | Type            | Description                      | **M/O** | **Notes** |
|--------------|-----------------|----------------------------------|---------|-----------|
| eccCurveType | EccCurveType    | Elliptic Curve Type Enum          | M       | [Link](#22-ecccurvetype) |
| publicKey    | PublicKey     | Elliptic Curve Public Key         | M       | Refer to java.security.ECPublicKey |
| privateKey   | PrivateKey    | Elliptic Curve Private Key        | M       | Refer to java.security.ECPrivateKey |
