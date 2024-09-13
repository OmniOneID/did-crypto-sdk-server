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

- 주제: Crypto SDK Server API
- 작성: 여승재
- 일자: 2024-08-30
- 버전: v1.0.0

| 버전   | 일자       | 변경 내용                 |
| ------ | ---------- | -------------------------|
| v1.0.0 | 2024-08-30 | 초기 작성                 |


<div style="page-break-after: always;"></div>

# 목차
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
- [3. 참조 클래스](#3-참조-클래스)
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

### Function Introduction
`공개키-개인키 쌍으로 이루어진 키 페어를 생성합니다.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|---------|
| didKeyType | DidKeyType | Did 키 타입 Enum |M| [Link](#21-didkeytype)|

### Output Parameters

| Type | Description                |**M/O** | **비고** |
|------|----------------------------|---------|---------|
| KeyPairInterface  | KeyPair 인터페이스 |M| [Link](#31-keypairinterface) |

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

### Function Introduction
`ECC 타입 공개키를 압축합니다.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|---------|
| unCompressedPublicKeyBytes    | byte[]    | 바이트 배열 타입의 압축되지 않은 공개키  |M||
| eccCurveType    | EccCurveType | 타원 곡선 타입 Enum |M| [Link](#22-ecccurvetype) |

### Output Parameters

| Type | Description                |**M/O** | **비고** |
|------|----------------------------|---------|---------|
| byte[]  | 바이트 배열 타입의 압축된 공개키  |M| |

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

### Function Introduction
`압축된 공개키를 압축 해제합니다.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|---------|
| compressedPublicKey    | byte[]    | 압축된 공개키  |M||
| eccCurveType    | EccCurveType | 타원 곡선 타입 Enum |M| [Link](#22-ecccurvetype) |

### Output Parameters

| Type | Description                |**M/O** | **비고** |
|------|----------------------------|---------|---------|
| byte[]  | 바이트 배열 타입의 압축 해제된 공개키 |M| |

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

### Function Introduction
`Nonce 값을 생성합니다.`

### Input Parameters
| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|---------|
| length    | int    | 생성할 논스 길이 |M||


### Output Parameters
| Type | Description                |**M/O** | **비고** |
|------|----------------------------|---------|---------|
| byte[]  | 생성된 논스 |M| |

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

### Function Introduction
`salt 값을 생성합니다.`

### Input Parameters

n/a

### Output Parameters

| Type | Description                |**M/O** | **비고** |
|------|----------------------------|---------|---------|
| byte[]  | 생성된 salt값 |M| |


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

### Function Introduction
`ECC 키를 사용해 암/복호화에 사용될 SharedSecret을 생성합니다.`<br/> `암호화 키는 SECP256R1, SECP256K1 종류만 사용 가능합니다`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|---------|
| compressedPublicKeyBytes    | byte[]    | 수신자 압축 공개키 |M||
| privateKeyBytes    | byte[] | 송신자 개인키 |M| |
| eccCurveType    | EccCurveType | 타원 곡선 타입 Enum  |M| [Link](#22-ecccurvetype) |


### Output Parameters

| Type | Description                |**M/O** | **비고** |
|------|----------------------------|---------|---------|
| byte[]  | SharedSecret 값 |M| |


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

### Function Introduction
`월렛 패스워드를 PBKDF2 알고리즘을 사용해서 암호화 키를 유도합니다.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|---------|
| password    | char[]    | 패스워드 |M||
| salt    | byte[] | 암호화 salt |M| |
| iterator    | int | 반복 횟수 |M| |
| keySize    | int | 생성할 키 길이 |M| |


### Output Parameters

| Type | Description                |**M/O** | **비고** |
|------|----------------------------|---------|---------|
| byte[]  | PBKDF2를 통해 유도한 키 |M| |


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

### Function Introduction
`AES 알고리즘으로 데이터를 암호화 합니다.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|---------|
| source    | byte[]    | 암호화 할 원문 데이터 |M||
| cipherInfo    | CipherInfo | 암호화 정보 |M| [Link](#32-cipherinfo) |
| key    | byte[] | 암호화 키 |M||
| iv    | byte[] | 초기화 벡터(IV)값 |M| |



### Output Parameters

| Type | Description                |**M/O** | **비고** |
|------|----------------------------|---------|---------|
| byte[]  | 암호문 |M| |


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

// SharedSecret으로 부터 유도된 key와 iv값
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

### Function Introduction
`AES 알고리즘으로 암호화 된 데이터를 복호화 합니다.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|---------|
| cipherText    | byte[]    | 복호화 할 암호화 데이터 |M||
| cipherInfo    | CipherInfo | 암호화 정보 |M| [Link](#32-cipherinfo) |
| key    | byte[] | 복호화 키 |M||
| iv    | byte[] | 초기화 벡터(IV)값 |M| |



### Output Parameters

| Type | Description                |**M/O** | **비고** |
|------|----------------------------|---------|---------|
| byte[]  | 원문 데이터 |M| |


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

// SharedSecret으로 부터 유도된 key와 iv값
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

### Function Introduction
`SHA 함수를 사용해 데이터를 해시화 합니다.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|---------|
| source    | byte[]    | 원문 데이터 |M||
| digestType  | DigestType | 해시 알고리즘 타입 |M| [Link](#28-digesttype) |

### Output Parameters

| Type | Description                |**M/O** | **비고** |
|------|----------------------------|---------|---------|
| byte[]  | 해시 데이터 |M| |

### Function Declaration

```java
byte[] getDigest(byte[] source, DigestType digestType) -> throws CryptoException
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

### Function Introduction
`선택한 MultiBase 타입에 따라 이진 데이터를 문자로 변환합니다.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|---------|
| source    | byte[]    | 원문 데이터 |M||
| baseType    | MultiBaseType    | MultiBase 인코딩 타입 |M| [Link](#29-multibasetype) |


### Output Parameters

| Type | Description                |**M/O** | **비고** |
|------|----------------------------|---------|---------|
| String  | 인코딩 된 데이터 |M| |


### Function Declaration

```java
String encode(byte[] source, MultiBaseType baseType) -> throws CryptoException
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

### Function Introduction
`MultiBase 인코딩 된 데이터를 디코딩 합니다.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|---------|
| multibase    | String    | 인코딩 된 데이터 |M||


### Output Parameters

| Type | Description                |**M/O** | **비고** |
|------|----------------------------|---------|---------|
| byte[]  | 원문 데이터 |M| |


### Function Declaration

```java
byte[] decode(String multibase) -> throws CryptoException
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

### Function Introduction
`ECDSA 알고리즘을 사용해 타원 곡선 키로 데이터를 서명하여 ASN.1 DER 형식의 서명값 생성 후 Compact 서명으로 변환합니다.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|---------|
| keyPair    | EcKeyPair    | 타원 곡선 키 페어 |M| [Link](#33-eckeypair) |
| hashedSource    | byte[]    | 해시된 원문 데이터 |M||
| eccCurveType    | EccCurveType    | 타원 곡선 알고리즘 |M| [Link](#22-ecccurvetype) |


### Output Parameters

| Type | Description                |**M/O** | **비고** |
|------|----------------------------|---------|---------|
| byte[]  | 서명 된 데이터 |M| |


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

### Function Introduction
`ECDSA 알고리즘을 사용해 타원 곡선 키로 ASN.1 DER 형식의 서명값을 생성합니다.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|---------|
| privateKey    | PrivateKey    | 서명 개인키 |M| java.security.PrivateKey 참조 |
| hashedSource    | byte[]    | 해시된 원문 데이터 |M||


### Output Parameters

| Type | Description                |**M/O** | **비고** |
|------|----------------------------|---------|---------|
| byte[]  | 서명 된 데이터 |M| |


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

### Function Introduction
`ASN.1 DER 형식의 서명값을 Compact 서명으로 변환합니다.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|---------|
| publicKey    | PublicKey    | 서명 공개키 |M| java.security.PublicKey 참조 |
| hashedSource    | byte[]    | 해시된 원문 데이터 |M||
| signatureBytes    | byte[]    | ECDSA 서명값 |M||
| eccCurveType    | EccCurveType    | 타원 곡선 알고리즘 |M| [Link](#22-ecccurvetype) |


### Output Parameters

| Type | Description                |**M/O** | **비고** |
|------|----------------------------|---------|---------|
| byte[]  | 압축된 서명 데이터 |M| |


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

### Function Introduction
`Compact 서명값을 검증합니다.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|---------|
| compressedpublicKeyBytes    | byte[]    | 압축된 공개키 |M||
| hashedsource    | byte[]    | 해시된 원문 데이터 |M||
| signatureBytes    | byte[]    | 압축된 ECDSA 서명값 |M||
| eccCurveType    | EccCurveType    | 타원 곡선 알고리즘 |M| [Link](#22-ecccurvetype) |


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
byte[] compressedPublickeyBytes = CryptoUtils.compressPublicKey(uncompressedPublicKeyBytes, eccCurveType);

// 해시된 서명원문
byte[] hashedsource;
// Compact 서명값
byte[] compactSign;

SignatureUtils.verifyCompactSignWithCompressedKey(compressedPublickeyBytes, hashedsource, compactSign, eccCurveType);
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
  Size128(128),
  Size256(256);
}
```

### Usage
```java
int symmetricKeySizeValue = 256;

SymmetricKeySize symmetricKeySize = SymmetricKeySize.fromString(symmetricKeySizeValue);
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

# 3. 참조 클래스

## 3.1 KeyPairInterface

### Declaration

```java
public interface KeyPairInterface {
  public Object getPublicKey();
  public void setPublicKey(Object publicKey);
  public Object getPrivateKey();
  public void setPrivateKey(Object privateKey);
}
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
| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|---------|
| type    | EncryptionType    | 암호화 알고리즘 타입  |M| [Link](#23-encryptiontype)|
| mode    | EncryptionMode    | 블록 암호화 모드 |M| [Link](#24-encryptionmode) |
| size    | SymmetricKeySize    | 키 길이 |M| [Link](#25-symmetrickeysize) |
| paddingType    | SymmetricPaddingType    | 패딩 타입 |M| [Link](#26-symmetricpaddingtype) |
| cipherType    | SymmetricCipherType    | Cipher 타입 |M| [Link](#27-symmetricciphertype) |

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
| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|---------|
| eccCurveType | EccCurveType    | 타원 곡선 타입 Enum  |M| [Link](#22-ecccurvetype)|
| publicKey    | ECPublicKey    | 타원 곡선 공개키 |M| java.security.ECPublicKey 참조 |
| privateKey   | ECPrivateKey    | 타원 곡선 개인키 |M| java.security.ECPrivateKey 참조 |
