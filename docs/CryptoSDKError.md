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

Crytpo SDK Error
==

- Topic: CryptoSDKError
- Author: Jongyun Baek
- Date: 2024-08-27
- Version: v1.0.0

| Version          | Date       | Changes                  |
| ---------------- | ---------- | ------------------------ |
| v1.0.0  | 2024-08-20 | Initial version          |

<div style="page-break-after: always;"></div>

# Table of Contents
- [Model](#model)
  - [Error Response](#error-response)
- [Error Code](#error-code)
  - [1.1. DigestUtil (01xxx)](#11-digestutil01xxx)
  - [1.2. CryptoUtil (02xxx)](#12-cryptoutil02xxx)
  - [1.3. MultibaseUtil (03xxx)](#13-multibaseutil03xxx)
  - [1.4. SignatureUtil (04xxx)](#14-signatureutil04xxx)

# Model
## Error Response

### Description
```
Error struct for Crypto SDK. It has code and message pair.
Code starts with SSDKCRT.
```

### Declaration
```java
public class ErrorResponse {
    private final String code;
    private final String description;
}
```

### Property

| Name               | Type       | Description                            | **M/O** | **Note**              |
|--------------------|------------|----------------------------------------|---------|-----------------------|
| code               | String     | Error code. It starts with SSDKCRT     |    M    |                       | 
| message            | String     | Error description                      |    M    |                       | 

<br>

# Error Code
## 1. Crypto SDK
### 1.1. DigestUtil(01xxx)

| Error Code   | Error Message                                | Description      | Action Required                                           |
|--------------|----------------------------------------------|------------------|-----------------------------------------------------------|
| SSDKCRT01000 | Hash type is invalid.                        | -                | Check the type of hash.                                   |
| SSDKCRT01001 | Failed to generate hash.                     | -                | Check the name of hash algorithme.                        |
| SSDKCRT01002 | Failed to generate secure random.            | -                | Check the name of algorithme for generating secure random.|
| SSDKCRT01003 | Hash type or Source is null.                 | -                | Ensure the source and hash type are not null.             |


<br>

### 1.2. CryptoUtil(02xxx)

| Error Code   | Error Message                                | Description      | Action Required                                                                                     |
|--------------|----------------------------------------------|------------------|-----------------------------------------------------------------------------------------------------|
| SSDKCRT02000 | Invalid DID Key Type.                        | -                | Check the type of DID key.                                                                          |
| SSDKCRT02001 | Failed to generate random key.               | -                | Check the key algorithm to generate.                                                                |
| SSDKCRT02002 | Failed to Compress PublicKey.                | -                | Verify correct algorithm/provider names, proper library setup, and valid public key format.         |
| SSDKCRT02003 | Failed to UnCompress PublicKey.              | -                | Verify correct algorithm/provider names, proper library setup, and valid public key format.         |
| SSDKCRT02004 | Failed to generate shared secret.            | -                | Verify correct setup, valid key data, and accurate algorithm/provider names.                        |
| SSDKCRT02005 | Cipher type is invalid.                      | -                | Ensure that the cipherType provided is valid and supported by the implementation.                   |
| SSDKCRT02006 | Failed to Encrypt, Decrypt.                  | -                | Verify the cipher, key, padding, and IV are correctly configured.                                   |



<br>

### 1.3. MultibaseUtil(03xxx)

| Error Code   | Error Message                                | Description      | Action Required                                                                                                  |
|--------------|----------------------------------------------|------------------|------------------------------------------------------------------------------------------------------------------|
| SSDKCRT03000 | Multibase encoding type is invalid.          | -                | Check that the selected multibase encoding type is valid.                                                        |
| SSDKCRT03001 | Multibase decoding type is invalid.          | -                | Ensure that the decoding type corresponds to the correct multibase encoding format and is implemented correctly. |


<br>

### 1.4. SignatureUtil(04xxx)

| Error Code   | Error Message                                        | Description      | Action Required                                                                                                          |
|--------------|------------------------------------------------------|------------------|--------------------------------------------------------------------------------------------------------------------------|
| SSDKCRT04000 | Failed to recover valid recovery ID.                 | -                | Verify that the recovery ID is generated correctly and corresponds to the expected format.                               |
| SSDKCRT04001 | The provided input value is invalid.                 | -                | Ensure that all provided input values are valid and within the expected range or format.                                 |
| SSDKCRT04002 | This indicates that the ASN.1 sequence is invalid.   | -                | Confirm that the ASN.1 sequence is properly structured and adheres to the required specifications.                       |
| SSDKCRT04003 | It is not a compact sign.                            | -                | Validate that the sign value is in the correct compact format and properly encoded.                                      | 
| SSDKCRT04004 | The publicKey is not in compressed public key format.| -                | Make sure that the public key is in the correct compressed format.                                                       |
| SSDKCRT04005 | RecoveryKey creation failed.                         | -                | Investigate the recovery process and verify that all required data for creating the RecoveryKey is correct and available.|
| SSDKCRT04006 | RecoveryKey and publicKey do not match.              | -                | Ensure that the generated RecoveryKey corresponds accurately to the provided publicKey.                                  |


<br>