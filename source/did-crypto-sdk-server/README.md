# Server Crypto SDK Guide
This document is a guide to using the OpenDID Server Crypto SDK, 
It provides the necessary decryption functions for Open DID as Crypto, Degest, MultiBase, and Signature Utils.


## S/W Specifications
| Component | Requirement     |
|------|----------------------------|
| Language  | Java 21|
| Build System  | Gradle 8.8 |

<br>

## Build Method
: Create a JAR file based on the build.gradle file of this SDK project.
1. Open the `build.gradle` file of your project and add a task from the configuration file as shown below.

```groovy
plugins {
    id 'java'
}

group = 'org.omnione.did'

java {
    sourceCompatibility = '21'
}

jar {
    archiveBaseName.set('did-crypto-sdk-server') 
    archiveVersion.set('2.0.0')
    archiveClassifier.set('') 
}

repositories {
    mavenCentral()	
}

dependencies {
    implementation 'org.bouncycastle:bcprov-jdk18on:1.78.1'
}
```

2. Open the `Gradle` tab in IDE and run the project's `Task > Build > Clean and Build` task, or type `./gradlew clean & build` in a terminal.
3. Once the execution is complete, the `did-crypto-sdk-server-2.0.0.jar` file will be generated in the `{projetPath}/build/libs/` folder.

<br>

## SDK Application Method
1. Copy the `did-crypto-sdk-server-2.0.0.jar` file to the libs of the server project.
2. Add the following dependencies to the `build.gradle` of the server project.

```groovy
    implementation files('libs/did-crypto-sdk-server-2.0.0.jar')
    implementation 'org.bouncycastle:bcprov-jdk18on:1.78.1'
```
3. Sync `Gradle` to ensure the dependencies are properly added.

<br>

## API Specification
| Classification | API Document Link |
|------|----------------------------|
| CryptoUtils | [Crypto SDK Server API - CryptoUtils ](/docs/api/CRYPTO_SDK-SERVER_API.md#11-cryptoutils) |
| DigestUtils | [Crypto SDK Server API - DigestUtils ](/docs/api/CRYPTO_SDK-SERVER_API.md#12-digestutils) |
| MultiBaseUtils  | [Crypto SDK Server API - MultiBaseUtils](/docs/api/CRYPTO_SDK-SERVER_API.md#13-multibaseutils)  |
| SignatureUtils | [Crypto SDK Server API - SignatureUtils](/docs/api/CRYPTO_SDK-SERVER_API.md#14-signatureutils)  |

### CryptoUtils
CryptoUtils provides features including ECC key pair generation and public key compression/decompression, nonce and salt generation, password-based key generation via PBKDF2, AES encryption/decryption, and SharedSecret generation.
<br>The main features are as follows:

* <b>Create a key</b>: Generate a key pair consisting of a public-private key pair.
* <b>Compress public keys</b>: Compresses the public key into a byte array type.
* <b>Decompress public key</b>: Decompress the compressed public key.
* <b>Generate a nonce</b>: Generate a nonce.
* <b>Generate a salt</b>: Generate a salt.
* <b>Create a SharedSecret</b>: Create a SharedSecret.
* <b>Generate the PBKDF2 derived key</b>: Generate an encryption key using the PBKDF2 algorithm for your wallet password.
* <b>Encrypt</b>: Encrypt the data.
* <b>Decrypt</b>: Decrypt the encrypted data.



### DigestUtils
DigestUtils provides SHA hashing functionality.
<br>The main features are as follows:

* <b>Hashification</b>: Hash data using the SHA function.
  
### MultiBaseUtils
MultiBaseUtils supports encoding/decoding functionality.
<br>The main features are as follows:

* <b>encoding</b>: Encodes the data.
* <b>decoding</b>: Decode the data.

### SignatureUtils
SignatureUtils provides signature functionality.
<br>The main features are as follows:

* <b>Generate a signature</b>: Signs the data using the ECDSA algorithm.
* <b>Generate compressed signature</b>: Generate a compressed signature for the data.
* <b>Verify compressed signature</b>: Verify the compressed signature.

<br>

## SDK Enumerator
Enumerators used by OpenDID Server Crypto SDK.
<br>The main features are as follows:

* <b>DidKeyType</b>: Define the Did key type.
* <b>EccCurveType</b>: Defines the Ecc Curve type.
* <b>EncryptionType</b>: Define the encryption algorithm type.
* <b>EncryptionMode</b>: Define the encryption mode type.
* <b>SymmetricKeySize</b>: Define a key size type.
* <b>SymmetricPaddingType</b>: Define the padding type.
* <b>SymmetricCipherType</b>:  Defines the type of symmetric key encryption algorithm.
* <b>DigestType</b>: Define a digest type.
* <b>MultiBaseType</b>: Define a multibase type.