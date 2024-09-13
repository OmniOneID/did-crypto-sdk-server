# Server Crypto SDK Guide
본 문서는 OpenDID Server Crypto SDK 사용을 위한 가이드로, 
Open DID에 필요한 암복호화를 Crypto, Degest, MultiBase, Signature Utils로서 기능을 제공한다.


## S/W 사양
| 구분 | 내용                |
|------|----------------------------|
| Language  | Java 17|
| Build System  | Gradle 8.7 |

<br>

## 빌드 방법
: 본 SDK 프로젝트의 build.gradle 파일을 기반으로 JAR 파일을 생성한다.
1. 프로젝트의 `build.gradle` 파일을 열고 아래와 같은 구성파일의 태스크를 추가한다.

```groovy
plugins {
    id 'java'
}

group = 'org.omnione.did'

java {
    sourceCompatibility = '17'
}

jar {
    archiveBaseName.set('did-crypto-sdk-server') 
    archiveVersion.set('1.0.0')
    archiveClassifier.set('') 
}

repositories {
    mavenCentral()	
}

dependencies {
    implementation 'org.bouncycastle:bcprov-jdk18on:1.78.1'
}
```

2. IDE에서 `Gradle` 창을 열고, 프로젝트의 `Tasks > build > clean & build` 태스크를 실행 또는 `./gradlew clean & build` 를 터미널 창에 입력한다.
3. 실행이 완료되면 `{projetPath}/build/libs/` 폴더에 `did-crypto-sdk-server-1.0.0.jar` 파일이 생성된다.

<br>

## SDK 적용 방법
1. 서버 프로젝트의 libs에 `did-crypto-sdk-server-1.0.0.jar` 파일을 복사한다.
2. 서버 프로젝트의 `build.gradle` 파일에 아래 의존성을 추가한다.

```groovy
    implementation files('libs/did-crypto-sdk-server-1.0.0.jar')
    implementation 'org.bouncycastle:bcprov-jdk18on:1.78.1'
```
3. `Gradle`을 동기화하여 의존성이 제대로 추가되었는지 확인한다.

<br>

## API 규격서
| 구분 | API 문서 Link |
|------|----------------------------|
| CryptoUtils | [Crypto SDK Server API - CryptoUtils ](/docs/api/CRYPTO_SDK-SERVER_API_ko.md#11-cryptoutils) |
| DigestUtils | [Crypto SDK Server API - DigestUtils ](/docs/api/CRYPTO_SDK-SERVER_API_ko.md#12-digestutils) |
| MultiBaseUtils  | [Crypto SDK Server API - MultiBaseUtils](/docs/api/CRYPTO_SDK-SERVER_API_ko.md#13-multibaseutils)  |
| SignatureUtils | [Crypto SDK Server API - SignatureUtils](/docs/api/CRYPTO_SDK-SERVER_API_ko.md#14-signatureutils)  |

### CryptoUtils
CryptoUtils는 ECC 키 쌍 생성 및 공개키 압축/해제, nonce 및 salt 생성, PBKDF2를 통한 패스워드 기반 키 생성, AES 암호화/복호화, 그리고 SharedSecret 생성을 포함한 기능을 제공한다.<br>주요 기능은 다음과 같다:

* <b>키 생성</b>: 공개키-개인키 쌍으로 이루어진 키페어를 생성한다.
* <b>공개키 압축</b>: 바이트 배열 타입으로 공개키를 압축한다.
* <b>압축된 공개키 해제</b>: 압축된 공개키를 해제한다.
* <b>nonce 생성</b>: nonce 값을 생성한다.
* <b>salt 생성</b>: salt 값을 생성한다.
* <b>SharedSecret 생성</b>: SharedSecret을 생성한다.
* <b>pbkdf2 유도 키 생성</b>: 월렛 패스워드를 PBKDF2 알고리즘을 사용한 암호화 키 생성
* <b>암호화</b>: 데이터를 암호화한다.
* <b>복호화</b>: 암호화된 데이터를 복호화한다.



### DigestUtils
DigestUtils는 SHA 해시 기능을 제공한다.<br>
주요 기능은 다음과 같다:

* <b>해시화</b>: SHA 함수를 사용해 데이터 해시화를 한다.
  
### MultiBaseUtils
MultiBaseUtils는 인코딩/디코딩 기능을 지원한다.<br>
주요 기능은 다음과 같다:

* <b>인코딩</b>: 데이터를 인코딩한다.
* <b>디코딩</b>: 데이터를 디코딩한다.

### SignatureUtils
SignatureUtils는 서명 기능을 제공한다.<br>주요 기능은 다음과 같다:

* <b>서명값 생성</b>: 데이터를 ECDSA 알고리즘을 사용해 서명한다.
* <b>압축된 서명값 생성</b>: 데이터를 압축된 서명값으로 생성한다.
* <b>압축 서명값 검증</b>: 압축된 서명값을 검증한다.


<br>

## SDK Enumerator
OpenDID Server Crypto SDK 에서 사용하는 Enumerator<br>
주요 기능은 다음과 같다:

* <b>DidKeyType</b>: Did 키 타입을 정의한다.
* <b>EccCurveType</b>: Ecc Curve 타입을 정의한다.
* <b>EncryptionType</b>: 암호화 알고리즘 타입을 정의한다.
* <b>EncryptionMode</b>: 암호화 Mode 타입을 정의한다.
* <b>SymmetricKeySize</b>: 키 사이즈 타입을 정의한다.
* <b>SymmetricPaddingType</b>: 패딩 타입을 정의한다.
* <b>SymmetricCipherType</b>: 대칭키 암호화 알고리즘 타입을 정의한다.
* <b>DigestType</b>: 다이제스트 타입을 정의한다.
* <b>MultiBaseType</b>: 멀티베이스 타입을 정의한다.