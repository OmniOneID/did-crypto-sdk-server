# Crypto Server SDK

Crypto Server SDK Repository에 오신 것을 환영합니다. <br> 이 Repository는 키 생성, 암/복호화 등을 개발하기 위한 SDK를 제공합니다.

## 폴더 구조
```
did-crypto-sdk-server
├── CHANGELOG.md
├── CLA.md
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── LICENSE
├── dependencies-license.md
├── MAINTAINERS.md
├── README.md
├── README_ko.md
├── RELEASE-PROCESS.md
├── SECURITY.md
├── docs
│   └── api
│       ├── CRYPTO_SDK_SERVER_API.md
│       ├── CRYPTO_SDK_SERVER_API_ko.md
│       └── CryptoSDKError.md
└── source
    ├── did-crypto-sdk-server
    │   ├── README.md
    │   ├── README_ko.md
    │   ├── build.gradle
    │   ├── gradle
    │   │   └── wrapper
    │   ├── .gitignore
    │   ├── build
    │   ├── gradlew        
    │   ├── gradlew.bat
    │   ├── settings.gradle
    │   └── src
    └── release
        └── did-crypto-sdk-server-1.0.0.jar
```

|  이름 |         역할                    |
| ------- | ------------------------------------ |
| source  |  SDK 소스코드 프로젝트             |
| docs  |   문서            |
| ┖ api  |  API 가이드 문서          |
| README.md  |  프로젝트의 전체적인 개요 설명            |
| CLA.md             | Contributor License Agreement                |
| CHANGELOG.md| 프로젝트 버전별 변경사항           |
| CODE_OF_CONDUCT.md| 기여자의 행동강령            |
| CONTRIBUTING.md| 기여 절차 및 방법           |
| LICENSE                 | Apache 2.0                                      |
| dependencies-license.md| 프로젝트 의존성 라이브러리에 대한 라이선스            |
| MAINTAINERS.md          | 유지관리 가이드              |
| RELEASE-PROCESS.md      | 릴리즈 절차                                |
| SECURITY.md| 보안취약점 보고 및 보안정책            | 

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

## 라이브러리

라이브러리는 [Releases](https://github.com/OmniOneID/did-crypto-sdk-server/releases) 에서 찾을 수 있습니다.

## Core SDK
1. 서버 프로젝트의 libs에 did-crypto-sdk-server-1.0.0.jar 파일을 복사한다.
2. 서버 프로젝트의 build gradle에 아래 의존성을 추가한다.

```groovy
    implementation 'org.bouncycastle:bcprov-jdk18on:1.78.1' 
    implementation files('libs/did-crypto-sdk-server-1.0.0.jar')
```
3. `Gradle`을 동기화하여 의존성이 제대로 추가되었는지 확인한다.

## API 참조

API 참조는 [여기](docs/CRYPTO_SDK-SERVER_API_ko.md)에서 확인할 수 있습니다.

## 기여

Contributing 및 pull request 제출 절차에 대한 자세한 내용은 [CONTRIBUTING.md](CONTRIBUTING.md)와 [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) 를 참조하세요.

## 라이선스
[Apache 2.0](LICENSE)

