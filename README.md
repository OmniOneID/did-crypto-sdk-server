# Crypto Server SDK

Welcome to the Crypto Server SDK Repository. <br> This repository provides an SDK for key generation, encryption/decryption, and other related functions.

## Folder Structure
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
        └── did-crypto-sdk-server-2.0.0.jar
```

| Name                    | Description                                     |
| ----------------------- | ----------------------------------------------- |
| source                  | SDK source code project                         |
| docs                    | Documentation                                   |
| ┖ api                   | API guide documentation                         |
| README.md               | Overview and description of the project         |
| CLA.md                  | Contributor License Agreement                   |
| CHANGELOG.md            | Version-specific changes in the project         |
| CODE_OF_CONDUCT.md      | Code of conduct for contributors                |
| CONTRIBUTING.md         | Contribution guidelines and procedures          |
| LICENSE                 | Apache 2.0                                      |
| dependencies-license.md | Licenses for the project’s dependency libraries |
| MAINTAINERS.md          | General guidelines for maintaining              |
| RELEASE-PROCESS.md      | Release process                                 |
| SECURITY.md             | Security policies and vulnerability reporting   |

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

## Libraries

Libraries can be found in the [Releases](https://github.com/OmniOneID/did-crypto-sdk-server/releases).

## Crypto SDK
1. Copy the did-crypto-sdk-server-2.0.0.jar file to the libs of the server project.
2. Add the following dependencies to the server project's build.gradle.

```groovy
    implementation 'org.bouncycastle:bcprov-jdk18on:1.78.1'  
    implementation files('libs/did-crypto-sdk-server-2.0.0.jar')
```
3. Sync `Gradle` to ensure the dependencies are properly added.

## API Reference

API Reference can be found [here](docs/CRYPTO_SDK-SERVER_API.md)

## Change Log

The Change Log provides a detailed record of version-specific changes and updates. You can find it here:
- [Change Log](./CHANGELOG.md)

## OpenDID Demonstration Videos <br>
To watch our demonstration videos of the OpenDID system in action, please visit our [Demo Repository](https://github.com/OmniOneID/did-demo-server). <br>

These videos showcase key features including user registration, VC issuance, and VP submission processes.

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for details on our code of conduct, and the process for submitting pull requests to us.


## License
[Apache 2.0](LICENSE)
