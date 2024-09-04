# Crypto Server SDK

Welcome to the Crypto Server SDK Repository. <br> This repository provides an SDK for key generation, encryption/decryption, and other related functions.

## Folder Structure
```
did-crypto-sdk-server
├── CHANGELOG.md
├── CLA.md
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── LICENSE.dependencies.md
├── MAINTAINERS.md
├── README.md
├── README_ko.md
├── RELEASE-PROCESS.md
├── SECURITY.md
├── docs
│    └── api
│        ├── CRYPTO_SDK_SERVER_API.md
│        ├── CRYPTO_SDK_SERVER_API_ko.md
│        └── CryptoSDKError.md
└── source
    └── did-crypto-sdk-server
        ├── README.md
        ├── README_ko.md
        ├── build.gradle
        ├── gradle
        │   └── wrapper
        ├── .gitignore
        ├── build
        ├── gradlew        
        ├── gradlew.bat
        ├── settings.gradle
        └── src
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
| LICENSE.dependencies.md | Licenses for the project’s dependency libraries |
| MAINTAINERS.md          | General guidelines for maintaining              |
| RELEASE-PROCESS.md      | Release process                                 |
| SECURITY.md             | Security policies and vulnerability reporting   |

## Libraries

Libraries can be found in the [build folder](did-crypto-sdk-server/source/did-crypto-sdk-server/build/libs).


1. Copy the did-crypto-sdk-server-1.0.0.jar file to the libs of the server project.
2. Add the following dependencies to the server project's build.gradle.

```groovy
    implementation 'org.bouncycastle:bcprov-jdk18on:1.78.1'  
    implementation files('libs/did-crypto-sdk-server-1.0.0.jar')
```
3. Sync `Gradle` to ensure the dependencies are properly added.

## API Reference

API Reference can be found [here](docs/CRYPTO_SDK-SERVER_API.md)


## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for details on our code of conduct, and the process for submitting pull requests to us.


## License
Copyright 2024 Raonsecure