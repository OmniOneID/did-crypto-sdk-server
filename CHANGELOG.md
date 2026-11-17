# Changelog

## [Unreleased] (v3.0.0)

### 🐛 Bug Fixes

- ECDH Shared Secret Length
    - `CryptoUtils.generateSharedSecret` now always returns the field-size (32-byte) X coordinate; a leading 0x00 was dropped before, so about 1 in 256 secrets were 31 bytes

## v2.0.0 (2025-05-26)

### 🚀 New Features

- Java Compile Version Upgrade
    - Updated Java compile version from 17 to 21

## v1.0.0 (2024-10-18)

### 🚀 New Features

- Supports key generation for ECC and RSA, along with encryption and decryption capabilities
- Support for SHA-256, SHA-384, and SHA-512 hash functions. 
- Supports MultiBase encoding and decoding functionality.
- Provides functionality for signature generation and verification.