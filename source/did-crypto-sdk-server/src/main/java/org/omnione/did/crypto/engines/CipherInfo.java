/*
 * Copyright 2024 OmniOne.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.omnione.did.crypto.engines;

import org.omnione.did.crypto.enums.EncryptionMode;
import org.omnione.did.crypto.enums.EncryptionType;
import org.omnione.did.crypto.enums.SymmetricCipherType;
import org.omnione.did.crypto.enums.SymmetricKeySize;
import org.omnione.did.crypto.enums.SymmetricPaddingType;
import org.omnione.did.crypto.exception.CryptoErrorCode;
import org.omnione.did.crypto.exception.CryptoException;

public class CipherInfo {
  
  /**
   * The type of encryption algorithm enum (e.g., AES).
   */    
  private EncryptionType type;
  
  /**
   * The mode of operation for the cipher (e.g., CBC, ECB).
   */
  private EncryptionMode mode;
  
  /**
   * The size of the symmetric key (e.g., 128 bits, 256 bits).
   */
  private SymmetricKeySize size;
  
  /**
   * The padding type used in the cipher (e.g., PKCS7).
   */
  private SymmetricPaddingType padding;
  
  public CipherInfo() {
    this.type = EncryptionType.AES;
    this.mode = EncryptionMode.CBC;
    this.size = SymmetricKeySize.Size256;
    this.padding = SymmetricPaddingType.PKCS5;
  }
  
  public CipherInfo(EncryptionType type, EncryptionMode mode, SymmetricKeySize size,
      SymmetricPaddingType padding) {
    this.type = type;
    this.mode = mode;
    this.size = size;
    this.padding = padding;
  }
  
  /**
   * Constructs a CipherInfo object with the specified cipher type and padding type.
   *
   * @param cipherType The type of symmetric cipher.
   * @param paddingType The type of padding used in the cipher.
   * @throws CryptoException
   */
  public CipherInfo(SymmetricCipherType cipherType, SymmetricPaddingType paddingType) throws CryptoException {
    this.padding = paddingType;
    switch(cipherType) {
      case AES_128_CBC :
        this.type = EncryptionType.AES;
        this.mode = EncryptionMode.CBC;
        this.size = SymmetricKeySize.Size128;
        break;
      case AES_128_ECB :
        this.type = EncryptionType.AES;
        this.mode = EncryptionMode.ECB;
        this.size = SymmetricKeySize.Size128;
        break;
      case AES_256_CBC :
        this.type = EncryptionType.AES;
        this.mode = EncryptionMode.CBC;
        this.size = SymmetricKeySize.Size256;
        break;
      case AES_256_ECB :
        this.type = EncryptionType.AES;
        this.mode = EncryptionMode.ECB;
        this.size = SymmetricKeySize.Size256;
        break;
      default:
        throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOUTIL_INVALID_CIPHER_INFO_TYPE);
    }
  }
  
  public EncryptionType getType() {
    return type;
  }
  public void setType(EncryptionType type) {
    this.type = type;
  }
  public EncryptionMode getMode() {
    return mode;
  }
  public void setMode(EncryptionMode mode) {
    this.mode = mode;
  }
  public SymmetricKeySize getSize() {
    return size;
  }
  public void setSize(SymmetricKeySize size) {
    this.size = size;
  }
  public SymmetricPaddingType getPadding() {
    return padding;
  }
  public void setPadding(SymmetricPaddingType padding) {
    this.padding = padding;
  }
}
