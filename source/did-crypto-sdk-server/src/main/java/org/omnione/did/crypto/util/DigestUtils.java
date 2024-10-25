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

package org.omnione.did.crypto.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.omnione.did.crypto.constant.CryptoConstant;
import org.omnione.did.crypto.enums.DigestType;
import org.omnione.did.crypto.exception.CryptoErrorCode;
import org.omnione.did.crypto.exception.CryptoException;

public class DigestUtils {

  /**
   * Generate Digest Data
   *
   * @param source The source data to generate the digest from
   * @param digestType  The type of digest algorithm to use (e.g., SHA-256, SHA-384, SHA-512)
   * @return The generated digest data
   * @throws CryptoException
   */
  public static byte[] getDigest(byte[] source, DigestType digestType) throws CryptoException {
    if (source == null || digestType == null) {
      throw new CryptoException(CryptoErrorCode.ERR_CODE_DIGESTUTIL_HASH_TYPE_OR_SOURCE_IS_NULL);
    }
    switch(digestType) {
      case SHA256:
        return getShaDigest(source, CryptoConstant.HASH_ALG_SHA256);
      case SHA384:
        return getShaDigest(source, CryptoConstant.HASH_ALG_SHA384);
      case SHA512:
        return getShaDigest(source, CryptoConstant.HASH_ALG_SHA512);
      default:
        throw new CryptoException(CryptoErrorCode.ERR_CODE_DIGESTUTIL_INVALID_HASH_TYPE);
    }
  }
  
  /**
   * Generate SHA Digest
   * 
   * @param source The source data to generate the SHA digest from
   * @param algorithm The SHA algorithm to use (e.g., SHA-256, SHA-384, SHA-512)
   * @return The generated SHA digest data
   * @throws CryptoException
   */
  private static byte[] getShaDigest(byte[] source, String algorithm) throws CryptoException {
    try {
      MessageDigest digest = MessageDigest.getInstance(algorithm);
      return digest.digest(source);
    } catch (NoSuchAlgorithmException e) {
      throw new CryptoException(CryptoErrorCode.ERR_CODE_DIGESTUTIL_GEN_HASH_FAIL, e.getMessage());
    }
  }

  /**
   * Merge ClientNonce and ServerNonce
   * 
   * @param clientNonce The client nonce bytes to merge
   * @param serverNonce The server nonce bytes to merge
   * @return The merged nonce bytes
   * @exception CryptoException
   */
  public static byte[] mergeNonce(byte[] clientNonce, byte[] serverNonce) throws CryptoException {
    if (clientNonce == null || serverNonce == null) {
      throw new CryptoException(CryptoErrorCode.ERR_CODE_DIGESTUTIL_HASH_TYPE_OR_SOURCE_IS_NULL);
    }
    MessageDigest digest;
    try {
      digest = MessageDigest.getInstance("SHA-256");
      digest.update(clientNonce, 0, clientNonce.length);
      digest.update(serverNonce, 0, serverNonce.length);
      return digest.digest();
    } catch (NoSuchAlgorithmException e) {
      throw new CryptoException(CryptoErrorCode.ERR_CODE_DIGESTUTIL_GEN_HASH_FAIL, e.getMessage());
    }
  }
}
