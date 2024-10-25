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

package org.omnione.did.crypto.generator;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.omnione.did.crypto.constant.CryptoConstant;
import org.omnione.did.crypto.exception.CryptoErrorCode;
import org.omnione.did.crypto.exception.CryptoException;

public class GenerateSecureRandom {
  private static int DEFAULT_KEYSIZE = 256;
  private static int DEFAULT_SALTLENGTH = DEFAULT_KEYSIZE / 8;
  private static int DEFAULT_NONCELENGTH = 16;

  public byte[] generateNonce() throws CryptoException {
    return generateSecureRandom(DEFAULT_NONCELENGTH);
  }

  public byte[] generateSalt() throws CryptoException {
    return generateSecureRandom(DEFAULT_SALTLENGTH);
  }

  public byte[] generateSecureRandom(int size) throws CryptoException {
    try {
      SecureRandom random;
      random = SecureRandom.getInstance(CryptoConstant.ALG_NONCE);              
      byte bytes[] = new byte[size];
      random.nextBytes(bytes);
      return bytes;

    } catch (NoSuchAlgorithmException e) {
      throw new CryptoException(CryptoErrorCode.ERR_CODE_DIGESTUTIL_GEN_RANDOM_FAIL, e.getMessage());
    }
  }
}
