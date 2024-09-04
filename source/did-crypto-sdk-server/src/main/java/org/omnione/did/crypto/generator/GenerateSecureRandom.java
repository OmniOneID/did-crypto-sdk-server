/* 
 * Copyright 2024 Raonsecure
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
