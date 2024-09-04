/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.crypto.generator;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import org.omnione.did.crypto.constant.CryptoConstant;
import org.omnione.did.crypto.exception.CryptoErrorCode;
import org.omnione.did.crypto.exception.CryptoException;
import org.omnione.did.crypto.keypair.KeyPairInterface;
import org.omnione.did.crypto.keypair.RsaKeyPair;

public class RsaKeyPairGenerator {

  public KeyPairInterface generateKeyPair() throws CryptoException {
    KeyPairGenerator keyGen;
    java.security.KeyPair key = null;
    try {
      keyGen = KeyPairGenerator.getInstance(CryptoConstant.ALG_RSA);
      keyGen.initialize(2048);
      key = keyGen.generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
      throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOUTIL_GEN_RANDOM_KEY_FAIL, e.getMessage());
    }

    RsaKeyPair rsaKeyPair = new RsaKeyPair();
    rsaKeyPair.setPrivateKey(key.getPrivate());
    rsaKeyPair.setPublicKey(key.getPublic());
    return rsaKeyPair;
  }
}
