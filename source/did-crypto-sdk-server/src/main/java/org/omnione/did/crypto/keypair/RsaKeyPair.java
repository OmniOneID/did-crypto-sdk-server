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

package org.omnione.did.crypto.keypair;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.omnione.did.crypto.constant.CryptoConstant;
import org.omnione.did.crypto.exception.CryptoErrorCode;
import org.omnione.did.crypto.exception.CryptoException;

public class RsaKeyPair implements KeyPairInterface{

  private PrivateKey privateKey;
  private PublicKey publicKey;

  public RsaKeyPair() {
    super();
  }

  @Override
  public PublicKey getPublicKey() {
    return publicKey;
  }

  @Override
  public void setPublicKey(PublicKey publicKey) {
    this.publicKey = publicKey;
  }

  @Override
  public PrivateKey getPrivateKey() {
    return privateKey;
  }

  @Override
  public void setPrivateKey(PrivateKey privateKey) {
    this.privateKey = privateKey;
  }

  public PublicKey getPublicKey(byte[] publicKey) throws CryptoException {

    KeyFactory keyFactory = null;
    PublicKey pubKey = null;
    X509EncodedKeySpec ukeySpec = new X509EncodedKeySpec(publicKey);
    try {
        keyFactory = KeyFactory.getInstance(CryptoConstant.ALG_RSA);
        pubKey = keyFactory.generatePublic(ukeySpec);
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
        throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOUTIL_CONVERT_RSA_KEY_FAIL, e.getMessage());
    }
    return pubKey;
  }

  public PrivateKey getPrivateKey(byte[] decPrivKey) throws CryptoException {
    PrivateKey privateKey = null;
    try{
      PKCS8EncodedKeySpec rkeySpec = new PKCS8EncodedKeySpec(decPrivKey);
      KeyFactory rkeyFactory = KeyFactory.getInstance(CryptoConstant.ALG_RSA);                     
      privateKey = rkeyFactory.generatePrivate(rkeySpec);
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
        throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOUTIL_CONVERT_RSA_KEY_FAIL, e.getMessage());
    }
    return privateKey;
  }
}