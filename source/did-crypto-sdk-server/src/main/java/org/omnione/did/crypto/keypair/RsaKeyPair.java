/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.crypto.keypair;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.omnione.did.crypto.constant.CryptoConstant;

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

  public PublicKey getPublicKey(byte[] publicKey) {

    KeyFactory keyFactory = null;
    PublicKey pubKey = null;
    try {
      X509EncodedKeySpec ukeySpec = new X509EncodedKeySpec(publicKey);
      keyFactory = KeyFactory.getInstance(CryptoConstant.ALG_RSA);
      pubKey = keyFactory.generatePublic(ukeySpec);
    } catch (Exception e) {
      e.printStackTrace();
    }
    return pubKey;
  }

  public PrivateKey getPrivateKey(byte[] decPrivKey){
    PrivateKey privateKey = null;
    try{
      PKCS8EncodedKeySpec rkeySpec = new PKCS8EncodedKeySpec(decPrivKey);
      KeyFactory rkeyFactory = KeyFactory.getInstance(CryptoConstant.ALG_RSA);                     
      privateKey = rkeyFactory.generatePrivate(rkeySpec);
    } catch (Exception e) {
      e.printStackTrace();
    }
    return privateKey;
  }
}