/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.crypto.keypair;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface KeyPairInterface {
    
  /**
   * Returns the public key of the key pair.
   *
   * @return the public key.
   */    
  public PublicKey getPublicKey();

  /**
   * Sets the public key of the key pair.
   *
   * @param publicKey the public key to set.
   */ 
  public void setPublicKey(PublicKey publicKey);

  /**
   * Returns the private key of the key pair.
   *
   * @return the private key.
   */ 
  public PrivateKey getPrivateKey();

  /**
   * Sets the private key of the key pair.
   *
   * @param privateKey the private key to set.
   */ 
  public void setPrivateKey(PrivateKey privateKey);
}
