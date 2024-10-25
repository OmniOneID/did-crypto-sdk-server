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
