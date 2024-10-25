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
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import org.omnione.did.crypto.enums.EccCurveType;
import org.omnione.did.crypto.enums.MultiBaseType;
import org.omnione.did.crypto.exception.CryptoException;
import org.omnione.did.crypto.util.CryptoUtils;
import org.omnione.did.crypto.util.MultiBaseUtils;

public class EcKeyPair implements KeyPairInterface{

  /**
   * The elliptic curve type associated with this key pair.
   */
  EccCurveType eccCurveType;
  
  /**
   * The elliptic curve public key.
   */  
  private PublicKey publicKey;
  
  /**
   * The elliptic curve private key.
   */
  private PrivateKey privateKey;
  
  public EcKeyPair(PublicKey publicKey, PrivateKey privateKey) {
    this.publicKey = (PublicKey) publicKey;
    this.privateKey = (PrivateKey) privateKey;
  }

  @Override
  public PublicKey getPublicKey() {
    return publicKey;
  }
  
  @Override
  public void setPublicKey(PublicKey publicKey) {
    this.publicKey = (ECPublicKey) publicKey;
  }
  
  @Override
  public PrivateKey getPrivateKey() {
    return privateKey;
  }
  
  @Override
  public void setPrivateKey(PrivateKey privateKey) {
    this.privateKey = (ECPrivateKey) privateKey;
  }
  
  public void setECType(EccCurveType eccCurveType) {
    this.eccCurveType = eccCurveType;
  }
  
  public EccCurveType getECType() {
    return eccCurveType;
  }

  public String getBase58PubKey() throws CryptoException {
    return MultiBaseUtils.encode(publicKey.getEncoded(), MultiBaseType.base58btc);
  }
  
  public String getBase58CompreessPubKey() throws CryptoException {
      byte[] compressPublicKey = CryptoUtils.compressPublicKey(publicKey.getEncoded(), eccCurveType);
      return MultiBaseUtils.encode(compressPublicKey, MultiBaseType.base58btc);
  }
}