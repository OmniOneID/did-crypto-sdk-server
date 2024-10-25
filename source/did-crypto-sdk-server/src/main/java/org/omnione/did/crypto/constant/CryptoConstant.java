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

package org.omnione.did.crypto.constant;

public class CryptoConstant {
  public static final String PROVIDER_BC = "BC";

  public static final String PROVIDER_EC = "EC";

  public static final String ALG_NONCE = "SHA1PRNG";
  
  public static final String ALG_RSA = "RSA";
  
  public static final String ALG_AES = "AES";
  
  public static final String SIG_ALG_SHA256_RSA = "SHA256withRSA";
  
  public static final String SIG_ALG_SHA256_ECDSA = "SHA256withECDSA";
  
  public static final String SIG_ALG_NONE_ECDSA = "NoneWithECDSA";
  
  public static final String PBKDF2_ALG_HMAC_SHA1 = "PBKDF2WithHmacSHA1";
  
  public static final String HASH_ALG_SHA256 = "SHA-256";
  
  public static final String HASH_ALG_SHA384 = "SHA-384";
  
  public static final String HASH_ALG_SHA512 = "SHA-512";
}
