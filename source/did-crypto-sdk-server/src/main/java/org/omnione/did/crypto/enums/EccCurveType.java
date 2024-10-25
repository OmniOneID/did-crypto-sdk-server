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

package org.omnione.did.crypto.enums;

import java.util.EnumSet;

public enum EccCurveType {
	Secp256k1("Secp256k1"),
	Secp256r1("Secp256r1");
  
  EccCurveType(String curveName) {
    this.curveName = curveName;
  }

  private String curveName;

  public String getCurveName() {
    return curveName;
  }
  
  public static EccCurveType fromString(String text) {
      for (EccCurveType b : EccCurveType.values()) {
          if (b.curveName.equalsIgnoreCase(text)) {
              return b;
          }
      }
      return null;
  }

  public static EnumSet<EccCurveType> all() {
      return EnumSet.allOf(EccCurveType.class);
  }
}
