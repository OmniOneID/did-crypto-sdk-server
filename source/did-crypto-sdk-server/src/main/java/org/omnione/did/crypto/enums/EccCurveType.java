/* 
 * Copyright 2024 Raonsecure
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
