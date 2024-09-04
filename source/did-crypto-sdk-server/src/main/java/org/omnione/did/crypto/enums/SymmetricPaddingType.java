/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.crypto.enums;

import java.util.EnumSet;

public enum SymmetricPaddingType {
  NOPAD("NoPadding"), PKCS5("PKCS5Padding");
  
  private String rawValue; 
  
  public String getRawValue() {
    return rawValue;
  }

  public void setRawValue(String padding) {
    this.rawValue = padding;
  }
  
  SymmetricPaddingType(String padding) {
    this.rawValue = padding;
  }

  public static SymmetricPaddingType fromString(String rawValue) {
    for (SymmetricPaddingType type : SymmetricPaddingType.values()) {
      if (type.getRawValue().equals(rawValue)) {
        return type;
      }
    }
    throw new IllegalArgumentException("No enum constant with rawValue " + rawValue);
  }
  public static EnumSet<SymmetricPaddingType> all() {
    return EnumSet.allOf(SymmetricPaddingType.class);
  }	
}
