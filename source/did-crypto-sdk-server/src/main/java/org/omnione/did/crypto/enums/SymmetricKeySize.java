/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.crypto.enums;

import java.util.EnumSet;

public enum SymmetricKeySize {
  Size128("128 bits"),
  Size256("256 bits");
  // TODO Change variable type (String -> int)
  private String rawValue;
  
  SymmetricKeySize(String size) {
    this.setRawValue(size);
  }

  public String getRawValue() {
    return rawValue;
  }

  public void setRawValue(String size) {
    this.rawValue = size;
  }
  
  public static SymmetricKeySize fromString(String text) {
    for (SymmetricKeySize b : SymmetricKeySize.values()) {
      if (b.rawValue.equalsIgnoreCase(text)) {
        return b;
      }
    }
    return null;
  }

  public static EnumSet<SymmetricKeySize> all() {
    return EnumSet.allOf(SymmetricKeySize.class);
  }
}
