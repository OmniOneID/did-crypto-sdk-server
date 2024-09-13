/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.crypto.enums;

import java.util.EnumSet;

public enum SymmetricKeySize {
  Size128(128),
  Size256(256);

  private int rawValue;
  
  SymmetricKeySize(int size) {
    this.setRawValue(size);
  }

  public int getRawValue() {
    return rawValue;
  }

  public void setRawValue(int size) {
    this.rawValue = size;
  }
  
  public static SymmetricKeySize fromString(int value) {
    for (SymmetricKeySize b : SymmetricKeySize.values()) {
      if (b.rawValue == value) {
        return b;
      }
    }
    return null;
  }

  public static EnumSet<SymmetricKeySize> all() {
    return EnumSet.allOf(SymmetricKeySize.class);
  }
}
