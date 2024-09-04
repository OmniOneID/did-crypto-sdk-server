/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.crypto.enums;

import java.util.EnumSet;

public enum EncryptionType {
  AES("AES");
  
  private String rawValue;
  
  EncryptionType(String encType) {
    this.setRawValue(encType);
  }

  public String getRawValue() {
    return rawValue;
  }

  public void setRawValue(String encType) {
    this.rawValue = encType;
  }
  
  public static EncryptionType fromString(String text) {
    for (EncryptionType b : EncryptionType.values()) {
      if (b.rawValue.equalsIgnoreCase(text)) {
        return b;
      }
    }
    return null;
  }

  public static EnumSet<EncryptionType> all() {
    return EnumSet.allOf(EncryptionType.class);
  }
}
