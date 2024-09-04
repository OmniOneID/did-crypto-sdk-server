/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.crypto.enums;

import java.util.EnumSet;

public enum EncryptionMode {
  CBC("CBC"), ECB("ECB");
  
  private String rawValue;

  public String getRawValue() {
    return rawValue;
  }

  public void setRawValue(String mode) {
    this.rawValue = mode;
  }

  EncryptionMode(String mode) {
    this.rawValue = mode;
  }
  
  public static EncryptionMode fromString(String text) {
    for (EncryptionMode b : EncryptionMode.values()) {
      if (b.rawValue.equalsIgnoreCase(text)) {
        return b;
      }
    }
    return null;
  }

  public static EnumSet<EncryptionMode> all() {
    return EnumSet.allOf(EncryptionMode.class);
  }
}
