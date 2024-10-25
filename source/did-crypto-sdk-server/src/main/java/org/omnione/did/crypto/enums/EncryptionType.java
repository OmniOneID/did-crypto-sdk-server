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
