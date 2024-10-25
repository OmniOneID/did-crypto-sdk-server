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
