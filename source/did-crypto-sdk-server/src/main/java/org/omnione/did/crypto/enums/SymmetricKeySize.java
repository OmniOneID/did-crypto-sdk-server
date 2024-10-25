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
