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

public enum MultiBaseType {
	base16("f"), 
	base16upper("F"), 
	base58btc("z"),
	base64url("u"),
	base64("m");

	private String character;

	MultiBaseType(String character) {
		this.character = character.substring(0, 1);
	}

	public String getCharacter() {
		return character;
	}
	
	public static MultiBaseType getByCharacter(String inputCharacter) {
        for (MultiBaseType value : MultiBaseType.values()) {
            if (value.character.equalsIgnoreCase(inputCharacter)) {
                return value;
            }
        }
        
        // If there is no matching value for the input character, Base64url is returned as the default value.
        return base64url;
    }
	
	public static EnumSet<MultiBaseType> all() {
	  return EnumSet.allOf(MultiBaseType.class);
	}
}
