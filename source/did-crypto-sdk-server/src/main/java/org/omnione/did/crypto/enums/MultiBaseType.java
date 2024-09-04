/* 
 * Copyright 2024 Raonsecure
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
