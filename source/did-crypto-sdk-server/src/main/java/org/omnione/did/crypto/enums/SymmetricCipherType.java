/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.crypto.enums;

import java.util.EnumSet;

public enum SymmetricCipherType {
	AES_128_CBC("AES-128-CBC"),
	AES_128_ECB("AES-128-ECB"), 
	AES_256_CBC("AES-256-CBC"),
	AES_256_ECB("AES-256-ECB");

	private String rawValue;

	SymmetricCipherType(String rawValue) {
		this.rawValue = rawValue;
	}


	public String getRawValue() {
		return rawValue;
	}
	
	public static SymmetricCipherType fromString(String text) {
		for (SymmetricCipherType b : SymmetricCipherType.values()) {
			if (b.rawValue.equalsIgnoreCase(text)) {
				return b;
			}
		}
		return null;
	}

	public static EnumSet<SymmetricCipherType> all() {
		return EnumSet.allOf(SymmetricCipherType.class);
	}

}