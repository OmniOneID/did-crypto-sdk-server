/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.crypto.enums;

import java.util.EnumSet;

public enum DigestType {
	SHA256("sha256"), SHA512("sha512"), SHA384("sha384");

	private String rawValue;

	DigestType(String rawValue) {
		this.rawValue = rawValue;
	}

	public String getRawValue() {
		return rawValue;
	}

	// default Sha384 or null .. 
	public static DigestType fromString(String text) {
		for (DigestType b : DigestType.values()) {
			if (b.rawValue.equalsIgnoreCase(text)) {
				return b;
			}
		}
		return SHA384;
	}

	public static EnumSet<DigestType> all() {
		return EnumSet.allOf(DigestType.class);
	}
}
