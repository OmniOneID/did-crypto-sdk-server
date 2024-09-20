/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.crypto.enums;

import java.util.EnumSet;

public enum DidKeyType {
	
	RSA_VERIFICATION_KEY_2018("RsaVerificationKey2018"),
	SECP256K1_VERIFICATION_KEY_2018("Secp256k1VerificationKey2018"),
	SECP256R1_VERIFICATION_KEY_2018("Secp256r1VerificationKey2018");

	private String rawValue;

	DidKeyType(String rawValue) {
		this.rawValue = rawValue;
	}

	public String getRawValue() {
		return rawValue;
	}

	public static DidKeyType fromString(String rawValue) {
		for (DidKeyType b : DidKeyType.values()) {
			if (b.rawValue.equalsIgnoreCase(rawValue)) {
				return b;
			}
		}
		return null;
	}

	public static EnumSet<DidKeyType> all() {
		return EnumSet.allOf(DidKeyType.class);
	}
}
