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
