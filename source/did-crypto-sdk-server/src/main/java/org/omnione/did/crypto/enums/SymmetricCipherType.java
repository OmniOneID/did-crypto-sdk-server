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