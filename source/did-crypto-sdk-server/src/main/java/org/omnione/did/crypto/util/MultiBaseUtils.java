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

package org.omnione.did.crypto.util;

import org.omnione.did.crypto.encoding.Base58;
import org.omnione.did.crypto.enums.MultiBaseType;
import org.omnione.did.crypto.exception.CryptoException;
import org.omnione.did.crypto.exception.CryptoErrorCode;

import java.util.*;

public class MultiBaseUtils {
    
	/**
	 * Encoding
	 * 
	 * @param source The source bytes to encode
	 * @param baseType The type of base encoding to use (e.g., base16, base58btc, base64, base64url)
	 * @return The encoded string 
	 * @throws CryptoException 
	 */
	public static String encode(byte[] source, MultiBaseType baseType) throws CryptoException {
		String character = baseType.getCharacter();

        switch (baseType){
            case base16:
            	String enc16Data = HexFormat.of().formatHex(source);
            	
            	StringBuilder sb16 = new StringBuilder(enc16Data);
            	sb16.insert(0, character);

           		return new String(sb16);
            case base16upper:
            	String enc16UpperData = HexFormat.of().withUpperCase().formatHex(source);
            	StringBuilder sb16Upper = new StringBuilder(enc16UpperData);
            	sb16Upper.insert(0, character);
            	
           		return new String(sb16Upper);
            case base58btc:

            	String enc58Data = Base58.encode(source);
            	StringBuilder sb58 = new StringBuilder(enc58Data);
            	sb58.insert(0, character);
       
           		return new String(sb58);
            case base64:
            	String enc64Data = Base64.getEncoder().withoutPadding().encodeToString(source);
            	StringBuilder sb64 = new StringBuilder(enc64Data);
            	sb64.insert(0, character);

           		return new String(sb64);
            case base64url:
            	String enc64urlData = Base64.getUrlEncoder().withoutPadding().encodeToString(source);
            	StringBuilder sb64url = new StringBuilder(enc64urlData);
            	sb64url.insert(0, character);

           		return new String(sb64url);
            default:
            	throw new CryptoException(CryptoErrorCode.ERR_CODE_MULTIBASEUTIL_INVALID_ENCODING_TYPE);
        }
	}
	
	/**
	 * Decoding
	 * 
	 * @param multibase The encoded string to decode
	 * @return The decoded bytes 
	 * @throws CryptoException
	 */
	public static byte[] decode(String multibase) throws CryptoException {
		if (multibase == null || multibase.length() < 2) {
			return null;
		}
		String firstString = multibase.substring(0, 1);
		String remainString = multibase.substring(1);
		
		MultiBaseType baseType = getMultibaseEnum(firstString);
		if (baseType == null) {
			return null;
		}
		switch (baseType) {
		case base16:
			return HexFormat.of().parseHex(remainString);
        case base16upper:
            return HexFormat.of().parseHex(remainString);
		case base58btc:
			return Base58.decode(remainString);
		case base64:
			return Base64.getDecoder().decode(padBase64String(remainString));
		case base64url:
			return Base64.getUrlDecoder().decode(padBase64String(remainString));
		default:
			throw new CryptoException(CryptoErrorCode.ERR_CODE_MULTIBASEUTIL_INVALID_DECODING_TYPE);
		}
	}

	/**
	 * Encoding Type Check
	 *
	 * @param firstString The first character of the encoded string to determine the encoding type
	 * @return The corresponding MultiBaseType enum
	 */
	private static MultiBaseType getMultibaseEnum(String firstString) {
        for (MultiBaseType baseType : MultiBaseType.values()) {
            if (baseType.getCharacter().equals(firstString)) {
               return baseType;
            }
        }
        return null;
	}
	
	/**
	 * Pad Base64 String
	 * 
	 * @param base64 The base64 string to pad
	 * @return The padded base64 string
	 */	
	private static String padBase64String(String base64) {
	    int paddingCount = (4 - (base64.length() % 4)) % 4;
	    StringBuilder sb = new StringBuilder(base64);
	    for (int i = 0; i < paddingCount; i++) {
	        sb.append('=');
	    }
	    return sb.toString();
	}
}