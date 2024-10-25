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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.omnione.did.crypto.enums.EccCurveType;
import org.omnione.did.crypto.exception.CryptoErrorCode;
import org.omnione.did.crypto.exception.CryptoException;
import org.omnione.did.crypto.keypair.EcKeyPair;
import org.omnione.did.crypto.signature.EccSignatureProvider;

public class SignatureUtils {
	
	public static EccSignatureProvider eccSignatureProvider = new EccSignatureProvider();
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * Generates a compact ECDSA signature using the given EC key pair and hashed data.
	 *
	 * @param keyPair The EC key pair containing both the private and public keys
	 * @param hashedSource The original hashed data to be signed
	 * @param eccCurveType The ECC curve type used for generating the signature
	 * @return a byte array containing the compact ECDSA signature
	 * @throws CryptoException
	 */
	public static byte[] generateCompactSignature(EcKeyPair keyPair, byte[] hashedSource, EccCurveType eccCurveType)
			throws CryptoException {

        if (keyPair == null || keyPair.getPrivateKey() == null || keyPair.getPublicKey() == null) {
        	throw new CryptoException(CryptoErrorCode.ERR_CODE_SIGNATUREUTIL_INVALID_PARAM, "KeyPair is null");
        }
        if (hashedSource == null || hashedSource.length == 0) {
        	throw new CryptoException(CryptoErrorCode.ERR_CODE_SIGNATUREUTIL_INVALID_PARAM, "Hashed Source is null");
        }
        if (eccCurveType == null) {
        	throw new CryptoException(CryptoErrorCode.ERR_CODE_SIGNATUREUTIL_INVALID_PARAM, "EccCurve Type is null");
        }
	
		byte[] signaure = generateEccSignatureFromHashedData(keyPair.getPrivateKey(), hashedSource);
		byte[] compactSignarue = convertToCompactSignature(keyPair.getPublicKey(), hashedSource, signaure,
				eccCurveType);

		return compactSignarue;
	}
	
	/**
	 * Generates an ECDSA signature in ASN.1 DER format from hashed data using the given private key and ECC curve type.
	 *
	 * @param privateKey The private key used for generating the signature
	 * @param hashedSource The original hashed data to be signed
	 * @return a byte array containing the ECDSA signature in ASN.1 DER format
	 * @throws CryptoException
	 */
	public static byte[] generateEccSignatureFromHashedData(PrivateKey privateKey, byte[] hashedSource) throws CryptoException {

		if (privateKey == null) {
			throw new CryptoException(CryptoErrorCode.ERR_CODE_SIGNATUREUTIL_INVALID_PARAM, "Private Key is null");
		}
		if (hashedSource == null || hashedSource.length == 0) {
			throw new CryptoException(CryptoErrorCode.ERR_CODE_SIGNATUREUTIL_INVALID_PARAM, "Hashed Source is null");
		}

		return eccSignatureProvider.generateSignatureFromHashedData(privateKey, hashedSource);
	}

	/**
	 * Converts an ECDSA signature in ASN.1 DER format to a compact format using the given public key, hashed data, and ECC curve type.
	 *
	 * @param publicKey The public key corresponding to the private key used for signing
	 * @param hashedSource The original hashed data to be signed
	 * @param signatureBytes The original ECDSA signature bytes in ASN.1 DER format
	 * @param eccCurveType The ECC curve type used for generating the signature
	 * @return a byte array containing the compact ECDSA signature
	 * @throws CryptoException
	 */
	public static byte[] convertToCompactSignature(PublicKey publicKey, byte[] hashedsource, byte[] signatureBytes,
			EccCurveType eccCurveType) throws CryptoException {
		
		if (publicKey == null ) {
			throw new CryptoException(CryptoErrorCode.ERR_CODE_SIGNATUREUTIL_INVALID_PARAM, "Public Key is null");
		}
		if (hashedsource == null || hashedsource.length == 0 ) {
			throw new CryptoException(CryptoErrorCode.ERR_CODE_SIGNATUREUTIL_INVALID_PARAM, "Hashed Source is null");
		}
		if (signatureBytes == null || signatureBytes.length == 0 ) {
			throw new CryptoException(CryptoErrorCode.ERR_CODE_SIGNATUREUTIL_INVALID_PARAM, "SignatureBytes is null");
		}
		
		if (eccCurveType == null) {
			throw new CryptoException(CryptoErrorCode.ERR_CODE_SIGNATUREUTIL_INVALID_PARAM, "EccCurve Type is null");
		}
		return eccSignatureProvider.convertToCompactSignature(publicKey, hashedsource, signatureBytes, eccCurveType);
	}

	/**
	 * Verifies a compact ECDSA signature using the given compressed public key, hashed data, and ECC curve type.
	 *
	 * @param compressedPublicKeyBytes The compressed public key bytes used for verifying the signature
	 * @param hashedSource The original hashed data to be signed
	 * @param signatureBytes The compact ECDSA signature bytes
	 * @param eccCurveType The ECC curve type used for generating the signature
	 * @throws CryptoException
	 */
	public static void verifyCompactSignWithCompressedKey(byte[] compressedpublicKeyBytes, byte[] hashedsource,
			byte[] signatureBytes, EccCurveType eccCurveType) throws CryptoException {
		
		if (compressedpublicKeyBytes == null || compressedpublicKeyBytes.length != 33) {
			throw new CryptoException(
			        CryptoErrorCode.ERR_CODE_SIGNATUREUTIL_INVALID_PARAM, "Compressed PublicKeyBytes is null");
		}
		if (hashedsource == null || hashedsource.length == 0) {
			throw new CryptoException(CryptoErrorCode.ERR_CODE_SIGNATUREUTIL_INVALID_PARAM, "Hashed Source is null");
		}
		if (signatureBytes == null || signatureBytes.length == 0) {
			throw new CryptoException(CryptoErrorCode.ERR_CODE_SIGNATUREUTIL_INVALID_PARAM, "SignatureBytes is null");
		}

		eccSignatureProvider.verifyCompactSignWithCompressedKey(compressedpublicKeyBytes, hashedsource, signatureBytes, eccCurveType);
	}
}