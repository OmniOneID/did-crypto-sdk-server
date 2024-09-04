/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.crypto.signature;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import org.omnione.did.crypto.constant.CryptoConstant;
import org.omnione.did.crypto.ec.CompactSign;
import org.omnione.did.crypto.enums.DidKeyType;
import org.omnione.did.crypto.enums.EccCurveType;
import org.omnione.did.crypto.exception.CryptoErrorCode;
import org.omnione.did.crypto.exception.CryptoException;
import org.omnione.did.crypto.util.CryptoUtils;

public class EccSignatureProvider implements SignatureProvider {

	public static CompactSign compactSign = new CompactSign();

	/**
	 * Generates an ECDSA signature from the given hashed data.
	 *
	 * @param privateKey The private key used for signing
	 * @param hashedSource The original hashed data to be signed
	 * @param eccCurveType The type of ECC curve to use
	 * @return The ECDSA signature in ASN.1 DER format
	 * @throws CryptoException
	 */
	public byte[] generateSignatureFromHashedData(PrivateKey privateKey, byte[] hashedSource) throws CryptoException {
		byte[] signData = null;

		try {
			Signature signature = null;

			try {
				signature = Signature.getInstance(CryptoConstant.SIG_ALG_NONE_ECDSA, CryptoConstant.PROVIDER_BC);
			} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
				throw new CryptoException(CryptoErrorCode.ERR_CODE_SIGNATUREUTIL_INVALID_SIGN_VALUE, e.getMessage());
			}

			signature.initSign(privateKey);
			signature.update(hashedSource);
			signData = signature.sign();
		} catch (SignatureException | InvalidKeyException e) {
			throw new CryptoException(CryptoErrorCode.ERR_CODE_SIGNATUREUTIL_INVALID_SIGN_VALUE, e.getMessage());
		}

		return signData;

	}

	/**
	 * Converts an ECDSA signature in ASN.1 DER format to a compact signature.
	 *
	 * @param publicKey The public key corresponding to the private key used for signing
	 * @param source The original hashed data to be signed
	 * @param signData The ECDSA signature in ASN.1 DER format
	 * @param eccCurveType The type of ECC curve to use
	 * @return The compact signature
	 * @throws CryptoException
	 */
	public byte[] convertToCompactSignature(PublicKey publicKey, byte[] source, byte[] signData,
			EccCurveType eccCurveType) throws CryptoException {

		byte[] compressedPubKey = null;
		compressedPubKey = CryptoUtils.compressPublicKey(publicKey.getEncoded(), eccCurveType);

		return compactSign.getSignBytes(compressedPubKey, source, signData, eccCurveType.getCurveName());
	}

	/**
	 * Verifies a compact signature using a compressed public key.
	 *
	 * @param compressedpublicKeyBytes The compressed public key bytes
	 * @param source The original hashed data that was signed
	 * @param signatureBytes The compact signature bytes
	 * @param eccCurveType The type of ECC curve to use
	 * @throws CryptoException
	 */
	public void verifyCompactSignWithCompressedKey(byte[] compressedpublicKeyBytes, byte[] source,
			byte[] signatureBytes, EccCurveType eccCurveType) throws CryptoException {

		compactSign.verifySign(compressedpublicKeyBytes, source, signatureBytes, eccCurveType.getCurveName());
	}

	/**
	 * Retrieves the ECC curve type corresponding to the given DID key type.
	 *
	 * @param didKeyType The DID key type
	 * @return The corresponding ECC curve type
	 * @throws CryptoException 
	 */
	public static EccCurveType getECTypeFromDidKeyType(DidKeyType didKeyType) throws CryptoException {
		switch (didKeyType) {
		case SECP256K1_VERIFICATION_KEY_2018:
			return EccCurveType.Secp256k1;
		case SECP256R1_VERIFICATION_KEY_2018:
			return EccCurveType.Secp256r1;
		default:
		    throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOUTIL_INVALID_DID_KEY_TYPE);
		}
	}

	/**
	 * Retrieves the signature algorithm corresponding to the given DID key type.
	 *
	 * @param didKeyType The DID key type
	 * @return The corresponding signature algorithm
	 * @throws CryptoException 
	 */
	public static String getSignatureAlgorithm(DidKeyType didKeyType) throws CryptoException {
		switch (didKeyType) {
		case RSA_VERIFICATION_KEY_2018:
			return "SHA256withRSA";
		case SECP256K1_VERIFICATION_KEY_2018:
		case SECP256R1_VERIFICATION_KEY_2018:
			return "SHA256withECDSA";
		default:
		    throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOUTIL_INVALID_DID_KEY_TYPE);
		}
	}
}
