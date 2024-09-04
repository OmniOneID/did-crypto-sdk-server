/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.crypto.ec;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;
import org.omnione.did.crypto.exception.CryptoErrorCode;
import org.omnione.did.crypto.exception.CryptoException;

public class CompactSign {

    /**
     * Converts an ECDSA signature in ASN.1 DER format to a compact signature.
     *
     * @param compressedPubKey The compressed public key used for recovery ID calculation
     * @param hashedsource The hashed original data
     * @param signData The ECDSA signature in ASN.1 DER format
     * @param curveName The name of the elliptic curve used
     * @return The compact signature
     * @throws CryptoException
     */
    public byte[] getSignBytes(byte[] compressedPubKey, byte[] hashedsource, byte[] signData, String curveName) throws CryptoException {
        ASN1Sequence asn1Sequence = parseASN1Sequence(signData);
        BigInteger[] rs = extractRS(asn1Sequence);
        BigInteger integerR = rs[0];
        BigInteger integerS = adjustS(rs[1], curveName);

        byte[] r = padTo32Bytes(integerR);
        byte[] s = padTo32Bytes(integerS);
        
        byte recoveryId = getRecoveryId(r, s, hashedsource, compressedPubKey, curveName);

        if (recoveryId < 0) {
            throw new CryptoException(CryptoErrorCode.ERR_CODE_SIGNATUREUTIL_INVALID_RECOVERY_ID);
        }

        return buildSignature(recoveryId, r, s);
    }

    /**
     * Parses the ASN.1 DER encoded signature data.
     *
     * @param signData The ECDSA signature in ASN.1 DER format
     * @return The ASN1Sequence containing the R and S values
     * @throws CryptoException
     */
    private ASN1Sequence parseASN1Sequence(byte[] signData) throws CryptoException {
        try (ByteArrayInputStream inStream = new ByteArrayInputStream(signData);
             ASN1InputStream asnInputStream = new ASN1InputStream(inStream)) {
            ASN1Primitive asn1 = asnInputStream.readObject();
            if (!(asn1 instanceof ASN1Sequence)) {
                throw new CryptoException(CryptoErrorCode.ERR_CODE_SIGNATUREUTIL_INVALID_ASN1_SEQUENCE);
            }
            return (ASN1Sequence) asn1;
        } catch (IOException e) {
            throw new CryptoException(CryptoErrorCode.ERR_CODE_SIGNATUREUTIL_INVALID_ASN1_SEQUENCE, e);
        }
    }

    /**
     * Extracts the R and S values from the ASN.1 sequence.
     *
     * @param asn1Sequence The ASN1Sequence containing the R and S values
     * @return an array of BigIntegers containing the R and S values
     * @throws CryptoException
     */
    private BigInteger[] extractRS(ASN1Sequence asn1Sequence) throws CryptoException {
        ASN1Encodable[] asn1Encodables = asn1Sequence.toArray();
        if (asn1Encodables.length != 2) {
            throw new CryptoException(CryptoErrorCode.ERR_CODE_SIGNATUREUTIL_INVALID_SIGN_VALUE);
        }
        BigInteger integerR = ((ASN1Integer) asn1Encodables[0].toASN1Primitive()).getValue();
        BigInteger integerS = ((ASN1Integer) asn1Encodables[1].toASN1Primitive()).getValue();
        return new BigInteger[]{integerR, integerS};
    }

    /**
     * Adjusts the S value to ensure it is less than or equal to half the curve order.
     *
     * @param s The original S value
     * @param curveName The name of the elliptic curve used
     * @return The adjusted S value
     */
    private BigInteger adjustS(BigInteger s, String curveName) {
        BigInteger curveN = CustomNamedCurves.getByName(curveName).getN();
        BigInteger halfCurveOrder = curveN.shiftRight(1);
        if (s.compareTo(halfCurveOrder) > 0) {
            s = curveN.subtract(s);
        }
        return s;
    }

    /**
     * Pads the BigInteger to a 32-byte array.
     *
     * @param value The BigInteger value to pad
     * @return The padded 32-byte array
     */
    private byte[] padTo32Bytes(BigInteger value) {
        byte[] result = new byte[32];
        byte[] byteArray = value.toByteArray();
        if (byteArray.length > 32) {
            System.arraycopy(byteArray, byteArray.length - 32, result, 0, 32);
        } else if (byteArray.length < 32) {
            System.arraycopy(byteArray, 0, result, 32 - byteArray.length, byteArray.length);
        } else {
            result = byteArray;
        }
        return result;
    }

    /**
     * Calculates the recovery ID for the given R and S values and the hashed message.
     *
     * @param sigR The R value of the signature
     * @param sigS The S value of the signature
     * @param hassedMessage The hashed original data
     * @param publicKey The compressed public key used for recovery ID calculation
     * @param curveName The name of the elliptic curve used
     * @return The recovery ID
     * @throws CryptoException
     */
    private byte getRecoveryId(byte[] sigR, byte[] sigS, byte[] hassedMessage, byte[] publicKey, String curveName) throws CryptoException {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveName);
        BigInteger pointN = spec.getN();

        for (int recoveryId = 0; recoveryId < 2; recoveryId++) {
            try {
                BigInteger pointX = new BigInteger(1, sigR);
                ECPoint pointR = decodePoint(spec, pointX, recoveryId);

                if (!pointR.multiply(pointN).isInfinity()) {
                    continue;
                }
                
                ECPoint pointQ = recoverPublicKey(spec, pointR, new BigInteger(1, sigS), new BigInteger(1, hassedMessage));
              
                if (Arrays.equals(publicKey, pointQ.getEncoded(true))) {
                    return (byte) recoveryId;
                }
            } catch (Exception e) {
                throw new CryptoException(CryptoErrorCode.ERR_CODE_SIGNATUREUTIL_INVALID_RECOVERY_ID, e.getMessage());
            }
        }
        throw new CryptoException(CryptoErrorCode.ERR_CODE_SIGNATUREUTIL_INVALID_RECOVERY_ID);
    }

    /**
     * Decodes the ECPoint from the given point X and recovery ID.
     *
     * @param spec The elliptic curve parameter specification
     * @param pointX The X coordinate of the point
     * @param recoveryId The recovery ID
     * @return The decoded ECPoint
     */
    private static ECPoint decodePoint(ECNamedCurveParameterSpec spec, BigInteger pointX, int recoveryId) {
        X9IntegerConverter x9 = new X9IntegerConverter();
        byte[] compEnc = x9.integerToBytes(pointX, 1 + x9.getByteLength(spec.getCurve()));
        compEnc[0] = (byte) ((recoveryId & 1) == 1 ? 0x03 : 0x02);
        return spec.getCurve().decodePoint(compEnc);
    }

    /**
     * Recovers the public key from the given parameters.
     *
     * @param spec The elliptic curve parameter specification
     * @param pointR The R point of the signature
     * @param sigS The S value of the signature
     * @param message Hashed original data converted to BigInteger
     * @return The recovered public key
     */
    private ECPoint recoverPublicKey(ECNamedCurveParameterSpec spec, ECPoint pointR, BigInteger sigS, BigInteger message) {
        BigInteger pointN = spec.getN();
        BigInteger pointEInv = message.negate().mod(pointN);
        BigInteger pointRInv = pointR.getXCoord().toBigInteger().modInverse(pointN);
        BigInteger srInv = pointRInv.multiply(sigS).mod(pointN);
        BigInteger pointEInvRInv = pointRInv.multiply(pointEInv).mod(pointN);
        return ECAlgorithms.sumOfTwoMultiplies(spec.getG(), pointEInvRInv, pointR, srInv);
    }

    /**
     * Builds the compact signature from the given recovery ID, R and S values.
     *
     * @param recoveryId The recovery ID
     * @param r The R value of the signature
     * @param s The S value of the signature
     * @return The compact signature
     */
    private byte[] buildSignature(byte recoveryId, byte[] r, byte[] s) {
        byte[] combined = new byte[65];
        ByteBuffer buff = ByteBuffer.wrap(combined);
        buff.put((byte) (recoveryId + 27 + 4));
        buff.put(r);
        buff.put(s);
        return combined;
    }

    /**
     * Verifies the compact signature with the compressed public key.
     *
     * @param pubkey_rw the compressed public key
     * @param hashedSource The hashed original data
     * @param signature_rw The compact signature
     * @param curveName The name of the elliptic curve used
     * @throws CryptoException
     */
    public void verifySign(byte[] pubkey_rw, byte[] hashedSource, byte[] signature_rw, String curveName) throws CryptoException {
        if (pubkey_rw.length != 33) {
            throw new CryptoException(CryptoErrorCode.ERR_CODE_SIGNATUREUTIL_INVALID_PUBLIC_KEY);
        }

        if (signature_rw == null || signature_rw.length != 65) {
            throw new CryptoException(CryptoErrorCode.ERR_CODE_SIGNATUREUTIL_INVALID_SIGN_VALUE);
        }

        byte[] sigR = Arrays.copyOfRange(signature_rw, 1, 33);
        byte[] sigS = Arrays.copyOfRange(signature_rw, 33, 65);
        int recId = (signature_rw[0] & 0xFF) - 27 - 4;

        byte[] recoveredPubKey = getRecoveryComPublicKey(sigR, sigS, hashedSource, curveName, recId);
        if (!Arrays.equals(pubkey_rw, recoveredPubKey)) {
            throw new CryptoException(CryptoErrorCode.ERR_CODE_SIGNATUREUTIL_NO_MATCH_RECOVERY_KEY);
        }
    }

    /**
     * Recovers the compressed public key from the given signature components (R, S) and hashed source data.
     *
     * @param sigR The R component of the ECDSA signature.
     * @param sigS The S component of the ECDSA signature.
     * @param hashedSource The hashed original data that was signed.
     * @param curveName The name of the elliptic curve used for the ECDSA signature.
     * @param recoveryId The recovery ID used to reconstruct the public key.
     * @return The compressed public key as a byte array.
     * @throws CryptoException
     */
    private static byte[] getRecoveryComPublicKey(byte[] sigR, byte[] sigS, byte[] hashedSource, String curveName, int recoveryId) throws CryptoException {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveName);
        BigInteger pointN = spec.getN();

        try {
            BigInteger pointX = new BigInteger(1, sigR);
            ECPoint pointR = decodePoint(spec, pointX, recoveryId);
            BigInteger pointEInv = new BigInteger(1, hashedSource).negate().mod(pointN);
            BigInteger pointRInv = pointR.getXCoord().toBigInteger().modInverse(pointN);
            BigInteger srInv = pointRInv.multiply(new BigInteger(1, sigS)).mod(pointN);
            BigInteger pointEInvRInv = pointRInv.multiply(pointEInv).mod(pointN);
            ECPoint pointQ = ECAlgorithms.sumOfTwoMultiplies(spec.getG(), pointEInvRInv, pointR, srInv);
            return pointQ.getEncoded(true);
        } catch (Exception e) {
            throw new CryptoException(CryptoErrorCode.ERR_CODE_SIGNATUREUTIL_PUBLIC_KEY_RECOVERY_FAIL, e.getMessage());
        }
    }
}