/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.crypto.util;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.omnione.did.crypto.constant.CryptoConstant;
import org.omnione.did.crypto.engines.AesEngine;
import org.omnione.did.crypto.engines.CipherInfo;
import org.omnione.did.crypto.enums.DidKeyType;
import org.omnione.did.crypto.enums.EccCurveType;
import org.omnione.did.crypto.exception.CryptoErrorCode;
import org.omnione.did.crypto.exception.CryptoException;
import org.omnione.did.crypto.generator.EcKeyPairGenerator;
import org.omnione.did.crypto.generator.GenerateSecureRandom;
import org.omnione.did.crypto.generator.RsaKeyPairGenerator;
import org.omnione.did.crypto.keypair.KeyPairInterface;

public class CryptoUtils {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final RsaKeyPairGenerator rsaKeyPairGenerator = new RsaKeyPairGenerator();
    private static final EcKeyPairGenerator ecKeyPairGenerator = new EcKeyPairGenerator();
    private static final GenerateSecureRandom generateSecureRandom = new GenerateSecureRandom();
    private static final AesEngine aesEngine = new AesEngine();

  /**
   * Generate ECC KeyPair
   * 
   * @param DidKeyType The type of DID key (e.g., RSA or specific ECC curve)
   * @return KeyPairInterface The generated key pair
   * @throws CryptoException 
   */
  public static KeyPairInterface generateKeyPair(DidKeyType didKeyType) throws CryptoException{
    if(DidKeyType.RSA_VERIFICATION_KEY_2018 == didKeyType) {
      return rsaKeyPairGenerator.generateKeyPair();
    }
    else if (DidKeyType.SECP256K1_VERIFICATION_KEY_2018 == didKeyType){
      return ecKeyPairGenerator.generateKeyPair(EccCurveType.Secp256k1);
    }
    else if (DidKeyType.SECP256R1_VERIFICATION_KEY_2018 == didKeyType) {
      return ecKeyPairGenerator.generateKeyPair(EccCurveType.Secp256r1);
    }
    else {
      throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOUTIL_INVALID_DID_KEY_TYPE);
    }
  }
  
  /**
   * Compress ECC PublicKey
   * 
   * @param unCompressedPublicKeyBytes The uncompressed ECC public key bytes
   * @param eccCurveType The ECC curve type
   * @return The compressed ECC public key bytes
   * @throws CryptoException 
   */
  public static byte[] compressPublicKey(byte[] unCompressedPublicKeyBytes, EccCurveType eccCurveType) throws CryptoException{

    KeyFactory keyFactory;
    ECPublicKey publicKey = null;
    
    try {
      keyFactory = KeyFactory.getInstance(CryptoConstant.PROVIDER_EC, CryptoConstant.PROVIDER_BC);
      X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(unCompressedPublicKeyBytes);
      publicKey = (ECPublicKey) keyFactory.generatePublic(publicKeySpec);
    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
      throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOUTIL_COMPRESS_PUBLIC_KEY_FAIL, e.getMessage());
    } catch (InvalidKeySpecException e) {
      throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOUTIL_COMPRESS_PUBLIC_KEY_FAIL, e.getMessage());
    }

    ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(eccCurveType.getCurveName());
    ECPoint point = ecSpec.getCurve().createPoint(publicKey.getW().getAffineX(), publicKey.getW().getAffineY());

    byte[] compressedPublicKey = point.getEncoded(true);
    return compressedPublicKey;
  }


  /**
   * Uncompress ECC PublicKey
   * 
   * @param compressedPublicKey The compressed ECC public key bytes
   * @param eccCurveType The ECC curve type
   * @return The uncompressed ECC public key bytes
   * @exception CryptoException
   * @throws CryptoException 
   */
  public static byte[] unCompressPublicKey(byte[] compressedPublicKey, EccCurveType eccCurveType) throws CryptoException{
	    byte[] uncompressPublicKey = null;

	    ECNamedCurveParameterSpec ecParams = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec(eccCurveType.getCurveName());
	    ECPoint uncompressedPoint = ecParams.getCurve().decodePoint(compressedPublicKey);
	    
	    ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(uncompressedPoint, ecParams);
	    KeyFactory keyFactory;
	    try {
	      keyFactory = KeyFactory.getInstance(CryptoConstant.PROVIDER_EC, CryptoConstant.PROVIDER_BC);
	      uncompressPublicKey = keyFactory.generatePublic(pubKeySpec).getEncoded();
	    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
	      throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOUTIL_COMPRESS_PUBLIC_KEY_FAIL, e.getMessage());
	    } catch (InvalidKeySpecException e) {
	      throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOUTIL_COMPRESS_PUBLIC_KEY_FAIL, e.getMessage());
	    }
	    
	    return uncompressPublicKey;
	  }

  /**
   * Generate Nonce
   * 
   * @return The generated nonce
   * @throws CryptoException
   */
	public static byte[] generateNonce(int length) throws CryptoException {
		return generateSecureRandom.generateSecureRandom(length);
	}
  
  
  /**
   * Generate Salt
   * 
   * @return The generated salt
   * @throws CryptoException
   */
	public static byte[] generateSalt() throws CryptoException {
		return generateSecureRandom.generateSalt();
	}

  /**
   * Generate SharedSecret
   * 
   * @param compressedPublicKeyBytes The compressed ECC public key bytes
   * @param privateKeyBytes The private key bytes
   * @param eccCurveType The ECC curve type
   * @return The generated shared secret
   * @throws CryptoException 
   */
  public static byte[] generateSharedSecret(byte[] compressedPublicKeyBytes, byte[] privateKeyBytes, EccCurveType eccCurveType) throws CryptoException{
	  
	
	byte[]  unCompressedPublicKeyBytes = unCompressPublicKey(compressedPublicKeyBytes, eccCurveType) ; 
    KeyFactory keyFactory;
    ECPoint P = null; 
    
    try {
      keyFactory = KeyFactory.getInstance(CryptoConstant.PROVIDER_EC, CryptoConstant.PROVIDER_BC);
      ECPrivateKey ecPrivateKey = (ECPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
      
      ECPublicKey ecPublicKey = (ECPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(unCompressedPublicKeyBytes));

      ECPrivateKeyParameters privKeyParams = (ECPrivateKeyParameters) ECUtil.generatePrivateKeyParameter(ecPrivateKey);
      ECPublicKeyParameters pubKeyParams = (ECPublicKeyParameters) ECUtil.generatePublicKeyParameter(ecPublicKey);
      P = pubKeyParams.getQ().multiply(privKeyParams.getD()).normalize();

    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
      throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOUTIL_GEN_SECRET_FAIL, e.getMessage());
    } catch (InvalidKeySpecException e) {
      throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOUTIL_GEN_SECRET_FAIL, e.getMessage());
    } catch (InvalidKeyException e) {
      throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOUTIL_GEN_SECRET_FAIL, e.getMessage());
    }

    if (P.isInfinity()) {
      throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOUTIL_GEN_SECRET_FAIL, "Infinity is not a valid agreement value for ECDH");
    }

    BigInteger bitInt = P.getAffineXCoord().toBigInteger();
    
    byte[] sharedSecret = bitInt.toByteArray();
    
    if (sharedSecret[0] == 0) {
        sharedSecret = Arrays.copyOfRange(sharedSecret, 1, sharedSecret.length);
    }

    return sharedSecret;
  }
  
  /**
   * Key Derivation Function By pbkdf2
   * 
   * @param password The password to derive the key from
   * @param salt The salt to use in the key derivation
   * @param iterator The number of iterations for the key derivation function
   * @param keySize The desired size of the derived key
   * @return derived byte[] key
   * @throws CryptoException 
   */
	public static byte[] pbkdf2(char[] password, byte[] salt, int iterator, int keySize) throws CryptoException {
		SecretKeySpec skeySpec = null;
		try {
			// Derive the key
			SecretKeyFactory factory = SecretKeyFactory.getInstance(CryptoConstant.PBKDF2_ALG_HMAC_SHA1);
			PBEKeySpec spec = new PBEKeySpec(password, salt, iterator, keySize);

			// Secret Key
			SecretKey secretKey = factory.generateSecret(spec);
			skeySpec = new SecretKeySpec(secretKey.getEncoded(), CryptoConstant.ALG_AES);
			return skeySpec.getEncoded();
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOUTIL_GEN_SECRET_FAIL, e.getMessage());
		}
	}

  /**
   * AES Encrypt
   * 
   * @param source The plaintext data to encrypt
   * @param cipherInfo The cipher information (e.g., algorithm, mode, padding)
   * @param key The encryption key
   * @param iv The initialization vector
   * @return The encrypted data
   * @throws CryptoException 
   */
  public static byte[] encrypt(byte[] source, CipherInfo cipherInfo, byte[] key, byte[] iv) throws CryptoException {
    return aesEngine.aesEncryptDecrypt(source, cipherInfo, key, iv, Cipher.ENCRYPT_MODE);
  }

  /**
   * AES Decrypt
   * 
   * @param cipherText The encrypted data to decrypt
   * @param cipherInfo The cipher information (e.g., algorithm, mode, padding)
   * @param key The decryption key
   * @param iv The initialization vector
   * @return The decrypted (plaintext) data
   * @throws CryptoException 
   */
  public static byte[] decrypt(byte[] cipherText, CipherInfo cipherInfo, byte[] key, byte[] iv) throws CryptoException {
    return aesEngine.aesEncryptDecrypt(cipherText, cipherInfo, key, iv, Cipher.DECRYPT_MODE);
  }

}
