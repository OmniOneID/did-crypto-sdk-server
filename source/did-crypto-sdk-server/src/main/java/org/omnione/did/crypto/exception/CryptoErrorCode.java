/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.crypto.exception;

public enum CryptoErrorCode implements CryptoErrorCodeInterface{
    
    ERR_CODE_CRYPTO_SDK_BASE("SSDKCRT", ""),
    
	ERR_CODE_DIGESTUTIL_BASE(ERR_CODE_CRYPTO_SDK_BASE, "01", ""),
	ERR_CODE_DIGESTUTIL_INVALID_HASH_TYPE(ERR_CODE_DIGESTUTIL_BASE, 		    "000",	"Hash type is invalid"),
    ERR_CODE_DIGESTUTIL_GEN_HASH_FAIL(ERR_CODE_DIGESTUTIL_BASE,                 "001",   "Failed to generate hash"),
	ERR_CODE_DIGESTUTIL_GEN_RANDOM_FAIL(ERR_CODE_DIGESTUTIL_BASE,               "002",   "Failed to generate secure random"),
    ERR_CODE_DIGESTUTIL_HASH_TYPE_OR_SOURCE_IS_NULL(ERR_CODE_DIGESTUTIL_BASE,   "003",   "Hash type or Source is null"),

    ERR_CODE_CRYPTOUTIL_BASE(ERR_CODE_CRYPTO_SDK_BASE, "02", ""),
    ERR_CODE_CRYPTOUTIL_INVALID_DID_KEY_TYPE(ERR_CODE_CRYPTOUTIL_BASE,          "000",   "Invalid DID Key Type"),
	ERR_CODE_CRYPTOUTIL_GEN_RANDOM_KEY_FAIL(ERR_CODE_CRYPTOUTIL_BASE,           "001",   "Failed to generate random key"),
    ERR_CODE_CRYPTOUTIL_COMPRESS_PUBLIC_KEY_FAIL(ERR_CODE_CRYPTOUTIL_BASE,      "002",   "Failed to Compress PublicKey"),
    ERR_CODE_CRYPTOUTIL_UNCOMPRESS_PUBLIC_KEY_FAIL(ERR_CODE_CRYPTOUTIL_BASE,    "003",   "Failed to UnCompress PublicKey"),
    ERR_CODE_CRYPTOUTIL_GEN_SECRET_FAIL(ERR_CODE_CRYPTOUTIL_BASE,               "004",   "Failed to generate shared secret"),
    ERR_CODE_CRYPTOUTIL_INVALID_CIPHER_INFO_TYPE(ERR_CODE_CRYPTOUTIL_BASE,      "005",   "Cipher type is invalid"),
    ERR_CODE_CRYPTOUTIL_ENCDEC_FAIL(ERR_CODE_CRYPTOUTIL_BASE,                   "006",   "Failed to Encrypt, Decrypt"),  
    ERR_CODE_CRYPTOUTIL_CONVERT_RSA_KEY_FAIL(ERR_CODE_CRYPTOUTIL_BASE,          "007",   "Failed to convert Rsa Key"),
    
    ERR_CODE_MULTIBASEUTIL_BASE(ERR_CODE_CRYPTO_SDK_BASE, "03", ""),
    ERR_CODE_MULTIBASEUTIL_INVALID_ENCODING_TYPE(ERR_CODE_MULTIBASEUTIL_BASE,   "000", "Multibase encoding type is invalid"),
    ERR_CODE_MULTIBASEUTIL_INVALID_DECODING_TYPE(ERR_CODE_MULTIBASEUTIL_BASE,   "001", "Multibase decoding type is invalid"),
   
    ERR_CODE_SIGNATUREUTIL_BASE(ERR_CODE_CRYPTO_SDK_BASE, "04", ""),
    ERR_CODE_SIGNATUREUTIL_INVALID_RECOVERY_ID(ERR_CODE_SIGNATUREUTIL_BASE,       	"000", "Failed to recover valid recovery ID"),
    ERR_CODE_SIGNATUREUTIL_INVALID_PARAM(ERR_CODE_MULTIBASEUTIL_BASE,				"001", "The provided input value is invalid."),
    ERR_CODE_SIGNATUREUTIL_INVALID_ASN1_SEQUENCE(ERR_CODE_SIGNATUREUTIL_BASE,       "002", "This indicates that the ASN.1 sequence is invalid"),
    ERR_CODE_SIGNATUREUTIL_INVALID_SIGN_VALUE(ERR_CODE_SIGNATUREUTIL_BASE,      	"003", "It is not a compact sign"),
    ERR_CODE_SIGNATUREUTIL_INVALID_PUBLIC_KEY(ERR_CODE_SIGNATUREUTIL_BASE,       	"004", "The publicKey is not in compressed public key format"),
    ERR_CODE_SIGNATUREUTIL_PUBLIC_KEY_RECOVERY_FAIL(ERR_CODE_SIGNATUREUTIL_BASE,    "005", "RecoveryKey creation failed"),
    ERR_CODE_SIGNATUREUTIL_NO_MATCH_RECOVERY_KEY(ERR_CODE_SIGNATUREUTIL_BASE,  		"006", "RecoveryKey and publicKey do not match"),

	;
	
	private String code;
	private String msg;

	private CryptoErrorCode(String code, String msg) {
		this.code = code;
		this.msg = msg;
	}
	private CryptoErrorCode(CryptoErrorCode errCodeKeymanagerKeyBase, String code, String msg) {
		this.code = errCodeKeymanagerKeyBase.getCode() + code;
		this.msg = msg;
	}

	@Override
	public String getCode() {
		return code;
	}
	
	@Override
	public String getMsg() {
		return msg;
	}
	
	public static CryptoErrorCodeInterface getEnumByCode(String code) {
		
		CryptoErrorCode agentTypes[] = CryptoErrorCode.values();
		for (CryptoErrorCode iwCode : agentTypes) {
			if(iwCode.getCode() == code){
				return iwCode;
			}
		}	
		throw new AssertionError("Unknown Enum Code");

	}

}
