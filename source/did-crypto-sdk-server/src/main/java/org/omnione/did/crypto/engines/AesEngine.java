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

package org.omnione.did.crypto.engines;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.omnione.did.crypto.enums.EncryptionMode;
import org.omnione.did.crypto.exception.CryptoErrorCode;
import org.omnione.did.crypto.exception.CryptoException;

public class AesEngine {

    /**
     * Encrypts or decrypts data using the specified AES cipher information, key, and IV.
     *
     * @param source the data to be encrypted or decrypted
     * @param cipherInfo The cipher information (e.g., algorithm, mode, padding)
     * @param key the encryption key
     * @param iv the initialization vector (IV)
     * @param mode the operation mode (Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE)
     * @return the encrypted or decrypted data
     * @throws CryptoException
     */
    public byte[] aesEncryptDecrypt(byte[] source, CipherInfo cipherInfo, byte[] key, byte[] iv, int mode) throws CryptoException {
        byte[] encDecData = null;

        SecretKey sKey = new SecretKeySpec(key, 0, key.length, cipherInfo.getType().getRawValue());

        AlgorithmParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher;
        try {
            cipher = Cipher.getInstance(convertCipherType(cipherInfo));
            if(EncryptionMode.ECB == cipherInfo.getMode()) {
                cipher.init(mode, sKey);
            } else {
                cipher.init(mode, sKey, ivSpec);
            }

            encDecData = cipher.doFinal(source);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOUTIL_ENCDEC_FAIL, e.getMessage());
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOUTIL_ENCDEC_FAIL, e.getMessage());
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOUTIL_ENCDEC_FAIL, e.getMessage());
        }

        return encDecData;
    }

    /**
     * Converts the cipher information to a string format used by the Cipher class.
     *
     * @param cipherInfo The cipher information (e.g., algorithm, mode, padding)
     * @return The string representation of the cipher information
     */
    private String convertCipherType(CipherInfo cipherInfo) {
        StringBuilder sb = new StringBuilder();
        sb.append(cipherInfo.getType().getRawValue());
        sb.append("/");
        sb.append(cipherInfo.getMode().getRawValue());
        sb.append("/");
        sb.append(cipherInfo.getPadding().getRawValue());
        return sb.toString();
    }
}
