/* 
 * Copyright 2024 Raonsecure
 */

package org.omnione.did.crypto.encoding;

import java.nio.charset.StandardCharsets;

public class Base58 {
	
    private static final char[] ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();
    private static final int[] INDEXES = new int[128];

    static {
        for (int i = 0; i < INDEXES.length; i++) {
            INDEXES[i] = -1;
        }
        for (int i = 0; i < ALPHABET.length; i++) {
            INDEXES[ALPHABET[i]] = i;
        }
    }

    /**
     * Encodes the given byte array using Base58 encoding.
     *
     * @param input the byte array to encode
     * @return the Base58 encoded string
     */
    public static String encode(byte[] input) {
        if (input.length == 0) {
            return "";
        }
        input = copyOfRange(input, 0, input.length);
        int zeroCount = 0;
        while (zeroCount < input.length && input[zeroCount] == 0) {
            zeroCount++;
        }

        byte[] temp = new byte[input.length * 2];
        int j = temp.length;

        int startAt = zeroCount;
        while (startAt < input.length) {
            byte mod = divmod(input, startAt, 58);
            if (input[startAt] == 0) {
                startAt++;
            }
            temp[--j] = (byte) ALPHABET[mod];
        }

        while (j < temp.length && temp[j] == ALPHABET[0]) {
            j++;
        }

        while (zeroCount-- > 0) {
            temp[--j] = (byte) ALPHABET[0];
        }

        return new String(temp, j, temp.length - j, StandardCharsets.US_ASCII);
    }

    /**
     * Decodes the given Base58 encoded string into a byte array.
     *
     * @param input the Base58 encoded string to decode
     * @return the decoded byte array, or null if the input is not valid Base58
     */
    public static byte[] decode(String input) {
        if (input.length() == 0) {
            return new byte[0];
        }

        byte[] input58 = new byte[input.length()];
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            int digit58 = (c < 128) ? INDEXES[c] : -1;
            if (digit58 < 0) {
                return null;
            }
            input58[i] = (byte) digit58;
        }

        int zeroCount = 0;
        while (zeroCount < input58.length && input58[zeroCount] == 0) {
            zeroCount++;
        }

        byte[] temp = new byte[input.length()];
        int j = temp.length;

        int startAt = zeroCount;
        while (startAt < input58.length) {
            byte mod = divmod(input58, startAt, 256);
            if (input58[startAt] == 0) {
                startAt++;
            }
            temp[--j] = mod;
        }

        while (j < temp.length && temp[j] == 0) {
            j++;
        }

        return copyOfRange(temp, j - zeroCount, temp.length);
    }

    /**
     * Performs division and modulo operations on the given byte array.
     *
     * @param number the byte array to operate on
     * @param startAt the starting index for the operation
     * @param base the base to use for the division and modulo operations
     * @return the remainder of the division operation
     */
    private static byte divmod(byte[] number, int startAt, int base) {
        int remainder = 0;
        for (int i = startAt; i < number.length; i++) {
            int digit = (number[i] & 0xFF);
            int temp = (base == 58 ? remainder * 256 : remainder * 58) + digit;
            number[i] = (byte) (temp / base);
            remainder = temp % base;
        }
        return (byte) remainder;
    }

    /**
     * Copies a range of elements from the given byte array.
     *
     * @param source the source byte array
     * @param from the starting index (inclusive)
     * @param to the ending index (exclusive)
     * @return the new byte array containing the specified range from the source array
     */
    private static byte[] copyOfRange(byte[] source, int from, int to) {
        byte[] range = new byte[to - from];
        System.arraycopy(source, from, range, 0, range.length);
        return range;
    }
}