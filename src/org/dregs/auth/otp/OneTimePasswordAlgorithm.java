package org.dregs.auth.otp;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class OneTimePasswordAlgorithm {
    private static final int[] doubleDigits = new int[]{0, 2, 4, 6, 8, 1, 3, 5, 7, 9};
    private static final int[] DIGITS_POWER = new int[]{1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};

    private OneTimePasswordAlgorithm() {
    }

    public static int calcChecksum(long num, int digits) {
        boolean doubleDigit = true;

        int total;
        int result;
        for (total = 0; 0 < digits--; doubleDigit = !doubleDigit) {
            result = (int) (num % 10L);
            num /= 10L;
            if (doubleDigit) {
                result = doubleDigits[result];
            }

            total += result;
        }

        result = total % 10;
        if (result > 0) {
            result = 10 - result;
        }

        return result;
    }

    public static byte[] hmac_sha(MacAlgorithm macAlgorithm, byte[] keyBytes, byte[] text) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmacSha1;
        try {
            hmacSha1 = Mac.getInstance(macAlgorithm.name());
        } catch (NoSuchAlgorithmException var4) {
            hmacSha1 = Mac.getInstance(macAlgorithm.as());
        }

        SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
        hmacSha1.init(macKey);
        return hmacSha1.doFinal(text);
    }

    public static String generateOTP(MacAlgorithm macAlgorithm, byte[] secret, long movingFactor, int codeDigits, boolean addChecksum, int truncationOffset) throws NoSuchAlgorithmException, InvalidKeyException {
        int digits = addChecksum ? codeDigits + 1 : codeDigits;
        byte[] text = new byte[8];

        for (int i = text.length - 1; i >= 0; --i) {
            text[i] = (byte) ((int) (movingFactor & 255L));
            movingFactor >>= 8;
        }

        byte[] hash = hmac_sha(macAlgorithm, secret, text);
        int offset = hash[hash.length - 1] & 15;
        if (0 <= truncationOffset && truncationOffset < hash.length - 4) {
            offset = truncationOffset;
        }

        int binary = (hash[offset] & 127) << 24 | (hash[offset + 1] & 255) << 16 | (hash[offset + 2] & 255) << 8 | hash[offset + 3] & 255;
        int otp = binary % DIGITS_POWER[codeDigits];
        if (addChecksum) {
            otp = otp * 10 + calcChecksum(otp, codeDigits);
        }

        StringBuilder result = new StringBuilder(Integer.toString(otp));

        while (result.length() < digits) {
            result.insert(0, "0");
        }

        return result.toString();
    }
}

