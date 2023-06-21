package org.dregs.auth.otp;

import javax.crypto.KeyGenerator;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;

public class Totp {

    private MacAlgorithm generateKeyAlgorithm = MacAlgorithm.HmacSHA1;
    private MacAlgorithm passwordAlgorithm = MacAlgorithm.HmacSHA1;
    private int keySize = 160;
    private int passwordLength = 6;
    private long period = 30L;

    public MacAlgorithm generateKeyAlgorithm() {
        return generateKeyAlgorithm;
    }

    public MacAlgorithm passwordAlgorithm() {
        return passwordAlgorithm;
    }

    public int keySize() {
        return keySize;
    }

    public int passwordLength() {
        return passwordLength;
    }

    public long period() {
        return period;
    }

    public Totp(MacAlgorithm generateKeyAlgorithm,
                MacAlgorithm passwordAlgorithm,
                int keySize,
                int passwordLength,
                long period) {
        this.generateKeyAlgorithm = generateKeyAlgorithm;
        this.passwordAlgorithm = passwordAlgorithm;
        this.keySize = keySize;
        this.passwordLength = passwordLength;
        this.period = period;
    }

    public Totp() {
    }

    public String generateKey() {
        KeyGenerator keyGenerator = null;
        try {
            keyGenerator = KeyGenerator.getInstance(this.generateKeyAlgorithm.name());
        } catch (Exception e) {
            e.printStackTrace();
        }

        keyGenerator.init(this.keySize);
        return Base32.encode(keyGenerator.generateKey().getEncoded());
    }

    public String generateUri(String key, String issuer, String user, String label) {
        try {
            if (label == null) {
                if (issuer == null) {
                    throw new IllegalArgumentException("label and issuer cannot all be null");
                }

                if (user == null) {
                    label = URLEncoder.encode(issuer, "UTF8");
                } else {
                    label = URLEncoder.encode(issuer, "UTF8") + ":" + URLEncoder.encode(user, "UTF8");
                }
            }

            StringBuilder sb = new StringBuilder();
            sb.append("secret=").append(key);
            if (issuer != null) {
                sb.append("&issuer=").append(URLEncoder.encode(issuer, "UTF8"));
            }

            if (this.passwordAlgorithm != null && this.passwordAlgorithm != MacAlgorithm.HmacSHA1) {
                sb.append("&algorithm=").append(this.passwordAlgorithm.name().substring(4));
            }

            if (this.passwordLength != 6) {
                sb.append("&digits=").append(this.passwordLength);
            }

            sb.append("&period=").append(this.period);
            return String.format("otpauth://totp/%s?%s", label, sb);
        } catch (UnsupportedEncodingException var6) {
            throw new RuntimeException(var6);
        }
    }

    public String generateCode(String key) {
        long movingFactor = Instant.now().getEpochSecond() / this.period;
        try {
            return OneTimePasswordAlgorithm.generateOTP(this.passwordAlgorithm, Base32.decode(key), movingFactor, this.passwordLength, false, -1);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }
    static final class Base32 {
        private static final char[] BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();
        private static final int[] BASE32_LOOKUP = new int[]{255, 255, 26, 27, 28, 29, 30, 31, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 255, 255, 255, 255, 255, 255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 255, 255, 255, 255, 255};

        private Base32() {
        }


        public static String encode(byte[] bytes) {
            int i = 0;
            int index = 0;

            int digit;
            StringBuilder base32;
            for (base32 = new StringBuilder((bytes.length + 7) * 8 / 5); i < bytes.length; base32.append(BASE32[digit])) {
                int currByte = bytes[i] >= 0 ? bytes[i] : bytes[i] + 256;
                if (index > 3) {
                    int nextByte;
                    if (i + 1 < bytes.length) {
                        nextByte = bytes[i + 1] >= 0 ? bytes[i + 1] : bytes[i + 1] + 256;
                    } else {
                        nextByte = 0;
                    }

                    digit = currByte & 255 >> index;
                    index = (index + 5) % 8;
                    digit <<= index;
                    digit |= nextByte >> 8 - index;
                    ++i;
                } else {
                    digit = currByte >> 8 - (index + 5) & 31;
                    index = (index + 5) % 8;
                    if (index == 0) {
                        ++i;
                    }
                }
            }

            return base32.toString();
        }

        static byte[] decode(String base32) {
            byte[] bytes = new byte[base32.length() * 5 / 8];
            int i = 0;
            int index = 0;
            int offset = 0;

            while (true) {
                label42:
                {
                    if (i < base32.length()) {
                        int lookup = base32.charAt(i) - 48;
                        if (lookup < 0 || lookup >= BASE32_LOOKUP.length) {
                            throw new IllegalArgumentException("Invalid char: " + base32.charAt(i));
                        }

                        int digit = BASE32_LOOKUP[lookup];
                        if (digit == 255) {
                            throw new IllegalArgumentException("Invalid char: " + base32.charAt(i));
                        }

                        if (index <= 3) {
                            index = (index + 5) % 8;
                            if (index != 0) {
                                bytes[offset] = (byte) (bytes[offset] | digit << 8 - index);
                                break label42;
                            }

                            bytes[offset] = (byte) (bytes[offset] | digit);
                            ++offset;
                            if (offset < bytes.length) {
                                break label42;
                            }
                        } else {
                            index = (index + 5) % 8;
                            bytes[offset] = (byte) (bytes[offset] | digit >>> index);
                            ++offset;
                            if (offset < bytes.length) {
                                bytes[offset] = (byte) (bytes[offset] | digit << 8 - index);
                                break label42;
                            }
                        }
                    }

                    return bytes;
                }

                ++i;
            }
        }

    }
}
