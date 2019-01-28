package gapp.season.encryptlib.hash;

import java.io.InputStream;
import java.security.MessageDigest;

import gapp.season.encryptlib.code.HexUtil;

public class HashUtil {
    public static final String DEFAULT_CHARSET = "UTF-8";

    public static final String ALGORITHM_MD5 = "MD5";
    public static final String ALGORITHM_SHA_1 = "SHA-1"; //"SHA1"、"SHA-1"、"SHA"
    public static final String ALGORITHM_SHA_256 = "SHA-256";
    public static final String ALGORITHM_SHA_512 = "SHA-512";

    public static byte[] encode(byte[] bts, String algorithm) {
        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance(algorithm);
            messageDigest.update(bts);
            return messageDigest.digest();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String encode(String str, String algorithm) {
        byte[] bs = null;
        try {
            bs = encode(str.getBytes(DEFAULT_CHARSET), algorithm);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return toHexStr(bs);
    }

    public static String encode(InputStream is, String algorithm) {
        byte[] digest = null;
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
            // 每次读取8k字节
            byte[] buffer = new byte[8192];
            int length;
            while ((length = is.read(buffer)) != -1) {
                messageDigest.update(buffer, 0, length);
            }
            is.close();
            digest = messageDigest.digest();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return toHexStr(digest);
    }

    public static String md5(String str) {
        return encode(str, ALGORITHM_MD5);
    }

    public static String sha1(String str) {
        return encode(str, ALGORITHM_SHA_1);
    }

    public static String sha256(String str) {
        return encode(str, ALGORITHM_SHA_256);
    }

    public static String sha512(String str) {
        return encode(str, ALGORITHM_SHA_512);
    }

    public static String md5sha512(String str) {
        return toHexStr(HashUtil.encode(HashUtil.encode(str.getBytes(), ALGORITHM_SHA_512), ALGORITHM_MD5));
    }

    /**
     * 字节数组转换为十六进制表示(MD5、SHA1等算法获得结果字符串)
     *
     * @param bytes 需要转换字节数组。
     * @return 字节数组的十六进制表示。
     */
    private static String toHexStr(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }

        return HexUtil.toHexStr(bytes);
    }
}
