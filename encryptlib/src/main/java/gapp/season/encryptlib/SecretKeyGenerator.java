package gapp.season.encryptlib;

import android.text.TextUtils;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import gapp.season.encryptlib.code.Base64Util;
import gapp.season.encryptlib.hash.HashUtil;
import gapp.season.encryptlib.symmetric.AESUtil;

public class SecretKeyGenerator {
    /**
     * 随机生成一组密钥
     */
    public static String randomGenerateKeys() {
        StringBuilder sb = new StringBuilder();
        try {
            sb.append("randomGenerateKeys: [\n");
            String aesKey = generateKey(AESUtil.KEY_GENERATOR_AES);
            sb.append("aesKey:").append(aesKey).append(";\n");
            String aesGCMIv = generateKey(AESUtil.KEY_GENERATOR_AES);
            sb.append("aesGCMIv:").append(aesGCMIv).append(";\n");
            sb.append("]");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return sb.toString().trim();
    }

    /**
     * 根据口令字符串生成16位字节数组的密钥
     *
     * @param word 口令字符串
     */
    public static byte[] generateKeyByWord(String word) {
        if (TextUtils.isEmpty(word)) {
            return HashUtil.encode("".getBytes(), HashUtil.ALGORITHM_MD5);
        }
        return HashUtil.encode(word.getBytes(), HashUtil.ALGORITHM_MD5);
    }

    /**
     * 随机生成密钥串(128位密钥对应的base64字符串)
     *
     * @param algorithm 密钥算法，传空默认使用AES算法
     */
    public static String generateKey(String algorithm) throws NoSuchAlgorithmException {
        if (TextUtils.isEmpty(algorithm)) {
            algorithm = AESUtil.KEY_GENERATOR_AES;
        }
        return Base64Util.encodeToString(generateKey(new byte[0], algorithm)).trim();
    }

    /**
     * 从seed获取128位的随机密钥(同一个seed多次生成的密钥各不相同)
     * AES共有128、192、256位三种长度的密钥(java原包只支持128位)
     */
    private static byte[] generateKey(byte[] seed, String algorithm) throws NoSuchAlgorithmException {
        KeyGenerator kgen = KeyGenerator.getInstance(algorithm);
        kgen.init(128, new SecureRandom(seed));
        SecretKey secretKey = kgen.generateKey();
        return secretKey.getEncoded();
    }
}
