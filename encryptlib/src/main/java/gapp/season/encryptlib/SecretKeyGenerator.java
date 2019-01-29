package gapp.season.encryptlib;

import android.text.TextUtils;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import gapp.season.encryptlib.code.Base64Util;
import gapp.season.encryptlib.hash.HashUtil;
import gapp.season.encryptlib.symmetric.AESUtil;
import gapp.season.encryptlib.symmetric.DESUtil;
import gapp.season.encryptlib.symmetric.DESedeUtil;

public class SecretKeyGenerator {
    /**
     * 随机生成一组密钥(用来打印显示)
     */
    public static String randomGenerateKeys() {
        StringBuilder sb = new StringBuilder();
        try {
            sb.append("randomGenerateKeys: [\n");
            String aesKey = generateKey(0, AESUtil.KEY_GENERATOR_AES);
            sb.append("aesKey:").append(aesKey).append(";\n");
            String aesGCMIv = generateKey(96, AESUtil.KEY_GENERATOR_AES);
            sb.append("aesGCMIv:").append(aesGCMIv).append(";\n");
            String desKey = generateKey(0, DESUtil.KEY_GENERATOR_DES);
            sb.append("desKey:").append(desKey).append(";\n");
            String desedeKey = generateKey(0, DESedeUtil.KEY_GENERATOR_DESEDE);
            sb.append("desedeKey:").append(desedeKey).append(";\n");
            String desIv = generateKey(64, DESUtil.KEY_GENERATOR_DES);
            sb.append("desIv:").append(desIv).append(";\n");
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
     * 随机生成密钥串(字节数组密钥对应的base64字符串)
     *
     * @param keysize   密钥长度(bit位)，传0时使用算法对应的默认长度
     * @param algorithm 密钥算法，传空默认使用AES算法
     */
    public static String generateKey(int keysize, String algorithm) throws NoSuchAlgorithmException {
        if (keysize <= 0) {
            keysize = 128; //默认16个字节(AES共有128、192、256位三种长度的密钥，java原包只支持128位)
            if (DESUtil.KEY_GENERATOR_DES.equalsIgnoreCase(algorithm)) {
                keysize = 64;
            } else if (DESedeUtil.KEY_GENERATOR_DESEDE.equalsIgnoreCase(algorithm)) {
                keysize = 192;
            }
        }
        if (TextUtils.isEmpty(algorithm)) {
            algorithm = AESUtil.KEY_GENERATOR_AES;
        }
        return Base64Util.encodeToString(generateKey(keysize, new byte[0], algorithm)).trim();
    }

    /**
     * 从seed获取随机密钥(同一个seed多次生成的密钥各不相同)
     */
    private static byte[] generateKey(int keysize, byte[] seed, String algorithm) throws NoSuchAlgorithmException {
        KeyGenerator kgen = KeyGenerator.getInstance(algorithm);
        kgen.init(keysize, new SecureRandom(seed));
        SecretKey secretKey = kgen.generateKey();
        return secretKey.getEncoded();
    }
}
