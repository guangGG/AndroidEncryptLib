package gapp.season.encryptlib.asymmetric;

import android.util.Base64;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import gapp.season.encryptlib.SecretKeyGenerator;

/**
 * RSA工具类，签名+加解密(支持长字符串分段加解密)，一般服务端保存私钥，客户端保存公钥
 * 【公钥加密、私钥解密】或【私钥加密、公钥解密】
 * 【私钥签名、公钥验签】
 */
public class RSAUtil {
    public static final String KEY_GENERATOR_RSA = "RSA";
    //android中默认填充方式是RSA/ECB/NoPadding，一般使用的填充方式是RSA/ECB/PKCS1Padding
    private static final String RSA_ALGORITHM = "RSA/ECB/PKCS1Padding";
    //签名、验签算法方式
    private static final String SIGNATURE_ALGORITHM = "MD5withRSA"; //SHA1WithRSA

    // RSA分段加密明文字节大小
    private static final int MAX_ENCRYPT_BLOCK = 117;
    // RSA分段解密密文字节大小
    private static final int MAX_DECRYPT_BLOCK = 128;

    // 默认密钥
    private static String sPublicKey;
    private static String sPrivateKey;

    public static void setPublicKey(String publicKey) {
        sPublicKey = publicKey;
    }

    public static void setPrivateKey(String privateKey) {
        sPrivateKey = privateKey;
    }

    /**
     * 用默认公钥加密数据
     */
    public static String encryptByPublicKey(String data) throws Exception {
        return Base64.encodeToString(encryptByPublicKey(data.getBytes(),
                SecretKeyGenerator.getPublicKey(sPublicKey), RSA_ALGORITHM), Base64.DEFAULT).trim();
    }

    /**
     * 用公钥加密
     */
    public static byte[] encryptByPublicKey(byte[] data, PublicKey key, String algorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return encrypt(data, cipher);
    }

    /**
     * 用默认私钥加密数据
     */
    public static String encryptByPrivateKey(String data) throws Exception {
        return Base64.encodeToString(encryptByPrivateKey(data.getBytes(),
                SecretKeyGenerator.getPrivateKey(sPrivateKey), RSA_ALGORITHM), Base64.DEFAULT).trim();
    }

    /**
     * 用私钥加密
     */
    public static byte[] encryptByPrivateKey(byte[] data, PrivateKey key, String algorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return encrypt(data, cipher);
    }

    /**
     * 分段加密数据
     */
    private static byte[] encrypt(byte[] data, Cipher cipher) throws BadPaddingException, IllegalBlockSizeException, IOException {
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return encryptedData;
    }

    /**
     * 用默认公钥解密数据
     */
    public static String decryptByPublicKey(String data) throws Exception {
        return new String(decryptByPublicKey(Base64.decode(data, Base64.DEFAULT),
                SecretKeyGenerator.getPublicKey(sPublicKey), RSA_ALGORITHM));
    }

    /**
     * 用公钥解密
     */
    public static byte[] decryptByPublicKey(byte[] data, PublicKey key, String algorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return decrypt(data, cipher);
    }

    /**
     * 用默认私钥解密数据
     */
    public static String decryptByPrivateKey(String data) throws Exception {
        return new String(decryptByPrivateKey(Base64.decode(data, Base64.DEFAULT),
                SecretKeyGenerator.getPrivateKey(sPrivateKey), RSA_ALGORITHM));
    }

    /**
     * 用私钥解密
     */
    public static byte[] decryptByPrivateKey(byte[] data, PrivateKey key, String algorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return decrypt(data, cipher);
    }

    /**
     * 分段解密数据
     */
    private static byte[] decrypt(byte[] data, Cipher cipher) throws BadPaddingException, IllegalBlockSizeException, IOException {
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }

    /**
     * 用默认私钥对信息生成签名
     */
    public static String sign(String data) throws Exception {
        return Base64.encodeToString(sign(data.getBytes(), SecretKeyGenerator.getPrivateKey(sPrivateKey),
                SIGNATURE_ALGORITHM), Base64.DEFAULT).trim();
    }

    /**
     * 用私钥对信息生成签名
     *
     * @param data       信息数据(通常使用hash值)
     * @param privateKey 私钥
     */
    public static byte[] sign(byte[] data, PrivateKey privateKey, String algorithm) throws Exception {
        Signature signature = Signature.getInstance(algorithm);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    /**
     * 用默认公钥校验签名
     */
    public static boolean verify(String data, String sign) throws Exception {
        return verify(data.getBytes(), Base64.decode(sign, Base64.DEFAULT),
                SecretKeyGenerator.getPublicKey(sPublicKey), SIGNATURE_ALGORITHM);
    }

    /**
     * 用公钥校验签名
     *
     * @param data      加密数据
     * @param sign      签名
     * @param publicKey 公钥
     */
    public static boolean verify(byte[] data, byte[] sign, PublicKey publicKey, String algorithm) throws Exception {
        Signature signature = Signature.getInstance(algorithm);
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(sign);
    }
}
