package gapp.season.encryptlib.asymmetric;

import android.util.Base64;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import gapp.season.encryptlib.SecretKeyGenerator;

/**
 * RSA工具类(密钥长度1024)，签名+加解密(支持长字符串分段加解密)，一般服务端保存私钥，客户端保存公钥
 * 【公钥加密、私钥解密】或【私钥加密、公钥解密】
 * 【私钥签名、公钥验签】
 */
public class RSAUtil {
    public static final String KEY_GENERATOR_RSA = "RSA";
    //android中默认填充方式是RSA/ECB/NoPadding，一般使用的填充方式是RSA/ECB/PKCS1Padding
    public static final String RSA_ALGORITHM_NO = "RSA/NONE/NoPadding"; //最大加密长度127，分段时解密会出现乱码
    public static final String RSA_ALGORITHM_PKCS1 = "RSA/NONE/PKCS1Padding"; //分段长度117(128-11)
    public static final String RSA_ALGORITHM_OAEP = "RSA/NONE/OAEPPadding"; //分段长度86(128-40-2) [不能用于私钥加密公钥解密]
    public static final String RSA_ALGORITHM_OAEP_SHA1 = "RSA/NONE/OAEPwithSHA-1andMGF1Padding"; //分段长度86(128-40-2) [不能用于私钥加密公钥解密]
    public static final String RSA_ALGORITHM_OAEP_SHA256 = "RSA/NONE/OAEPwithSHA-256andMGF1Padding"; //分段长度62(128-64-2) [不能用于私钥加密公钥解密]
    public static final String RSA_ALGORITHM_ECB_NO = "RSA/ECB/NoPadding"; //最大加密长度127，分段时解密会出现乱码
    public static final String RSA_ALGORITHM_ECB_PKCS1 = "RSA/ECB/PKCS1Padding"; //分段长度117(128-11)
    public static final String RSA_ALGORITHM_ECB_OAEP = "RSA/ECB/OAEPPadding"; //分段长度86(128-40-2) [不能用于私钥加密公钥解密]
    public static final String RSA_ALGORITHM_ECB_OAEP_SHA1 = "RSA/ECB/OAEPwithSHA-1andMGF1Padding"; //分段长度86(128-40-2) [不能用于私钥加密公钥解密]
    public static final String RSA_ALGORITHM_ECB_OAEP_SHA256 = "RSA/ECB/OAEPwithSHA-256andMGF1Padding"; //分段长度62(128-64-2) [不能用于私钥加密公钥解密]
    private static final String RSA_ALGORITHM = RSA_ALGORITHM_ECB_PKCS1;
    //签名、验签算法方式
    public static final String SIGNATURE_ALGORITHM_NONE = "NONEwithRSA";
    public static final String SIGNATURE_ALGORITHM_MD5 = "MD5withRSA";
    public static final String SIGNATURE_ALGORITHM_SHA1 = "SHA1WithRSA";
    public static final String SIGNATURE_ALGORITHM_SHA256 = "SHA256withRSA";
    public static final String SIGNATURE_ALGORITHM_SHA512 = "SHA512withRSA";
    private static final String SIGNATURE_ALGORITHM = SIGNATURE_ALGORITHM_MD5;

    // RSA分段加密明文字节大小
    private static final int MAX_ENCRYPT_BLOCK = 117;
    // RSA分段解密密文字节大小
    private static final int MAX_DECRYPT_BLOCK = 128;

    // 默认密钥
    private static String sPublicKey;
    private static String sPrivateKey;
    private static String sPSource;

    public static void setPublicKey(String publicKey) {
        sPublicKey = publicKey;
    }

    public static void setPrivateKey(String privateKey) {
        sPrivateKey = privateKey;
    }

    public static void setPSource(String PSource) {
        sPSource = PSource;
    }

    private static byte[] getPSource() {
        if (sPSource == null) {
            return null;
        } else {
            return Base64.decode(sPSource, Base64.DEFAULT);
        }
    }

    public static int getMaxEncryptBlock(String algorithm) {
        if (RSA_ALGORITHM_NO.equals(algorithm) || RSA_ALGORITHM_ECB_NO.equals(algorithm)) {
            return 127;
        } else if (RSA_ALGORITHM_PKCS1.equals(algorithm) || RSA_ALGORITHM_ECB_PKCS1.equals(algorithm)) {
            return 117;
        } else if (RSA_ALGORITHM_OAEP.equals(algorithm) || RSA_ALGORITHM_ECB_OAEP.equals(algorithm)) {
            return 86;
        } else if (RSA_ALGORITHM_OAEP_SHA1.equals(algorithm) || RSA_ALGORITHM_ECB_OAEP_SHA1.equals(algorithm)) {
            return 86;
        } else if (RSA_ALGORITHM_OAEP_SHA256.equals(algorithm) || RSA_ALGORITHM_ECB_OAEP_SHA256.equals(algorithm)) {
            return 62;
        } else {
            return 128;
        }
    }

    public static OAEPParameterSpec getOAEPParameterSpec(String algorithm, byte[] pSrc) {
        if (RSA_ALGORITHM_OAEP.equals(algorithm) || RSA_ALGORITHM_ECB_OAEP.equals(algorithm) ||
                RSA_ALGORITHM_OAEP_SHA1.equals(algorithm) || RSA_ALGORITHM_ECB_OAEP_SHA1.equals(algorithm)) {
            return new OAEPParameterSpec("SHA-1", "MGF1",
                    MGF1ParameterSpec.SHA1, new PSource.PSpecified(pSrc));
        } else if (RSA_ALGORITHM_OAEP_SHA256.equals(algorithm) || RSA_ALGORITHM_ECB_OAEP_SHA256.equals(algorithm)) {
            return new OAEPParameterSpec("SHA-256", "MGF1",
                    MGF1ParameterSpec.SHA256, new PSource.PSpecified(pSrc));
        } else {
            return null;
        }
    }

    /**
     * 用默认公钥加密数据
     */
    public static String encryptByPublicKey(String data) throws Exception {
        return Base64.encodeToString(encryptByPublicKey(data.getBytes(), SecretKeyGenerator.getPublicKey(
                sPublicKey), null, RSA_ALGORITHM, MAX_ENCRYPT_BLOCK), Base64.DEFAULT).trim();
    }

    /**
     * 用默认公钥加密数据
     */
    public static String encryptByPublicKey(String data, String algorithm) throws Exception {
        return Base64.encodeToString(encryptByPublicKey(data.getBytes(), SecretKeyGenerator.getPublicKey(sPublicKey),
                getOAEPParameterSpec(algorithm, getPSource()), algorithm, -1), Base64.DEFAULT).trim();
    }

    /**
     * 用公钥加密
     *
     * @param maxEncryptBlock 加密分段长度，传<=0则使用默认分段长度
     */
    public static byte[] encryptByPublicKey(byte[] data, PublicKey key, AlgorithmParameterSpec params,
                                            String algorithm, int maxEncryptBlock) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm);
        if (params == null) {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, key, params);
        }
        if (maxEncryptBlock <= 0) {
            maxEncryptBlock = getMaxEncryptBlock(algorithm);
        }
        return encrypt(data, maxEncryptBlock, cipher);
    }

    /**
     * 用默认私钥加密数据
     */
    public static String encryptByPrivateKey(String data) throws Exception {
        return Base64.encodeToString(encryptByPrivateKey(data.getBytes(), SecretKeyGenerator.getPrivateKey(
                sPrivateKey), null, RSA_ALGORITHM, MAX_ENCRYPT_BLOCK), Base64.DEFAULT).trim();
    }

    /**
     * 用默认私钥加密数据
     */
    public static String encryptByPrivateKey(String data, String algorithm) throws Exception {
        return Base64.encodeToString(encryptByPrivateKey(data.getBytes(), SecretKeyGenerator.getPrivateKey(sPrivateKey),
                getOAEPParameterSpec(algorithm, getPSource()), algorithm, -1), Base64.DEFAULT).trim();
    }

    /**
     * 用私钥加密
     *
     * @param maxEncryptBlock 加密分段长度，传<=0则使用默认分段长度
     */
    public static byte[] encryptByPrivateKey(byte[] data, PrivateKey key, AlgorithmParameterSpec params,
                                             String algorithm, int maxEncryptBlock) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm);
        if (params == null) {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, key, params);
        }
        if (maxEncryptBlock <= 0) {
            maxEncryptBlock = getMaxEncryptBlock(algorithm);
        }
        return encrypt(data, maxEncryptBlock, cipher);
    }

    /**
     * 分段加密数据
     *
     * @param maxEncryptBlock 加密分段长度
     */
    private static byte[] encrypt(byte[] data, int maxEncryptBlock, Cipher cipher) throws BadPaddingException, IllegalBlockSizeException, IOException {
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > maxEncryptBlock) {
                cache = cipher.doFinal(data, offSet, maxEncryptBlock);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * maxEncryptBlock;
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
                SecretKeyGenerator.getPublicKey(sPublicKey), null, RSA_ALGORITHM));
    }

    /**
     * 用默认公钥解密数据
     */
    public static String decryptByPublicKey(String data, String algorithm) throws Exception {
        return new String(decryptByPublicKey(Base64.decode(data, Base64.DEFAULT), SecretKeyGenerator.getPublicKey(sPublicKey),
                getOAEPParameterSpec(algorithm, getPSource()), algorithm));
    }

    /**
     * 用公钥解密
     */
    public static byte[] decryptByPublicKey(byte[] data, PublicKey key,
                                            AlgorithmParameterSpec params, String algorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm);
        if (params == null) {
            cipher.init(Cipher.DECRYPT_MODE, key);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key, params);
        }
        return decrypt(data, cipher);
    }

    /**
     * 用默认私钥解密数据
     */
    public static String decryptByPrivateKey(String data) throws Exception {
        return new String(decryptByPrivateKey(Base64.decode(data, Base64.DEFAULT),
                SecretKeyGenerator.getPrivateKey(sPrivateKey), null, RSA_ALGORITHM));
    }

    /**
     * 用默认私钥解密数据
     */
    public static String decryptByPrivateKey(String data, String algorithm) throws Exception {
        return new String(decryptByPrivateKey(Base64.decode(data, Base64.DEFAULT), SecretKeyGenerator.getPrivateKey(sPrivateKey),
                getOAEPParameterSpec(algorithm, getPSource()), algorithm));
    }

    /**
     * 用私钥解密
     */
    public static byte[] decryptByPrivateKey(byte[] data, PrivateKey key,
                                             AlgorithmParameterSpec params, String algorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm);
        if (params == null) {
            cipher.init(Cipher.DECRYPT_MODE, key);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key, params);
        }
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
