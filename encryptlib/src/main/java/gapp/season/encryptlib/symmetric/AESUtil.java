package gapp.season.encryptlib.symmetric;

import android.annotation.TargetApi;
import android.os.Build;
import android.support.annotation.RequiresApi;
import android.util.Base64;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES加密算法
 * (使用128位长度的密钥，api-21及以上推荐使用CBC或GCM方式加密)
 */
public class AESUtil {
    public static final String KEY_GENERATOR_AES = "AES";
    //API-8+   模式：CBC/CFB/CTR/CTS/ECB/OFB   Padding：ISO10126Padding/NoPadding/PKCS5Padding
    public static final String AES_ALGORITHM_ECB = "AES/ECB/PKCS5Padding"; //ECB-PKCS5是比较常用的模式，对低版本兼容性较好
    //API-21+ (最低支持到5.0)  模式：GCM   Padding：NoPadding
    public static final String AES_ALGORITHM_GCM = "AES/GCM/NoPadding"; //GCM可以提供对消息的加密和完整性校验
    //API-8+   模式：CBC   Padding：PKCS5Padding
    public static final String AES_ALGORITHM_CBC = "AES/CBC/PKCS5Padding"; //密码分组链接模式 Cipher Block Chaining

    private static String sKey; //应用初始化时设置的默认密钥
    private static String sGcmIv; //应用初始化时设置的默认GCM向量
    private static String sCbcIv; //应用初始化时设置的默认CBC向量

    /**
     * 应用初始化时可以设置一个默认密钥
     *
     * @param key 128位长度(16个字节)的密钥经过base64编码的字符串
     */
    public static void setDefaultKey(String key) {
        sKey = key;
    }

    /**
     * 应用初始化时可以设置一个默认GCM向量
     *
     * @param iv GCM向量经过base64编码的字符串 (向量不限位数，通常使用12或16个字节长度)
     */
    public static void setDefaultGCMIv(String iv) {
        sGcmIv = iv;
    }

    /**
     * 应用初始化时可以设置一个默认CBC向量
     *
     * @param iv CBC向量经过base64编码的字符串 (向量需使用16个字节长度)
     */
    public static void setDefaultCBCIv(String iv) {
        sCbcIv = iv;
    }

    /**
     * 获取默认密钥的16位字节数组
     */
    public static byte[] getKeyBytes() {
        return Base64.decode(sKey, Base64.DEFAULT);
    }

    /**
     * 获取默认GCM向量 (已废弃，请使用getGCMIvBytes)
     *
     * @deprecated Use {@link #getGCMIvBytes()} instead.
     */
    @Deprecated
    public static byte[] getIvBytes() {
        return Base64.decode(sGcmIv, Base64.DEFAULT);
    }

    /**
     * 获取默认GCM向量
     */
    public static byte[] getGCMIvBytes() {
        return Base64.decode(sGcmIv, Base64.DEFAULT);
    }

    /**
     * 获取默认CBC向量
     */
    public static byte[] getCBCIvBytes() {
        return Base64.decode(sCbcIv, Base64.DEFAULT);
    }

    /**
     * AES-ECB加密，Base64编码(使用默认密钥)
     */
    public static String encrypt(String data) {
        try {
            if (data != null) {
                byte[] bs = encrypt(data.getBytes());
                return Base64.encodeToString(bs, Base64.DEFAULT).trim();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * AES-ECB加密(使用默认密钥)
     */
    public static byte[] encrypt(byte[] data) throws Exception {
        return encrypt(data, getKeyBytes(), null, AES_ALGORITHM_ECB);
    }

    /**
     * AES加密
     */
    public static byte[] encrypt(byte[] data, byte[] keyBytes, AlgorithmParameterSpec params, String algorithm) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        SecretKeySpec key = new SecretKeySpec(keyBytes, KEY_GENERATOR_AES);
        Cipher cipher = Cipher.getInstance(algorithm);
        if (params == null) {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, key, params);
        }
        return cipher.doFinal(data);
    }

    /**
     * AES-ECB解密，Base64编码(使用默认密钥)
     */
    public static String decrypt(String data) {
        try {
            if (data != null) {
                byte[] bs = Base64.decode(data, Base64.DEFAULT);
                return new String(decrypt(bs));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * AES-ECB解密(使用默认密钥)
     */
    public static byte[] decrypt(byte[] data) throws Exception {
        return decrypt(data, getKeyBytes(), null, AES_ALGORITHM_ECB);
    }

    /**
     * AES解密
     */
    public static byte[] decrypt(byte[] data, byte[] keyBytes, AlgorithmParameterSpec params, String algorithm) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        SecretKeySpec key = new SecretKeySpec(keyBytes, KEY_GENERATOR_AES);
        Cipher cipher = Cipher.getInstance(algorithm);
        if (params == null) {
            cipher.init(Cipher.DECRYPT_MODE, key);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key, params);
        }
        return cipher.doFinal(data);
    }

    /**
     * AES-GCM加密，Base64编码(使用默认密钥和默认向量)
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public static String encryptGCM(String data) {
        try {
            if (data != null) {
                byte[] bs = encryptGCM(data.getBytes(), getKeyBytes(), getGCMIvBytes());
                return Base64.encodeToString(bs, Base64.DEFAULT).trim();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * AES-GCM加密
     *
     * @param aesIv 向量(向量不限位数，通常使用12或16个字节长度)
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public static byte[] encryptGCM(byte[] data, byte[] keyBytes, byte[] aesIv) throws Exception {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.KITKAT) {
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, aesIv);
            return encrypt(data, keyBytes, parameterSpec, AES_ALGORITHM_GCM);
        } else {
            throw new RuntimeException("Android API 小于19，无法使用AES-GCM方式加解密算法");
        }
    }

    /**
     * AES-GCM解密，Base64编码(使用默认密钥和默认向量)
     */
    @TargetApi(Build.VERSION_CODES.KITKAT)
    public static String decryptGCM(String data) {
        try {
            if (data != null) {
                byte[] bs = Base64.decode(data, Base64.DEFAULT);
                return new String(decryptGCM(bs, getKeyBytes(), getGCMIvBytes()));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * AES-GCM解密
     *
     * @param aesIv 向量(向量不限位数，通常使用12或16个字节长度)
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public static byte[] decryptGCM(byte[] data, byte[] keyBytes, byte[] aesIv) throws Exception {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.KITKAT) {
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, aesIv);
            return decrypt(data, keyBytes, parameterSpec, AES_ALGORITHM_GCM);
        } else {
            throw new RuntimeException("Android API 小于19，无法使用AES-GCM方式加解密算法");
        }
    }

    /**
     * AES-CBC加密，Base64编码(使用默认密钥和默认向量)
     */
    public static String encryptCBC(String data) {
        try {
            if (data != null) {
                byte[] bs = encryptCBC(data.getBytes(), getKeyBytes(), getCBCIvBytes());
                return Base64.encodeToString(bs, Base64.DEFAULT).trim();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * AES-CBC加密 (aesIv可以使用16字节长度)
     */
    public static byte[] encryptCBC(byte[] data, byte[] keyBytes, byte[] aesIv) throws Exception {
        IvParameterSpec parameterSpec = new IvParameterSpec(aesIv);
        return encrypt(data, keyBytes, parameterSpec, AES_ALGORITHM_CBC);
    }

    /**
     * AES-CBC解密，Base64编码(使用默认密钥和默认向量)
     */
    public static String decryptCBC(String data) {
        try {
            if (data != null) {
                byte[] bs = Base64.decode(data, Base64.DEFAULT);
                return new String(decryptCBC(bs, getKeyBytes(), getCBCIvBytes()));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * AES-CBC解密 (aesIv可以使用16字节长度)
     */
    public static byte[] decryptCBC(byte[] data, byte[] keyBytes, byte[] aesIv) throws Exception {
        IvParameterSpec parameterSpec = new IvParameterSpec(aesIv);
        return decrypt(data, keyBytes, parameterSpec, AES_ALGORITHM_CBC);
    }
}
