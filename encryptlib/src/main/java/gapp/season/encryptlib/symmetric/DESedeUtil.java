package gapp.season.encryptlib.symmetric;

import android.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 3DES/CBC加密算法工具类(使用24字节密钥+8字节向量)
 * (3DES算法安全性比DES高，比AES低，推荐使用AES加密)
 */
public class DESedeUtil {
    public static final String KEY_GENERATOR_DESEDE = "DESede";
    public static final String DESEDE_ALGORITHM_CBC = "DESede/CBC/PKCS5Padding";

    private static String sKey; //应用初始化时设置的默认密钥
    private static String sIv; //应用初始化时设置的默认向量

    /**
     * 应用初始化时可以设置一个默认密钥
     *
     * @param key 192位长度(24个字节)的密钥经过base64编码的字符串
     */
    public static void setDefaultKey(String key) {
        sKey = key;
    }

    /**
     * 应用初始化时可以设置一个默认GCM向量
     *
     * @param iv 8个字节的向量经过base64编码的字符串
     */
    public static void setDefaultIv(String iv) {
        sIv = iv;
    }

    /**
     * 获取默认密钥
     */
    private static byte[] getKeyBytes() {
        return Base64.decode(sKey, Base64.DEFAULT);
    }

    /**
     * 获取默认向量
     */
    private static byte[] getIvBytes() {
        return Base64.decode(sIv, Base64.DEFAULT);
    }

    public static String encrypt(String data) throws Exception {
        return Base64.encodeToString(encrypt(data.getBytes(), getKeyBytes(), getIvBytes()), Base64.DEFAULT).trim();
    }

    public static String decrypt(String data) throws Exception {
        byte[] bs = Base64.decode(data, Base64.DEFAULT);
        return new String(decrypt(bs, getKeyBytes(), getIvBytes()));
    }

    /**
     * 使用3DES/CBC方式加密数据
     *
     * @param data 源数据
     * @param key  密钥(24字节)
     * @param iv   向量(salt值，8字节)
     * @return 加密后的数据
     */
    public static byte[] encrypt(byte[] data, byte[] key, byte[] iv) throws Exception {
        Cipher encrypt = Cipher.getInstance(DESEDE_ALGORITHM_CBC);
        SecretKeySpec keySpec = new SecretKeySpec(key, KEY_GENERATOR_DESEDE);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        encrypt.init(Cipher.ENCRYPT_MODE, keySpec, ivParam);
        return encrypt.doFinal(data);
    }

    /**
     * 使用3DES/CBC方式解密数据
     *
     * @param data 源数据
     * @param key  密钥(24字节)
     * @param iv   向量(salt值，8字节)
     * @return 解密后的数据
     */
    public static byte[] decrypt(byte[] data, byte[] key, byte[] iv) throws Exception {
        Cipher encrypt = Cipher.getInstance(DESEDE_ALGORITHM_CBC);
        SecretKeySpec keySpec = new SecretKeySpec(key, KEY_GENERATOR_DESEDE);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        encrypt.init(Cipher.DECRYPT_MODE, keySpec, ivParam);
        return encrypt.doFinal(data);
    }
}
