package gapp.season.encryptlib;

import android.text.TextUtils;
import android.util.Base64;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import gapp.season.encryptlib.asymmetric.RSAUtil;
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
            KeyPair keyPair = generateRSAKeyPair(1024);
            if (keyPair != null) {
                String publicKey = getPublicKeyStr(keyPair);
                String privateKey = getPrivateKeyStr(keyPair);
                sb.append("publicKey:").append(publicKey).append(";\n");
                sb.append("privateKey:").append(privateKey).append(";\n");
                //sb.append(printPublicKeyInfo(getPublicKey(publicKey)));
                //sb.append(printPrivateKeyInfo(getPrivateKey(privateKey)));
            }
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
        return Base64.encodeToString(generateKey(keysize, new byte[0], algorithm), Base64.DEFAULT).trim();
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

    /**
     * 随机生成RSA密钥对
     *
     * @param keyLength 密钥长度，范围：512～2048位(一般1024，java原包支持到1024位)
     */
    public static KeyPair generateRSAKeyPair(int keyLength) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSAUtil.KEY_GENERATOR_RSA);
            kpg.initialize(keyLength);
            return kpg.genKeyPair(); //kpg.generateKeyPair()
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 从RSA密钥对象中获取公钥字符串(base64编码)
     */
    public static String getPublicKeyStr(KeyPair keyPair) {
        PublicKey publicKey = keyPair.getPublic();
        byte[] encoded = publicKey.getEncoded();
        return Base64.encodeToString(encoded, Base64.DEFAULT).trim();
    }

    /**
     * 从字符串中加载公钥
     *
     * @param publicKeyStr 公钥数据字符串(base64编码)
     */
    public static RSAPublicKey getPublicKey(String publicKeyStr) throws Exception {
        return getPublicKey(Base64.decode(publicKeyStr, Base64.DEFAULT));
    }

    public static RSAPublicKey getPublicKey(byte[] publicKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(RSAUtil.KEY_GENERATOR_RSA);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

    /**
     * 从RSA密钥对象中获取私钥字符串(base64编码)
     * (密钥长度大于1024字节时privateKey.getEncoded方法不能用)
     */
    public static String getPrivateKeyStr(KeyPair keyPair) {
        PrivateKey privateKey = keyPair.getPrivate();
        byte[] encoded = privateKey.getEncoded();
        return Base64.encodeToString(encoded, Base64.DEFAULT).trim();
    }

    /**
     * 从字符串中加载私钥
     *
     * @param privateKeyStr 私钥数据字符串(base64编码)
     */
    public static RSAPrivateKey getPrivateKey(String privateKeyStr) throws Exception {
        return getPrivateKey(Base64.decode(privateKeyStr, Base64.DEFAULT));
    }

    public static RSAPrivateKey getPrivateKey(byte[] privateKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(RSAUtil.KEY_GENERATOR_RSA);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey); //PKCS#8编码的Key指令
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }

    /**
     * 使用N、e值还原公钥
     *
     * @param modulus        模数
     * @param publicExponent 指数
     */
    public static PublicKey getPublicKey(String modulus, String publicExponent) throws NoSuchAlgorithmException, InvalidKeySpecException {
        BigInteger bigIntModulus = new BigInteger(modulus);
        BigInteger bigIntPrivateExponent = new BigInteger(publicExponent);
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(bigIntModulus, bigIntPrivateExponent);
        KeyFactory keyFactory = KeyFactory.getInstance(RSAUtil.KEY_GENERATOR_RSA);
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * 使用N、e值还原私钥
     *
     * @param modulus         模数
     * @param privateExponent 指数
     */
    public static PrivateKey getPrivateKey(String modulus, String privateExponent) throws NoSuchAlgorithmException, InvalidKeySpecException {
        BigInteger bigIntModulus = new BigInteger(modulus);
        BigInteger bigIntPrivateExponent = new BigInteger(privateExponent);
        RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(bigIntModulus, bigIntPrivateExponent);
        KeyFactory keyFactory = KeyFactory.getInstance(RSAUtil.KEY_GENERATOR_RSA);
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * 打印公钥信息
     */
    public static String printPublicKeyInfo(PublicKey publicKey) {
        RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
        return "----------RSAPublicKey----------\n" +
                "Modulus.length=" + rsaPublicKey.getModulus().bitLength() + "\n" +
                "Modulus=" + rsaPublicKey.getModulus().toString() + "\n" +
                "PublicExponent.length=" + rsaPublicKey.getPublicExponent().bitLength() + "\n" +
                "PublicExponent=" + rsaPublicKey.getPublicExponent().toString() + "\n";
    }

    /**
     * 打印私钥信息
     */
    public static String printPrivateKeyInfo(PrivateKey privateKey) {
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;
        return "----------RSAPrivateKey ----------\n" +
                "Modulus.length=" + rsaPrivateKey.getModulus().bitLength() + "\n" +
                "Modulus=" + rsaPrivateKey.getModulus().toString() + "\n" +
                "PrivateExponent.length=" + rsaPrivateKey.getPrivateExponent().bitLength() + "\n" +
                "PrivatecExponent=" + rsaPrivateKey.getPrivateExponent().toString() + "\n";
    }
}
