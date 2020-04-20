package gapp.season.encryptlib.builder;

import android.support.annotation.NonNull;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

import gapp.season.encryptlib.SecretKeyGenerator;
import gapp.season.encryptlib.asymmetric.RSAUtil;

/**
 * 默认算法： "RSA/ECB/PKCS1Padding"
 */
public class RSABuilder extends CipherBuilder<RSABuilder> {
    //常用的算法Mode
    public static final String MODE_NONE = "NONE";
    public static final String MODE_ECB = "ECB";
    //常用的算法Padding
    public static final String PADDING_NONE = "NoPadding";
    public static final String PADDING_PKCS1 = "PKCS1Padding";
    public static final String PADDING_OAEP = "OAEPPadding";

    private boolean usePublicKey = true;
    private byte[] pSrc; //PSource of OAEP Padding

    public RSABuilder() {
        algorithmType = "RSA";
        mode = MODE_ECB;
        padding = PADDING_PKCS1;
    }

    public RSABuilder usePublicKey(boolean usePublicKey) {
        this.usePublicKey = usePublicKey;
        return this;
    }

    public RSABuilder setPSrc(byte[] pSrc) {
        this.pSrc = pSrc;
        return this;
    }

    @Override
    public byte[] doFinal() {
        try {
            String algorithm = algorithmType + "/" + mode + "/" + padding;
            if (isEncrypt) {
                if (usePublicKey) {
                    PublicKey key = SecretKeyGenerator.getPublicKey(keyBytes);
                    AlgorithmParameterSpec params = RSAUtil.getOAEPParameterSpec(algorithm, pSrc);
                    return RSAUtil.encryptByPublicKey(data, key, params, algorithm, 0);
                } else {
                    PrivateKey key = SecretKeyGenerator.getPrivateKey(keyBytes);
                    AlgorithmParameterSpec params = RSAUtil.getOAEPParameterSpec(algorithm, pSrc);
                    return RSAUtil.encryptByPrivateKey(data, key, params, algorithm, 0);
                }
            } else {
                if (usePublicKey) {
                    PublicKey key = SecretKeyGenerator.getPublicKey(keyBytes);
                    AlgorithmParameterSpec params = RSAUtil.getOAEPParameterSpec(algorithm, pSrc);
                    return RSAUtil.decryptByPublicKey(data, key, params, algorithm);
                } else {
                    PrivateKey key = SecretKeyGenerator.getPrivateKey(keyBytes);
                    AlgorithmParameterSpec params = RSAUtil.getOAEPParameterSpec(algorithm, pSrc);
                    return RSAUtil.decryptByPrivateKey(data, key, params, algorithm);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    @NonNull
    @Override
    public String toString() {
        String str = super.toString();
        return str + "\n"
                + "PSource:" + ((pSrc != null) ? pSrc.length : -1) + "\n"
                + "usePublicKey:" + usePublicKey;
    }
}
