package gapp.season.encryptlib.builder;

import android.os.Build;
import android.text.TextUtils;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public abstract class SymmetricBuilder extends CipherBuilder<SymmetricBuilder> {
    //常用的算法Mode
    public static final String MODE_ECB = "ECB";
    public static final String MODE_CBC = "CBC";
    public static final String MODE_GCM = "GCM";
    //常用的算法Padding
    public static final String PADDING_NONE = "NoPadding";
    public static final String PADDING_PKCS5 = "PKCS5Padding";

    protected SymmetricBuilder(String algorithmType) {
        this.algorithmType = algorithmType;
        mode = MODE_CBC;
        padding = PADDING_PKCS5;
    }

    @Override
    public byte[] doFinal() {
        try {
            String algorithm = algorithmType + "/" + mode + "/" + padding;
            AlgorithmParameterSpec params = null;
            if (MODE_GCM.equals(mode)) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
                    params = new GCMParameterSpec(128, ivBytes);
                }
            } else if (!TextUtils.isEmpty(mode)) {
                params = new IvParameterSpec(ivBytes);
            }
            if (isEncrypt) {
                return encrypt(data, keyBytes, params, algorithm);
            } else {
                return decrypt(data, keyBytes, params, algorithm);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    protected abstract byte[] encrypt(byte[] data, byte[] keyBytes, AlgorithmParameterSpec params, String algorithm) throws Exception;

    protected abstract byte[] decrypt(byte[] data, byte[] keyBytes, AlgorithmParameterSpec params, String algorithm) throws Exception;
}
