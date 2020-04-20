package gapp.season.encryptlib.builder;

import java.security.spec.AlgorithmParameterSpec;

import gapp.season.encryptlib.symmetric.AESUtil;

/**
 * 默认算法： "AES/CBC/PKCS5Padding"
 */
public class AESBuilder extends SymmetricBuilder {
    public AESBuilder() {
        super("AES");
    }

    @Override
    protected byte[] encrypt(byte[] data, byte[] keyBytes, AlgorithmParameterSpec params, String algorithm) throws Exception {
        return AESUtil.encrypt(data, keyBytes, params, algorithm);
    }

    @Override
    protected byte[] decrypt(byte[] data, byte[] keyBytes, AlgorithmParameterSpec params, String algorithm) throws Exception {
        return AESUtil.decrypt(data, keyBytes, params, algorithm);
    }
}
