package gapp.season.encryptlib.builder;

import java.security.spec.AlgorithmParameterSpec;

import gapp.season.encryptlib.symmetric.DESUtil;

/**
 * 默认算法： "DES/CBC/PKCS5Padding"
 */
public class DESBuilder extends SymmetricBuilder {
    public DESBuilder() {
        super("DES");
    }

    @Override
    protected byte[] encrypt(byte[] data, byte[] keyBytes, AlgorithmParameterSpec params, String algorithm) throws Exception {
        return DESUtil.encrypt(data, keyBytes, params, algorithm);
    }

    @Override
    protected byte[] decrypt(byte[] data, byte[] keyBytes, AlgorithmParameterSpec params, String algorithm) throws Exception {
        return DESUtil.decrypt(data, keyBytes, params, algorithm);
    }
}
