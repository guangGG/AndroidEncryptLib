package gapp.season.encryptlib.builder;

import java.security.spec.AlgorithmParameterSpec;

import gapp.season.encryptlib.symmetric.DESedeUtil;

/**
 * 默认算法： "DESede/CBC/PKCS5Padding"
 */
public class DESedeBuilder extends SymmetricBuilder {
    public DESedeBuilder() {
        super("DESede");
    }

    @Override
    protected byte[] encrypt(byte[] data, byte[] keyBytes, AlgorithmParameterSpec params, String algorithm) throws Exception {
        return DESedeUtil.encrypt(data, keyBytes, params, algorithm);
    }

    @Override
    protected byte[] decrypt(byte[] data, byte[] keyBytes, AlgorithmParameterSpec params, String algorithm) throws Exception {
        return DESedeUtil.decrypt(data, keyBytes, params, algorithm);
    }
}
