package gapp.season.encryptlib.builder;

import android.support.annotation.NonNull;
import android.util.Base64;

import gapp.season.encryptlib.code.HexUtil;

public abstract class CipherBuilder<T extends CipherBuilder> {
    protected String algorithmType; //在子类初始化

    protected boolean isEncrypt = true;
    protected String mode;
    protected String padding;
    protected byte[] keyBytes;
    protected byte[] ivBytes;
    protected byte[] data;

    //设置加密/解密

    public void setEncrypt(boolean encrypt) {
        isEncrypt = encrypt;
    }

    public T toEncrypt() {
        isEncrypt = true;
        return (T) this;
    }

    public T toDecrypt() {
        isEncrypt = false;
        return (T) this;
    }


    //设置算法

    public T setMode(String mode) {
        this.mode = mode;
        return (T) this;
    }

    public T setPadding(String padding) {
        this.padding = padding;
        return (T) this;
    }


    //设置密钥和向量

    public T setKeyBytes(byte[] keyBytes) {
        this.keyBytes = keyBytes;
        return (T) this;
    }

    public T setHexKey(String key) {
        try {
            this.keyBytes = HexUtil.decodeHexStr(key);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return (T) this;
    }

    public T setBase64Key(String key) {
        try {
            this.keyBytes = Base64.decode(key, Base64.DEFAULT);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return (T) this;
    }

    public T setIvBytes(byte[] ivBytes) {
        this.ivBytes = ivBytes;
        return (T) this;
    }

    public T setHexIv(String iv) {
        try {
            this.ivBytes = HexUtil.decodeHexStr(iv);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return (T) this;
    }

    public T setBase64Iv(String iv) {
        try {
            this.ivBytes = Base64.decode(iv, Base64.DEFAULT);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return (T) this;
    }


    //设置要计算的数据

    public T setData(byte[] data) {
        this.data = data;
        return (T) this;
    }

    public T setData(String dataStr, String charsetName) {
        try {
            charsetName = (charsetName == null) ? "UTF-8" : charsetName;
            this.data = dataStr.getBytes(charsetName);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return (T) this;
    }

    public T setHexData(String dataStr) {
        try {
            this.data = HexUtil.decodeHexStr(dataStr);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return (T) this;
    }

    public T setBase64Data(String dataStr) {
        try {
            this.data = Base64.decode(dataStr, Base64.DEFAULT);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return (T) this;
    }


    //获取计算结果

    public abstract byte[] doFinal();

    public String doFinalStr(String charsetName) {
        try {
            byte[] data = doFinal();
            if (data != null) {
                charsetName = (charsetName == null) ? "UTF-8" : charsetName;
                return new String(data, charsetName);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public String doFinalHexStr() {
        try {
            byte[] data = doFinal();
            if (data != null) {
                return HexUtil.toHexStr(data);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public String doFinalBase64Str() {
        try {
            byte[] data = doFinal();
            if (data != null) {
                return Base64.encodeToString(data, Base64.DEFAULT).trim();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    @NonNull
    @Override
    public String toString() {
        String algorithm = algorithmType + "/" + mode + "/" + padding;
        return "algorithm:" + algorithm + "\n"
                + "isEncrypt:" + isEncrypt + "\n"
                + "KeyBytes:" + ((keyBytes != null) ? keyBytes.length : -1) + "\n"
                + "IvBytes:" + ((ivBytes != null) ? ivBytes.length : -1) + "\n"
                + "Data:" + ((data != null) ? data.length : -1);
    }
}
