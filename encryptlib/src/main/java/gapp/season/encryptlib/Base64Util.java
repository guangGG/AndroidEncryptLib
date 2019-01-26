package gapp.season.encryptlib;

import android.util.Base64;

/**
 * Base64工具类
 */
public class Base64Util {
    public static byte[] encode(byte[] data) {
        return Base64.encode(data, Base64.DEFAULT);
    }

    public static byte[] decode(byte[] base64Data) {
        return Base64.decode(base64Data, Base64.DEFAULT);
    }

    public static String encode(String data) {
        return Base64.encodeToString(data.getBytes(), Base64.DEFAULT);
    }

    public static String decode(String base64Data) {
        return new String(Base64.decode(base64Data, Base64.DEFAULT));
    }

    public static String encodeToString(byte[] data) {
        return Base64.encodeToString(data, Base64.DEFAULT);
    }

    public static byte[] decodeString(String base64Data) {
        return Base64.decode(base64Data, Base64.DEFAULT);
    }
}
