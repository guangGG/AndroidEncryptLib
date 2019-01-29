package gapp.season.encryptlib.code;

import android.text.TextUtils;
import android.util.Base64;

import java.io.UnsupportedEncodingException;

import gapp.season.encryptlib.ElUtil;

/**
 * Base64工具类
 */
public class Base64Util {
    private static final String CHARSET_ISO8859_1 = "iso8859-1";
    private static boolean sUseCustomFunction = true; //方法内部标记，标记使用自定义方法还是使用android工具包中的Base64

    public static byte[] encode(byte[] data) {
        try {
            return encodeToString(data).getBytes(CHARSET_ISO8859_1);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return new byte[0];
    }

    public static byte[] decode(byte[] base64Data) {
        try {
            return decodeString(new String(base64Data, CHARSET_ISO8859_1));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return new byte[0];
    }

    public static String encode(String data) {
        return encodeToString(data.getBytes());
    }

    public static String decode(String base64Data) {
        return new String(decodeString(base64Data));
    }

    public static String encodeToString(byte[] data) {
        if (sUseCustomFunction) {
            return encodeFunc(data);
        } else {
            return Base64.encodeToString(data, Base64.DEFAULT);
        }
    }

    public static byte[] decodeString(String base64Data) {
        if (sUseCustomFunction) {
            return decodeFunc(base64Data);
        } else {
            return Base64.decode(base64Data, Base64.DEFAULT);
        }
    }


    // Base64编码：每3个字节转4个字符，剩下的2个字节转3个字符+“=”，剩下1个字节转2个字符+“==”
    private static Character[] BASE64_ENCODE_CHARS = new Character[]{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
            'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a',
            'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
            't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

    private static byte[] BASE64_DECODE_CHARS = new byte[]{-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1,
            -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
            22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
            40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1};

    /**
     * 简单检查字符串是否符合Base64编码格式的字符串
     */
    public static boolean isBase64Str(String str) {
        if (TextUtils.isEmpty(str)) {
            return false;
        }

        //移除所有空格(包括换行符)
        String s = ElUtil.removeBlank(str);

        // 判断长度是否是4的倍数(4个字符为3个字节)
        if (s.length() % 4 != 0) {
            return false;
        }

        // 判断是否有非Base64编码的字符
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c != '=' && !ElUtil.isContains(BASE64_ENCODE_CHARS, c)) {
                return false;
            }
        }
        return true;
    }

    /**
     * 编码
     */
    private static String encodeFunc(byte[] data) {
        StringBuilder sb = new StringBuilder();
        if (data != null) {
            int len = data.length;
            int i = 0;
            int b1, b2, b3;
            while (i < len) {
                b1 = data[i++] & 0xff;
                if (i == len) {
                    sb.append(BASE64_ENCODE_CHARS[b1 >>> 2]);
                    sb.append(BASE64_ENCODE_CHARS[(b1 & 0x3) << 4]);
                    sb.append("==");
                    break;
                }
                b2 = data[i++] & 0xff;
                if (i == len) {
                    sb.append(BASE64_ENCODE_CHARS[b1 >>> 2]);
                    sb.append(BASE64_ENCODE_CHARS[((b1 & 0x03) << 4) | ((b2 & 0xf0) >>> 4)]);
                    sb.append(BASE64_ENCODE_CHARS[(b2 & 0x0f) << 2]);
                    sb.append("=");
                    break;
                }
                b3 = data[i++] & 0xff;
                sb.append(BASE64_ENCODE_CHARS[b1 >>> 2]);
                sb.append(BASE64_ENCODE_CHARS[((b1 & 0x03) << 4) | ((b2 & 0xf0) >>> 4)]);
                sb.append(BASE64_ENCODE_CHARS[((b2 & 0x0f) << 2) | ((b3 & 0xc0) >>> 6)]);
                sb.append(BASE64_ENCODE_CHARS[b3 & 0x3f]);
            }
        }
        return sb.toString();
    }

    /**
     * 解码
     */
    private static byte[] decodeFunc(String str) {
        try {
            if (!TextUtils.isEmpty(str)) {
                StringBuilder sb = new StringBuilder();
                byte[] data = str.getBytes(CHARSET_ISO8859_1);
                int len = data.length;
                int i = 0;
                int b1, b2, b3, b4;
                while (i < len) {
                    do {
                        b1 = BASE64_DECODE_CHARS[data[i++]];
                    } while (i < len && b1 == -1);
                    if (b1 == -1) {
                        break;
                    }

                    do {
                        b2 = BASE64_DECODE_CHARS[data[i++]];
                    } while (i < len && b2 == -1);
                    if (b2 == -1) {
                        break;
                    }
                    sb.append((char) ((b1 << 2) | ((b2 & 0x30) >>> 4)));

                    do {
                        byte bt3 = data[i++];
                        if (bt3 == 61) { //'='号
                            return sb.toString().getBytes(CHARSET_ISO8859_1);
                        }
                        b3 = BASE64_DECODE_CHARS[bt3];
                    } while (i < len && b3 == -1);
                    if (b3 == -1) {
                        break;
                    }
                    sb.append((char) (((b2 & 0x0f) << 4) | ((b3 & 0x3c) >>> 2)));

                    do {
                        byte bt4 = data[i++];
                        if (bt4 == 61) { //'='号
                            return sb.toString().getBytes(CHARSET_ISO8859_1);
                        }
                        b4 = BASE64_DECODE_CHARS[bt4];
                    } while (i < len && b4 == -1);
                    if (b4 == -1) {
                        break;
                    }
                    sb.append((char) (((b3 & 0x03) << 6) | b4));
                }
                return sb.toString().getBytes(CHARSET_ISO8859_1);
            }
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return new byte[0];
    }
}
