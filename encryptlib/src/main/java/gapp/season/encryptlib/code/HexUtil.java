package gapp.season.encryptlib.code;

import android.text.TextUtils;

import gapp.season.encryptlib.ElUtil;

/**
 * 十六进制工具类
 */
public class HexUtil {
    private static final Character[] HEX_CHARS = new Character[]{'A', 'B', 'C', 'D', 'E', 'F',
            'a', 'b', 'c', 'd', 'e', 'f', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};

    /**
     * 校验字符串是否十六进制字符串
     *
     * @param str         校验的字符串
     * @param removeBlank 是否移除字符串中的空格后再校验
     * @param verifyEven  是否校验字符串长度为双数（即是否可转成字节）
     * @return 校验结果
     */
    public static boolean isHexStr(String str, boolean removeBlank, boolean verifyEven) {
        if (TextUtils.isEmpty(str)) {
            return false;
        }

        StringBuilder sb = new StringBuilder(removeBlank ? ElUtil.removeBlank(str) : str);
        if (verifyEven && sb.length() % 2 != 0) {
            return false;
        }
        for (int i = 0; i < sb.length(); i++) {
            if (!ElUtil.isContains(HEX_CHARS, sb.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    /**
     * 字节数组转换为十六进制字符串
     *
     * @param bytes 需要转换字节数组
     * @return 字节数组对应的十六进制字符串
     */
    public static String toHexStr(byte[] bytes) {
        if (bytes != null) {
            String temp;
            StringBuilder sb = new StringBuilder(bytes.length * 2);
            for (byte b : bytes) {
                temp = Integer.toHexString(b & 0xFF);
                if (temp.length() == 1) {
                    sb.append("0").append(temp);
                } else {
                    sb.append(temp);
                }
            }
            return sb.toString();
        }
        return null;
    }

    /**
     * 将十六进制字符串转为字节数组
     */
    public static byte[] decodeHexStr(String str) {
        if (isHexStr(str, true, true)) {
            String trimStr = ElUtil.removeBlank(str);
            byte[] bytes = new byte[trimStr.length() / 2];
            int j;
            for (int i = 0; i < bytes.length; i++) {
                j = (i << 1);
                bytes[i] = 0;
                char c = trimStr.charAt(j);
                if ('0' <= c && c <= '9') {
                    bytes[i] |= ((c - '0') << 4);
                } else if ('A' <= c && c <= 'F') {
                    bytes[i] |= ((c - 'A' + 10) << 4);
                } else if ('a' <= c && c <= 'f') {
                    bytes[i] |= ((c - 'a' + 10) << 4);
                } else {
                    // Exception
                    return null;
                }
                j++;
                c = trimStr.charAt(j);
                if ('0' <= c && c <= '9') {
                    bytes[i] |= (c - '0');
                } else if ('A' <= c && c <= 'F') {
                    bytes[i] |= (c - 'A' + 10);
                } else if ('a' <= c && c <= 'f') {
                    bytes[i] |= (c - 'a' + 10);
                } else {
                    // Exception
                    return null;
                }
            }
            return bytes;
        }
        return null;
    }
}
