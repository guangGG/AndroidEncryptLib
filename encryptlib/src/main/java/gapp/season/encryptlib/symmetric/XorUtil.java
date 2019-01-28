package gapp.season.encryptlib.symmetric;

public class XorUtil {
    /**
     * 使用指定key对字节数组进行异或运算
     * 备注：使用异或运算做对称加密，解码速度会非常快，但安全性比较低
     * 适用于：比如加密存放一些比较大的多媒体文件，又不希望文件直接被其他播放器使用的情况
     *
     * @param bts 字节数组
     * @param key 密钥
     */
    public static byte[] xor(byte[] bts, byte key) {
        try {
            if (bts != null) {
                byte[] bs = new byte[bts.length];
                for (int i = 0; i < bts.length; i++) {
                    bs[i] = (byte) (bts[i] ^ key);
                }
                return bs;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 异或两个等长的字节数组(不等长时，短的数组前面用0补齐)
     */
    public static byte[] xorByteArray(byte[] bts1, byte[] bts2) {
        try {
            int length = Math.max(bts1.length, bts2.length);
            byte[] result = new byte[length];
            for (int i = 0; i < length; i++) {
                byte b1 = (i + bts1.length - length) < 0 ? 0 : bts1[i + bts1.length - length];
                byte b2 = (i + bts2.length - length) < 0 ? 0 : bts2[i + bts2.length - length];
                result[i] = (byte) (b1 ^ b2);
            }
            return result;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 异或两个等长的16进制字符串(不等长时，短的字符串前面用0补齐)
     */
    public static String xorHexStr(String strHexX, String strHexY) {
        StringBuilder sb = new StringBuilder();
        try {
            //对齐两个字符串的长度
            int length = Math.max(strHexX.length(), strHexY.length());
            StringBuilder strHexXBuilder = new StringBuilder(strHexX);
            while (strHexXBuilder.length() < length) {
                strHexXBuilder.insert(0, "0");
            }
            strHexX = strHexXBuilder.toString();
            StringBuilder strHexYBuilder = new StringBuilder(strHexY);
            while (strHexYBuilder.length() < length) {
                strHexYBuilder.insert(0, "0");
            }
            strHexY = strHexYBuilder.toString();
            //对单个字符异或后再拼接
            for (int i = 0; i < length; i++) {
                String charX = strHexX.substring(i, i + 1);
                int intX = Integer.valueOf(charX, 16);
                String charY = strHexY.substring(i, i + 1);
                int intY = Integer.valueOf(charY, 16);
                int intXor = intX ^ intY;
                String charXor = Integer.toHexString(intXor);
                sb.append(charXor);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return sb.toString();
    }
}
