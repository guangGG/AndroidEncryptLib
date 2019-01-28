package gapp.season.encryptlib.hash;

import gapp.season.encryptlib.ElUtil;

public class HashExtUtil {
    /**
     * java中字符串默认哈希算法
     */
    public static int hashCode(String str) {
        if (str != null) {
            return str.hashCode();
        }
        return 0;
    }

    /**
     * 对字符串进行取余哈希计算(结果为0-z之间的字符)
     *
     * @param radix 位数
     */
    public static String modHash(String str, int radix) throws IllegalArgumentException {
        return modHash(hashCode(str), radix);
    }

    /**
     * 对数字进行取余哈希计算(结果为0-z之间的字符)
     *
     * @param radix 位数
     */
    public static String modHash(long num, int radix) throws IllegalArgumentException {
        if (radix > 36 || radix < 2) {
            throw new IllegalArgumentException("digit must >=2 and <=36");
        }

        int modNum = (int) (num % radix);
        if (modNum < 0) {
            modNum += radix;
        }
        return Integer.toString(modNum, radix);
    }

    /**
     * 对数字字符串生成校验位(同二代身份证校验位算法：17位数字生成末位校验字符)
     *
     * @param numStr 全部由数字拼成的字符串
     */
    public static String modCheckCode(String numStr) {
        try {
            String trimStr = ElUtil.removeBlank(numStr);
            if (ElUtil.isNumStr(trimStr)) {
                int len = trimStr.length();
                int sum = 0;
                for (int i = 0; i < len; i++) {
                    int multiplierFactor = (int) (((long) (Math.pow(2, len - i))) % 11); //乘数因子
                    sum += multiplierFactor * Integer.valueOf(Character.toString(trimStr.charAt(i)));
                }
                int modNum = sum % 11;
                int result = modNum > 1 ? (12 - modNum) : (1 - modNum); //结果映射计算方法
                if (result == 10) {
                    return "X";
                } else {
                    return String.valueOf(result);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    /**
     * 生成异或校验码
     * BCC(Block Check Character/信息组校验码)，校验码是将所有数据异或得出
     * 具体算法是：将每一个字节的数据（一般是两个16进制的字符）进行异或后即得到校验码
     */
    public static String xorHash(byte[] bytes) {
        if (bytes != null) {
            int result = 0;
            for (byte b : bytes) {
                result ^= b;
            }
            return String.valueOf(result);
        }
        return "";
    }
}
