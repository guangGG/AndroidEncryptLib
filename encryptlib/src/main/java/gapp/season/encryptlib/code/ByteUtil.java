package gapp.season.encryptlib.code;

import java.net.InetAddress;

public class ByteUtil {
    /**
     * 将4个字节转为int值
     *
     * @param src 长度为4的字节数组
     * @return int值
     * @throws IllegalArgumentException 传入的字节数组不符合条件
     */
    public static int bytesToInt(byte[] src) throws IllegalArgumentException {
        if (src == null || src.length != 4) {
            throw new IllegalArgumentException("illegal byte array");
        }
        return ((src[0] & 0xFF) << 24)
                | ((src[1] & 0xFF) << 16)
                | ((src[2] & 0xFF) << 8)
                | (src[3] & 0xFF);
    }

    /**
     * 将int数值转换为四个字节的byte数组
     *
     * @param value 要转换的int值
     * @return 四个字节的byte数组
     */
    public static byte[] intToBytes(int value) {
        byte[] src = new byte[4];
        src[0] = (byte) ((value >> 24) & 0xFF);
        src[1] = (byte) ((value >> 16) & 0xFF);
        src[2] = (byte) ((value >> 8) & 0xFF);
        src[3] = (byte) (value & 0xFF);
        return src;
    }

    /**
     * 把IP(v4)地址转换为int值
     */
    public static int ipToInt(String ipAddr) throws IllegalArgumentException {
        try {
            InetAddress inetAddress = InetAddress.getByName(ipAddr);
            byte[] ipBytes = inetAddress.getAddress();
            return bytesToInt(ipBytes);
        } catch (Exception e) {
            throw new IllegalArgumentException(ipAddr + " is invalid IP");
        }
    }

    /**
     * 把int值转换为IP(v4)地址
     */
    public static String intToIp(int value) {
        try {
            byte[] ipBytes = intToBytes(value);
            InetAddress inetAddress = InetAddress.getByAddress(ipBytes);
            return inetAddress.getHostAddress();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 字符转为对应编码的int数值
     */
    public static int charToInt(char c, String charset) {
        try {
            byte[] bs = Character.toString(c).getBytes(charset);
            if (bs.length < 4) {
                byte[] bs4 = new byte[4];
                for (int i = 0; i < 4; i++) {
                    int index = i + bs.length - 4;
                    if (index >= 0) {
                        bs4[i] = bs[index];
                    } else {
                        bs4[i] = 0;
                    }
                }
                return ByteUtil.bytesToInt(bs4);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return -1;
    }

    /**
     * int数值按对应编码转为字符串
     */
    public static String intToCharStr(int num, String charset) {
        try {
            byte[] bs = ByteUtil.intToBytes(num);
            int size = 0;
            for (int i = 0; i < bs.length; i++) {
                if (bs[i] != 0) {
                    size = bs.length - i;
                    break;
                }
            }
            byte[] bts = new byte[size];
            System.arraycopy(bs, bs.length - size, bts, 0, size);
            return new String(bts, charset);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
