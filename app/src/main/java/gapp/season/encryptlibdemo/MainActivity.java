package gapp.season.encryptlibdemo;

import android.annotation.SuppressLint;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.view.View;
import android.widget.TextView;

import java.security.KeyPair;

import gapp.season.encryptlib.SecretKeyGenerator;
import gapp.season.encryptlib.asymmetric.RSAUtil;
import gapp.season.encryptlib.code.Base64Util;
import gapp.season.encryptlib.code.ByteUtil;
import gapp.season.encryptlib.code.HexUtil;
import gapp.season.encryptlib.hash.HashExtUtil;
import gapp.season.encryptlib.hash.HashUtil;
import gapp.season.encryptlib.symmetric.AESUtil;
import gapp.season.encryptlib.symmetric.DESUtil;
import gapp.season.encryptlib.symmetric.DESedeUtil;
import gapp.season.encryptlib.symmetric.XorUtil;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        TextView tv = findViewById(R.id.text);
        tv.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                update();
            }
        });
        update();
    }

    private void update() {
        TextView tv = findViewById(R.id.text);
        String str = getShowText();
        tv.setText(str);
    }

    @SuppressLint("NewApi")
    private String getShowText() {
        try {
            int num = 2019012820;
            String str1 = String.valueOf(num);
            String str2 = "abcd2018080808";
            int ipInt = ByteUtil.ipToInt("120.87.176.212");
            String ip = ByteUtil.intToIp(num);
            int charInt1 = ByteUtil.charToInt('人', "GBK");
            int charInt2 = ByteUtil.charToInt('人', "UTF-8");
            String intStr1 = ByteUtil.intToCharStr(51403, "GBK");
            String intStr2 = ByteUtil.intToCharStr(14990010, "UTF-8");
            String base64 = Base64Util.encodeToString(ByteUtil.intToBytes(num)).trim();
            int base64Int = ByteUtil.bytesToInt(Base64Util.decodeString("eFew1A=="));
            String hex = HexUtil.toHexStr(ByteUtil.intToBytes(num));
            int hexInt = ByteUtil.bytesToInt(HexUtil.decodeHexStr(" 78 57B 0d4 "));
            byte[] keyBytes = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
            byte[] iv = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20};
            AESUtil.setDefaultKey(Base64Util.encodeToString(keyBytes).trim());
            AESUtil.setDefaultGCMIv(Base64Util.encodeToString(iv).trim());
            String aesData = AESUtil.encryptGCM(str2);
            String desKey = SecretKeyGenerator.generateKey(0, DESUtil.KEY_GENERATOR_DES);
            String desedeKey = SecretKeyGenerator.generateKey(0, DESedeUtil.KEY_GENERATOR_DESEDE);
            String desIv = SecretKeyGenerator.generateKey(64, DESUtil.KEY_GENERATOR_DES);
            DESUtil.setDefaultKey(desKey);
            DESUtil.setDefaultIv(desIv);
            DESedeUtil.setDefaultKey(desedeKey);
            DESedeUtil.setDefaultIv(desIv);
            String desData = DESUtil.encrypt(str2);
            String desedeData = DESedeUtil.encrypt(str2);
            KeyPair keyPair = SecretKeyGenerator.generateRSAKeyPair(1024);
            RSAUtil.setPublicKey(SecretKeyGenerator.getPublicKeyStr(keyPair));
            RSAUtil.setPrivateKey(SecretKeyGenerator.getPrivateKeyStr(keyPair));
            byte[] pSource = new byte[]{100, 56, 24, 78};
            RSAUtil.setPSource(Base64.encodeToString(pSource, Base64.DEFAULT).trim());
            String data = "Markdown是一种可以使用普通文本编辑器编写的标记语言，通过简单的标记语法，它可以使普通文本内容具有一定的格式。它允许人们使用易读易写的纯文本格式编写文档，然后转换成格式丰富的HTML页面，Markdown文件的后缀名便是“.md”";
            String algorithm1 = RSAUtil.RSA_ALGORITHM_ECB_OAEP_SHA1;
            String algorithm2 = RSAUtil.RSA_ALGORITHM_PKCS1;
            String rsaData1 = RSAUtil.encryptByPublicKey(data, algorithm1);
            String rsaData2 = RSAUtil.encryptByPrivateKey(data, algorithm2);
            String rsaSign = RSAUtil.sign(HashUtil.md5(data));
            return ipInt + "\n"
                    + ip + "\n"
                    + charInt1 + "\n"
                    + charInt2 + "\n"
                    + intStr1 + "\n"
                    + intStr2 + "\n"
                    + base64 + "\n"
                    + base64Int + "\n"
                    + hex + "\n"
                    + hexInt + "\n"
                    + HashUtil.md5(str1) + "~\n"
                    + HashUtil.sha1(str1) + "~\n"
                    + HashUtil.sha256(str1) + "~\n"
                    + HashUtil.sha512(str1) + "~\n"
                    + HashUtil.md5sha512(str1) + "~\n"
                    + HashExtUtil.modHash(str1, 36) + "\n"
                    + HashExtUtil.modHash(num, 16) + "\n"
                    + HashExtUtil.modCheckCode("34052419800101001") + "\n"
                    + HashExtUtil.modCheckCode(str1) + "\n"
                    + HashExtUtil.xorHash(HexUtil.decodeHexStr(str1)) + "\n"
                    + HexUtil.toHexStr(XorUtil.xor(HexUtil.decodeHexStr(str1), (byte) 0x68)) + "\n"
                    + HexUtil.toHexStr(XorUtil.xorByteArray(HexUtil.decodeHexStr(str1), HexUtil.decodeHexStr(str2))) + "\n"
                    + XorUtil.xorHexStr(str1, XorUtil.xorHexStr(str1, str2)) + "\n"
                    + aesData + "\n"
                    + AESUtil.decryptGCM(aesData) + "\n"
                    + desData + "\n"
                    + DESUtil.decrypt(desData) + "\n"
                    + desedeData + "\n"
                    + DESedeUtil.decrypt(desedeData) + "\n"
                    + "【" + rsaData1 + "】\n"
                    + "【" + rsaData2 + "】\n"
                    + "【" + rsaSign + "】\n"
                    + RSAUtil.decryptByPrivateKey(rsaData1, algorithm1) + "\n"
                    + RSAUtil.decryptByPublicKey(rsaData2, algorithm2) + "\n"
                    + RSAUtil.verify(HashUtil.md5(data), rsaSign) + "\n"
                    + SecretKeyGenerator.randomGenerateKeys() + "\n";
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
