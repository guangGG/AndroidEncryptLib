package gapp.season.encryptlibdemo;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.TextView;

import gapp.season.encryptlib.code.Base64Util;
import gapp.season.encryptlib.code.ByteUtil;
import gapp.season.encryptlib.code.HexUtil;
import gapp.season.encryptlib.hash.HashExtUtil;
import gapp.season.encryptlib.hash.HashUtil;
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

    private String getShowText() {
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
                + XorUtil.xorHexStr(str1, XorUtil.xorHexStr(str1, str2)) + "\n";
    }
}
