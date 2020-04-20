# Android Encrypt Library
android library of encrypt utils

## Installation Adding to project
1.Add the Jcenter repository to your build file
```
buildscript {
    repositories {
        jcenter()
    }
}
```
2.Add the dependency
```
dependencies {
    implementation 'gapp.season:EncryptLib:0.0.4'
}
```
## Usage
### hash
```
HashUtil.md5(dataStr);
HashUtil.sha1(dataStr);
HashUtil.sha256(dataStr);
HashUtil.sha512(dataStr);
HashUtil.md5sha512(dataStr);
HashExtUtil.modHash(...); //取余哈希
HashExtUtil.modCheckCode(...); //数字校验码(例如二代身份证尾数校验码)
HashExtUtil.xorHash(...); //BCC校验码
```
### symmetrical/asymmetrical encryption
##### Generate key:
```
SecretKeyGenerator.generateKey(...);
SecretKeyGenerator.generateRSAKeyPair(...);
```
##### Setup Key When Application onCreate:
```
DESUtil/DESedeUtil/AESUtil.setDefaultKey(key);
RSAUtil.setPublicKey(key1);
RSAUtil.setPrivateKey(key2);
```
##### Encrypt/Decrypt data use default key:
```
DESUtil/DESedeUtil/AESUtil.encrypt(dataStr);
DESUtil/DESedeUtil/AESUtil.decrypt(data);
RSAUtil.encryptByPublicKey(dataStr);
RSAUtil.decryptByPrivateKey(data);
RSAUtil.encryptByPrivateKey(dataStr);
RSAUtil.decryptByPublicKey(data);
```
##### Sign/Verify data:
```
RSAUtil.sign(data);
RSAUtil.verify(data,signStr);
```
##### Encrypt/Decrypt data use Chain calls(v0.0.4):
```
//RSA default "RSA/ECB/PKCS1Padding"
String resultRSA = new RSABuilder()
        .toEncrypt()
        .setMode(RSABuilder.MODE_ECB)
        .setPadding(RSABuilder.PADDING_OAEP)
        .setPSrc(pSource) //OAEPPadding需要设置pSource
        .setData(data, null) //default "UTF-8"
        .usePublicKey(true)
        .setKeyBytes(publicKey)
        .doFinalBase64Str();
String originRSA = new RSABuilder()
        .toDecrypt()
        .setMode(RSABuilder.MODE_ECB)
        .setPadding(RSABuilder.PADDING_OAEP)
        .setPSrc(pSource) //OAEPPadding需要设置pSource
        .setBase64Data(resultRSA)
        .usePublicKey(false) //use PrivateKey
        .setKeyBytes(privateKey)
        .doFinalStr(null);
//AES default "AES/CBC/PKCS5Padding"
String resultAES = new AESBuilder()
        .toEncrypt()
        .setMode(AESBuilder.MODE_GCM)
        .setPadding(AESBuilder.PADDING_NONE)
        .setData(data, "GBK")
        .setKeyBytes(keyBytes)
        .setIvBytes(ivBytes)
        .doFinalBase64Str();
String originAES = new AESBuilder()
        .toDecrypt()
        .setMode(AESBuilder.MODE_GCM)
        .setPadding(AESBuilder.PADDING_NONE)
        .setBase64Data(resultAES)
        .setKeyBytes(keyBytes)
        .setIvBytes(ivBytes)
        .doFinalStr("GBK");
```
## More
See more android encrypted information:
https://developer.android.com/reference/javax/crypto/Cipher.html
