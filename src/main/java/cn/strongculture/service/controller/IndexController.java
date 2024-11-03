package cn.strongculture.service.controller;

import cn.strongculture.service.utils.*;

import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.web.bind.annotation.*;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.util.Arrays;

@RestController
public class IndexController {

    static Charset CHARSET = Charset.forName("utf-8");
    byte[] aesKey;

    @GetMapping("/wx/check")
    public String check(@RequestParam(name = "signature") String msgSignature,
                         @RequestParam(name = "timestamp") String timeStamp,
                         @RequestParam(name = "nonce") String nonce,
                         @RequestParam(name = "echostr") String echoStr) throws Exception{
        System.out.println("signature:"  + msgSignature);
        System.out.println("timeStamp:"  + timeStamp);
        System.out.println("nonce:"  + nonce);
        System.out.println("echoStr:"  + echoStr);
        String signature = SHA1.getSHA1("peterToken", timeStamp, nonce);
        System.out.println(signature);
        if (signature.equals(msgSignature)) {
            return echoStr;
        }
        return null;
    }


    String decrypt(String text) throws Exception {
        byte[] original;
        try {
            // 设置解密模式为AES的CBC模式
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            SecretKeySpec key_spec = new SecretKeySpec(aesKey, "AES");
            IvParameterSpec iv = new IvParameterSpec(Arrays.copyOfRange(aesKey, 0, 16));
            cipher.init(Cipher.DECRYPT_MODE, key_spec, iv);

            // 使用BASE64对密文进行解码
            byte[] encrypted = Base64.decodeBase64(text);

            // 解密
            original = cipher.doFinal(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
            throw new Exception(e);
        }

        String xmlContent, from_appid;
        try {
            // 去除补位字符
            byte[] bytes = PKCS7Encoder.decode(original);

            // 分离16位随机字符串,网络字节序和AppId
            byte[] networkOrder = Arrays.copyOfRange(bytes, 16, 20);

            int xmlLength = recoverNetworkBytesOrder(networkOrder);

            xmlContent = new String(Arrays.copyOfRange(bytes, 20, 20 + xmlLength), CHARSET);
            from_appid = new String(Arrays.copyOfRange(bytes, 20 + xmlLength, bytes.length),
                    CHARSET);
        } catch (Exception e) {
            e.printStackTrace();
            throw new Exception(e);
        }

        // appid不相同的情况
        if (!from_appid.equals("wxb1b5c8468d15dd62")) {
            throw new Exception();
        }
        return xmlContent;
    }


    // 还原4个字节的网络字节序
    int recoverNetworkBytesOrder(byte[] orderBytes) {
        int sourceNumber = 0;
        for (int i = 0; i < 4; i++) {
            sourceNumber <<= 8;
            sourceNumber |= orderBytes[i] & 0xff;
        }
        return sourceNumber;
    }
}
