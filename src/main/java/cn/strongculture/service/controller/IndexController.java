package cn.strongculture.service.controller;

import cn.strongculture.service.utils.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class IndexController {

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

}
