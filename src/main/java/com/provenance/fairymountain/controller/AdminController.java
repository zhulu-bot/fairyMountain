package com.provenance.fairymountain.controller;

import com.provenance.fairymountain.model.WXAuth;
import com.provenance.fairymountain.response.RespBean;
import com.provenance.fairymountain.service.WxService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;


@RestController
@Slf4j
public class AdminController {
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private WxService wxService;


    @GetMapping("/hello")
    public Object hello() {
        return SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }


    @GetMapping("/world")
    public Object world() {
        return SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }

    /**
     * w微信小程序获取code
     * @param code
     * @return
     */
    @GetMapping("/getSessionId")
    public RespBean getSessionId(@RequestParam String code) {
        String sessionId = wxService.getSessionId(code);
        HashMap<String, String> hashMap = new HashMap<String, String>();
        hashMap.put("sessionId", sessionId);
        return RespBean.ok("成功获取sessionid", hashMap);
    }
    /**
     * 获取微信小程序用户数据ncryptedData:加密数据 vi:初始向量 sessionid:getSessionId的返回值
     * @param wxAuth
     * @return
     */
    @PostMapping("/authLogin")
    public RespBean authLogin(@RequestBody WXAuth wxAuth) {
        RespBean result = wxService.authLogin(wxAuth);
        log.info("admincontroller", "authlogin", wxAuth.toString());
        return result;
    }


}
