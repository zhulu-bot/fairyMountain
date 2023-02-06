package com.provenance.fairymountain.controller;

import com.provenance.fairymountain.response.RespBean;
import com.provenance.fairymountain.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
@RestController
@RequestMapping("/seed")
public class SeedController {
    @Autowired
    private UserService userService;
    /**
     * 获取用户的所有的种子
     * @param code
     * @return
     */
    @GetMapping("/getSeeds")
    public RespBean getSessionId(@RequestParam String code) {
        return RespBean.ok("成功获取sessionid");
    }

    @GetMapping("/hello")
    public Object hello() {
        return userService.getUserId();
    }
}
