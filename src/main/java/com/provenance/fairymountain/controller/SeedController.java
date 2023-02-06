package com.provenance.fairymountain.controller;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.provenance.fairymountain.model.Seed;
import com.provenance.fairymountain.response.RespBean;
import com.provenance.fairymountain.service.SeedService;
import com.provenance.fairymountain.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;

@RestController
@RequestMapping("/seed")
public class SeedController {
    @Autowired
    private UserService userService;
    @Autowired
    private SeedService seedService;
    /**
     * 获取用户的所有的种子
     * @return
     */
    @GetMapping("/getSeeds")
    public RespBean getSessionId() {
        List<Seed> seeds = seedService.getSeeds(userService.getUserId());
        return RespBean.ok("成功获取用户的所有种子",seeds);
    }

    @GetMapping("/hello")
    public Object hello() {
        return userService.getUserId();
    }

    @PostMapping("/updateSeeds")
    public RespBean updateSeeds(@RequestBody Seed seed) {
        seed.setUserId(userService.getUserId());
        //更新种子库，先查看是否有这个类型的种子，如果有直接加数量，如果没有，直接插入
        Seed userSeed = seedService.updateSeed(seed);
        return RespBean.ok("成功获取sessionid",userSeed);
    }
}
