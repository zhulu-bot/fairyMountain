package com.provenance.fairymountain;

import com.provenance.fairymountain.config.myAuthenticationEntryPoint;
import com.provenance.fairymountain.mapper.UserMapper;
import com.provenance.fairymountain.model.User;
import javafx.application.Application;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootTest(classes = FairyMountainApplication.class)
public class test {
    @Autowired
    UserMapper userMapper;
    @Autowired
    private PasswordEncoder passwordEncoder;


    /**
     * 配置bean，做密码加密
     *
     * @return 以前返回PasswordEncoder改成了BCryptPasswordEncoder
     * 返回PasswordEncoder打包会异常
     */
    @Bean("passwordEncoder")
    public static BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Test
    public void test2() {
        User u = new User();
        u.setUserName("18222155748");
        u.setPassword(passwordEncoder.encode("123"));
        userMapper.insert(u);
    }
}
