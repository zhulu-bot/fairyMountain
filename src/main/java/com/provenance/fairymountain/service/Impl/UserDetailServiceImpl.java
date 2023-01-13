package com.provenance.fairymountain.service.Impl;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.provenance.fairymountain.mapper.UserMapper;
import com.provenance.fairymountain.model.AuthUser;
import com.provenance.fairymountain.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class UserDetailServiceImpl implements UserDetailsService {
    @Autowired
    private UserMapper userMapper;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        /**
         * 这个类的功能是通过名字返回一个userdetail对象,这个对象用于验证
         * 调用多个dao装配user
         */
        if(username == null  || "".equals(username)){
            throw new RuntimeException("用户不能为空");
        }
        ArrayList<String> role = new ArrayList<String>();
        role.add("ROLE_use");
        QueryWrapper<User> queryWrapper = new QueryWrapper<>();
        queryWrapper.eq("user_name",username);
        User u = userMapper.selectOne(queryWrapper);
        AuthUser user =  new AuthUser();
        user.setUsername(username);
        user.setPassword(u.getPassword());
        user.setRoles(role);
        if (user == null) {
            throw new UsernameNotFoundException("用户不存在!");
        }
        return user;
    }
}

