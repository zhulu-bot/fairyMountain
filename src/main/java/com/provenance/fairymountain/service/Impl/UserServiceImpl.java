package com.provenance.fairymountain.service.Impl;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.provenance.fairymountain.mapper.UserMapper;
import com.provenance.fairymountain.model.User;
import com.provenance.fairymountain.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserMapper userMapper;

    @Override
    public Long getUserId() {
        String userInfo = (String) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Long userId;
        if(userInfo.length()==11){
            //username
            QueryWrapper<User> queryWrap = new QueryWrapper<User>();
            queryWrap.eq("user_name", userInfo);
            User user = userMapper.selectOne(queryWrap);
            userId = user.getUserId();
        }else{
            userId = Long.parseLong(userInfo);
        }
        return userId;
    }
}
