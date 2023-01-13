package com.provenance.fairymountain.redisMapper;


import com.provenance.fairymountain.mapper.UserMapper;
import com.provenance.fairymountain.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

/**
 * 用于redis
 */

@Component
public class RedisUserMapper {


    @Autowired
    private RedisTemplate redisTemplate;
    @Autowired
    private UserMapper userMapper;

    public User redisGetUserById(int userId){
        //在redis里获取用户，先在redis里查，没有就去数据库
        User u = (User)redisTemplate.opsForValue().get(userId);
        if(u==null){
            //redis不存在，去数据库查，并且放入redis
            u = userMapper.selectById(userId);
            redisUpdataUser(u);
        }
        return (User)redisTemplate.opsForValue().get(userId);
    }

    /**
     * 登录和更新用户信息时调用，将user序列化写入redis
     * 键为userid
     * @param user
     */
    public void redisUpdataUser(User user){

        redisTemplate.opsForValue().set(user.getUserId(),user);
    }

    public void  deleteUserById(int userId){
        redisTemplate.delete(userId);
    }
}
