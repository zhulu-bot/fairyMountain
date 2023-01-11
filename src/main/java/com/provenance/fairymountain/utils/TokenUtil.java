package com.provenance.fairymountain.utils;

import com.provenance.fairymountain.model.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;

public class TokenUtil {
    public static String getJwtByUser(User user) {
        StringBuffer as = new StringBuffer();
        as.append("user");
        String jwt = Jwts.builder()
                .claim("authorities", as)//配置用户权限
                .setSubject(user.getUid().toString())//把用户名放到Subject，所以在JwtFilter调用方法可以获得用户名，token只包含用户名和权限
                .setExpiration(new Date(System.currentTimeMillis() + 30 * 60 * 1000)) //设置过期时间
                .signWith(SignatureAlgorithm.HS512, "zhulu@123") ///用密钥加密，密钥可以随便写，但要和解密对应
                .compact();  //构建JWT
        return jwt;

    }
}
