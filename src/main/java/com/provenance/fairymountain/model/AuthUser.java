package com.provenance.fairymountain.model;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * 用于微信身份认证的实体
 */
@Data
public class AuthUser implements UserDetails {

    private static final long serialVersionUID = -6901904826102838814L;
    /**
     * 保存用户登录的账号可能是电话，可能是学号
     */
    private String username;

    /**
     * 密码，当用户名是学号
     * 先用比较蠢的策略，当使用手机发送验证码登录时，首先更改用户的数据库，然后再比对
     */
    private String password;

    /**
     * 保存用户的权限
     */
    /**
     * 用户的ID
     */
    private int id;
    //roles 里包含了权限加角色，角色前缀为RLOE而已

    private List<String> roles;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<SimpleGrantedAuthority> authorities = new ArrayList<SimpleGrantedAuthority>();
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}