package com.provenance.fairymountain.config;



import com.fasterxml.jackson.databind.ObjectMapper;
import com.provenance.fairymountain.response.RespBean;
import com.provenance.fairymountain.response.ResultCode;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * ExceptionTranslationFilter 是 Spring Security 中专门负责处理异常的过滤器
 * 在security初始化的时候会自动加载这个过滤器，并且传入以下两个对象
 * AuthenticationEntryPoint 这个用来处理认证异常。
 * AccessDeniedHandler 这个用来处理授权异常。
 * 如果需要自定义异常处理逻辑，可以写一个类继承以上两个类，重写commence
 * 因为默认的逻辑一个是进行请求转发一个是重定向，我们这里使用前后端分离，不需要转发和重定向，所以自定义一个处理逻辑
 * 登录失败后返回json，而不是跳转
 */
@Component("myAuthenticationEntryPoint")
public class myAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {

        response.setContentType("application/json;charset=utf-8");
        PrintWriter out = response.getWriter();
        //权限不足，我有个问题，这里只能out，不能返回吗？
        out.write(new ObjectMapper().writeValueAsString(RespBean.error(ResultCode.NO_PERMISSION)));
        out.flush();
        out.close();
    }
}
