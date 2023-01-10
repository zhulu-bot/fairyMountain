package com.provenance.fairymountain.config;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.provenance.fairymountain.response.RespBean;
import com.provenance.fairymountain.response.ResultCode;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;

/**
 * 这个类处理前端传过来的token，处理一般请求，除了登录表单的提交
 */
public class JwtFilter extends GenericFilterBean {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) servletRequest;
        //token放在请求头里传过来
        //token可以放在很多地方传过来
        String jwtToken = req.getHeader("authorization");
        //记录状态
        Claims claims = null;
        if(jwtToken != null){
            try {
                claims = Jwts.parser().setSigningKey("zhulu@123") //sang@123
                        //把请求头多出来的Bearer替换掉
                        .parseClaimsJws(jwtToken.replace("Bearer",""))  //解析JWT，这时可能会报异常，比如jwt过期或被篡改
                        .getBody();
            }catch (Exception e){
                // req.getRequestDispatcher("/tokenError").forward(req,servletResponse);
                servletResponse.setCharacterEncoding("UTF-8");
                servletResponse.setContentType("text/html;charset=utf-8");
                PrintWriter out = servletResponse.getWriter();
                out.write(new ObjectMapper().writeValueAsString(RespBean.error(ResultCode.USER_ACCOUNT_TOKEN_ERROR)));
                out.flush();
                //直接结束

                return;
            }

            if(claims != null){
                //获取当前登录用户名,可能会报空指针异常，交给spring了
                String username = claims.getSubject();
                //获取用户权限，authorities为JwtLoginFilter中定义的名字
                List<GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList((String) claims.get("authorities"));
                //进行校验。生成token
                UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, null, authorities);
                //把token放到一个类似全局容器的地方，这里只放了用户名和权限。有这两个就够了，就能让springSecurity验证权限了
                //用户名是给我用的，权限是给security框架用的
                //SecurityContextHolder.getContext().getAuthentication().getPrincipal() 可以获取用户名，强制用户名用学号不能重复
                SecurityContextHolder.getContext().setAuthentication(token);
            }
        }
            filterChain.doFilter(req,servletResponse);


    }
}
