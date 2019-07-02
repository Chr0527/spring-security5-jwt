package com.example.springsecurity.springsecurity;

import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * token 过滤器，在这里解析token，拿到该用户角色，设置到springsecurity的上下文环境中，让springsecurity自动判断权限
 * 所有请求最先进入此过滤器，包括登录接口，而且在springsecurity的密码验证之前执行
 * <p>
 * MyJwtTokenFilter 类继承自OncePerRequestFilter，这个OncePerRequestFilter就厉害了，可以说是所有filter的基类，所以最先执行，
 * 在这里我们写验证jwt的逻辑，验证通过后要告诉springsecurity，我们获取到的用户的权限，并把权限设置到springsecurity的上下文环境中，
 * 让它来给我们做权限的判断，这点最重要！！！！是springsecurity和jwt的整合纽带
 * <p>
 * * GYB
 * * 20190220
 */
@Component
public class MyJwtTokenFilter extends OncePerRequestFilter {

    @Autowired
    MyUserDetailsService myUserDetailsService;

    private String tokenHeader = "Authorization";
    private String tokenHead = "Bearer ";

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        System.out.println("进入token过滤器");
        String authHeader = httpServletRequest.getHeader(tokenHeader);

        if (authHeader != null && authHeader.startsWith(tokenHead)) {
            String authToken = authHeader.substring(tokenHead.length());
            Claims Claims = JwtUtils.parseJWT(authToken);
            String username = Claims.getId();
            System.out.println("username:" + username);
            //验证token,具体怎么验证看需求，可以只验证token不查库，把权限放在jwt中即可
            UserDetails UserDetails = myUserDetailsService.loadUserByUsername(username);
            if (JwtUtils.isTokenExpired(Claims)) {//token过期
                System.out.println("token过期" + authToken);
            } else {
                System.out.println("token没过期，放行" + authToken);
                //这里只要告诉springsecurity权限即可，账户密码就不用提供验证了，这里我们把UserDetails传给springsecurity，以便以后我们获取当前登录用户
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(UserDetails, null, UserDetails.getAuthorities());
//                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(null, null, UserDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
                logger.info(String.format("Authenticated userDetail %s, setting security context", username));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

}
