package com.yaofangshou.security.config;

import com.yaofangshou.security.handler.MyAuthenticationFailureHandler;
import com.yaofangshou.security.handler.MyAuthenticationSucessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class BrowserSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private MyAuthenticationSucessHandler authenticationSucessHandler;

    @Autowired
    private MyAuthenticationFailureHandler authenticationFailureHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin() // 表单方式
//        http.httpBasic() // HTTP Basic方式
//                .loginPage("/login.html")//指定了跳转到登录页面的请求URL
                .loginPage("/authentication/require") // 登录跳转 URL
                .loginProcessingUrl("/login")//对应登录页面form表单的action="/login"
                .successHandler(authenticationSucessHandler)// 处理登录成功
                .failureHandler(authenticationFailureHandler)// 处理登录失败
                .and()
                .authorizeRequests() // 授权配置
//                .antMatchers("/login.html").permitAll()//表示跳转到登录页面的请求不被拦截，否则会进入无限循环
                .antMatchers("/authentication/require","/login.html").permitAll()//表示跳转到登录页面的请求不被拦截，否则会进入无限循环
                .anyRequest()  // 所有请求
                .authenticated() // 都需要认证
                .and().csrf().disable();//关闭CSRF攻击防御
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
