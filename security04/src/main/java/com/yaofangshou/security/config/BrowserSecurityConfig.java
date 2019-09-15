package com.yaofangshou.security.config;

import com.yaofangshou.security.handler.MyAuthenticationFailureHandler;
import com.yaofangshou.security.handler.MyAuthenticationSucessHandler;
import com.yaofangshou.security.service.UserDetailService;
import com.yaofangshou.security.validate.imagecode.ValidateCodeFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;

@Configuration
public class BrowserSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private MyAuthenticationSucessHandler authenticationSucessHandler;

    @Autowired
    private MyAuthenticationFailureHandler authenticationFailureHandler;

    @Autowired
    private ValidateCodeFilter validateCodeFilter;
    @Autowired
    private UserDetailService userDetailService;
    @Autowired
    private DataSource dataSource;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.addFilterBefore(validateCodeFilter, UsernamePasswordAuthenticationFilter.class) // 添加验证码校验过滤器
                .formLogin() // 表单方式
//        http.httpBasic() // HTTP Basic方式
//                .loginPage("/login.html")//指定了跳转到登录页面的请求URL
                    .loginPage("/authentication/require") // 登录跳转 URL
                    .loginProcessingUrl("/login")//对应登录页面form表单的action="/login"
                    .successHandler(authenticationSucessHandler)// 处理登录成功
                    .failureHandler(authenticationFailureHandler)// 处理登录失败
                .and()
                    .rememberMe()
                    .tokenRepository(persistentTokenRepository()) // 配置 token 持久化仓库
                    .tokenValiditySeconds(3600) // remember 过期时间，单为秒
                    .userDetailsService(userDetailService) // 处理自动登录逻辑
                .and()
                    .authorizeRequests() // 授权配置
    //                .antMatchers("/login.html").permitAll()//表示跳转到登录页面的请求不被拦截，否则会进入无限循环
                    .antMatchers("/authentication/require",
                            "/login.html",
                            "/code/image").permitAll()//表示跳转到登录页面的请求不被拦截，否则会进入无限循环
                    .anyRequest()  // 所有请求
                    .authenticated() // 都需要认证
                .and()
                    .csrf().disable();//关闭CSRF攻击防御
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource);
        //属性用于是否启动项目时创建保存token信息的数据表，这里设置为false，我们自己手动创建
        jdbcTokenRepository.setCreateTableOnStartup(false);
        return jdbcTokenRepository;
    }
}
