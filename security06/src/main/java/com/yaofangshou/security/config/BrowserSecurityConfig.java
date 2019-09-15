package com.yaofangshou.security.config;

import com.yaofangshou.security.handler.MyAuthenticationFailureHandler;
import com.yaofangshou.security.handler.MyAuthenticationSucessHandler;
import com.yaofangshou.security.session.MySessionExpiredStrategy;
import com.yaofangshou.security.validate.imagecode.ValidateCodeFilter;
import com.yaofangshou.security.validate.smscode.SmsAuthenticationConfig;
import com.yaofangshou.security.validate.smscode.SmsCodeFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class BrowserSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private MyAuthenticationSucessHandler authenticationSucessHandler;

    @Autowired
    private MyAuthenticationFailureHandler authenticationFailureHandler;

    @Autowired
    private ValidateCodeFilter validateCodeFilter;

    @Autowired
    private SmsCodeFilter smsCodeFilter;

    @Autowired
    private SmsAuthenticationConfig smsAuthenticationConfig;

    @Autowired
    private MySessionExpiredStrategy sessionExpiredStrategy;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.addFilterBefore(validateCodeFilter, UsernamePasswordAuthenticationFilter.class) // 添加验证码校验过滤器
                .addFilterBefore(smsCodeFilter, UsernamePasswordAuthenticationFilter.class) // 添加短信验证码校验过滤器
                .formLogin() // 表单方式
//        http.httpBasic() // HTTP Basic方式
//                .loginPage("/login.html")//指定了跳转到登录页面的请求URL
                    .loginPage("/authentication/require") // 登录跳转 URL
                    .loginProcessingUrl("/login")//对应登录页面form表单的action="/login"
                    .successHandler(authenticationSucessHandler)// 处理登录成功
                    .failureHandler(authenticationFailureHandler)// 处理登录失败
                .and()
                    .authorizeRequests() // 授权配置
    //                .antMatchers("/login.html").permitAll()//表示跳转到登录页面的请求不被拦截，否则会进入无限循环
                    .antMatchers("/authentication/require",
                            "/login.html",
                            "/code/image",
                            "/code/sms",
                            "/session/invalid").permitAll()//表示跳转到登录页面的请求不被拦截，否则会进入无限循环
                    .anyRequest()  // 所有请求
                    .authenticated() // 都需要认证
                .and()
                    .sessionManagement() // 添加 Session管理器
                    .invalidSessionUrl("/session/invalid") // Session失效后跳转到这个链接
                    .maximumSessions(1)// 配置了最大Session并发数量为1个,失效策略：类似于一个先入先出队列
                    .maxSessionsPreventsLogin(true)// 控制当Session达到最大有效数的时候，不再允许相同的账户登录
                    .expiredSessionStrategy(sessionExpiredStrategy)// 配置了Session在并发下失效后的处理策略
                .and()
                .and()
                    .csrf().disable()//关闭CSRF攻击防御
                .apply(smsAuthenticationConfig); // 将短信验证码认证配置加到 Spring Security 中
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
