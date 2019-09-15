package com.yaofangshou.security.service;

import com.yaofangshou.domain.MyUser;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;
import java.util.List;

@Configuration
public class UserDetailService implements UserDetailsService {
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
        MyUser user=new MyUser();
        user.setUserName(userName);
        user.setPassword(this.passwordEncoder.encode("123456"));
        System.out.println(user.getPassword());

        List<GrantedAuthority> authorities = new ArrayList<>();
        if (StringUtils.equalsIgnoreCase("admin", userName)) {
            authorities = AuthorityUtils.commaSeparatedStringToAuthorityList("admin");
        } else {
            authorities = AuthorityUtils.commaSeparatedStringToAuthorityList("test");
        }

        return new User(userName, user.getPassword(), user.isEnabled(),
                user.isAccountNonExpired(), user.isCredentialsNonExpired(),
                user.isAccountNonLocked(), authorities);
    }
}
