package com.yaofangshou.web.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {
    @GetMapping("/hello")
    public String hello(){
        return "hello";
    }

//    @GetMapping("/index")
//    public Object index(){
//        return SecurityContextHolder.getContext().getAuthentication();
//    }

    @GetMapping("index")
    public Object index(Authentication authentication) {
        return authentication;
    }
}
