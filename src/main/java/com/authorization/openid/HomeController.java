package com.authorization.openid;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    @GetMapping("/")
    public String login() {
        String userName = SecurityContextHolder.getContext().getAuthentication().getName();
        return "Hello " + userName;
    }
}
