package com.road3144.oauth2jwt.controller;

import com.road3144.oauth2jwt.config.auth.PrincipalDetails;
import com.road3144.oauth2jwt.model.User;
import com.road3144.oauth2jwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @RequestMapping("/")
    public String index() {
        return "index";
    }
    @RequestMapping("/api/v1/user")
    public String user(Authentication authentication) {
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        return principalDetails.getUsername() + "의 정보입니다.";
    }

    @RequestMapping("/api/v1/manager")
    public String manager() {
        return "manager";
    }

    @RequestMapping("/api/v1/admin")
    public String admin() {
        return "admin";
    }

    @RequestMapping("/join")
    public String join(@RequestBody User user) {
        System.out.println(user);
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        userRepository.save(user);
        return "회원가입 완료";
    }

}
