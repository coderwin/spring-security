package com.cos.security1.controller;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.apache.catalina.Store;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequiredArgsConstructor
public class IndexController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping
    public String index() {
        return "index"; // src/main/resources/templates/index.mustache
    }

    @GetMapping("/user")
    @ResponseBody
    public String user() {

        return "user";

    }
    @GetMapping("/admin")
    @ResponseBody
    public String admin() {

        return "admin";

    }
    @GetMapping("/manager")
    @ResponseBody
    public String manager() {

        return "manager";

    }

    @GetMapping("/loginForm")
    public String loginForm() {

        return "loginForm";

    }

    @GetMapping("/joinForm")
    public String joinForm() {

        return "joinForm";

    }

    @PostMapping("/join")
    @ResponseBody
    public ResponseEntity<Void> join(User user) {

        user.setRole("ROLE_USER");

        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);

        user.setPassword(encPassword);

        userRepository.save(user);

        return ResponseEntity.status(HttpStatus.MOVED_PERMANENTLY)
                .header(HttpHeaders.LOCATION, "/loginForm")
                .build();

    }

    @Secured(value = {"ROLE_admin"})
    @GetMapping("/info")
    @ResponseBody
    public String info() {

        return "info";
    }

    @PostAuthorize("hasRole('ROLE_MANAGER')")
//    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_admin')")
    @GetMapping("/data")
    @ResponseBody
    public String data() {

        return "data";
    }


}
