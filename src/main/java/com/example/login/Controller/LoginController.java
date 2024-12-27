package com.example.login.Controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {
    @GetMapping({"/", "index"})
    public String login(){
        return "index";
    }

    @GetMapping("result")
    public String result(){
        return "result";
    }
}
