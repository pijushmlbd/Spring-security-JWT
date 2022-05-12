package com.example.springsecurityjwt.Spring.security.JWT.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/*
only authenticated users are allowed
*/

@RestController
public class WebPrivateInfoController {


    @GetMapping("/privateinfo")
    public String privateInfo()
    {
        return "info only for registered member";
    }

}
