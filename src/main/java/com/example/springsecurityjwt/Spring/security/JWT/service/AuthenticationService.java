package com.example.springsecurityjwt.Spring.security.JWT.service;

import com.example.springsecurityjwt.Spring.security.JWT.model.AuthenticationResponse;
import org.springframework.security.core.userdetails.UserDetails;

public interface AuthenticationService {

     AuthenticationResponse getToken(UserDetails userDetails);

}
