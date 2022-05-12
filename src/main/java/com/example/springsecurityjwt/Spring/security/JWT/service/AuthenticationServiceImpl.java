package com.example.springsecurityjwt.Spring.security.JWT.service;

import com.example.springsecurityjwt.Spring.security.JWT.Util.JwtUtil;
import com.example.springsecurityjwt.Spring.security.JWT.model.AuthenticationResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@Service
public class AuthenticationServiceImpl  implements AuthenticationService{

    @Autowired
    JwtUtil jwtUtil;

    @Override
    public AuthenticationResponse getToken(UserDetails userDetails) {
        AuthenticationResponse authenticationResponse=null;
        try {
            authenticationResponse= jwtUtil.generateToken(userDetails);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return authenticationResponse;
    }

}
