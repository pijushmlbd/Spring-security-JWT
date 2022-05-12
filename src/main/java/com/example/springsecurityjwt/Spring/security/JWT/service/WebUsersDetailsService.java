package com.example.springsecurityjwt.Spring.security.JWT.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class WebUsersDetailsService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String input) throws UsernameNotFoundException {

        return new User("user","user123",new ArrayList<>());
    }
}
