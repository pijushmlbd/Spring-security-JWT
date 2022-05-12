package com.example.springsecurityjwt.Spring.security.JWT.model;

public class AuthenticationResponse {
    private String access_token;
    private String refresh_token;

    public AuthenticationResponse(String access_token, String refresh_token) {
        this.access_token=access_token;
        this.refresh_token=refresh_token;
    }

    public String getAccess_token() {
        return access_token;
    }


    public String getRefresh_token() {
        return refresh_token;
    }

}




